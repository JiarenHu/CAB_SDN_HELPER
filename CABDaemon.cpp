#include <arpa/inet.h>
#include <atomic>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <iostream>
#include <fstream>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <utility>
#include "Message.hpp"
#include "TimeSpec.hpp"
#include "../CAB_SDN/BucketTree.h"

using boost::asio::ip::tcp;


class Adapter
{
public:
    Adapter(bucket_tree & bTree):bTree_(bTree)
    {
    }

    void process(Message & msg)
    {
        char * body = msg.body();
        addr_5tup pkt_h;
        for(uint32_t i = 0; i != 4; ++i)
        {
            uint32_t word = 0;
            memcpy(&word,body + i*4,4);
            word = ntohl(word);
            pkt_h.addrs[i] = word;
        }
        msg.clear();
        std::pair<bucket*, int> bpair;
        bpair = bTree_.search_bucket(pkt_h,bTree_.root);
        bucket * b = bpair.first;
        BOOST_LOG_TRIVIAL(debug) << b->get_str() << endl;
        if(b != nullptr)
        {
            msg.append_uint(b->addrs[0].pref);
            msg.append_uint(b->addrs[0].mask);
            msg.append_uint(b->addrs[1].pref);
            msg.append_uint(b->addrs[1].mask);
            msg.append_uint(b->addrs[2].pref);
            msg.append_uint(b->addrs[2].mask);
            msg.append_uint(b->addrs[3].pref);
            msg.append_uint(b->addrs[3].mask);

            auto & rule_ids = b->related_rules;
            auto & rule_list = bTree_.rList->list;
            for(uint32_t id : rule_ids)
            {
                msg.append_uint(rule_list[id].hostpair[0].pref);
                msg.append_uint(rule_list[id].hostpair[0].mask);
                msg.append_uint(rule_list[id].hostpair[1].pref);
                msg.append_uint(rule_list[id].hostpair[1].mask);
                msg.append_uint(rule_list[id].portpair[0].range[0]);
                msg.append_uint(rule_list[id].portpair[0].range[1]);
                msg.append_uint(rule_list[id].portpair[1].range[0]);
                msg.append_uint(rule_list[id].portpair[1].range[1]);
            }

        }
        msg.encode_header();
    }
private:
    bucket_tree & bTree_;
};





//----------------------------------------------------------------------
class session;
typedef std::shared_ptr<session> session_ptr;
typedef std::set<session_ptr> session_container;
//----------------------------------------------------------------------

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket && socket, session_container & container, Adapter & adapter)
        : socket_(std::forward<tcp::socket>(socket)),
          container_(container),
          adapter_(adapter)
    {
    }

    void start()
    {
        container_.insert(shared_from_this());
        do_read_header();
    }

    ~session()
    {
        if(socket_.is_open())
        {
            socket_.close();
        }
    }
private:
    void do_read_header()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_,
                                boost::asio::buffer(msg_.data(), Message::header_length),
                                [this, self](boost::system::error_code ec, std::uint32_t /*length*/)
        {
            if (!ec && msg_.decode_header())
            {
                do_read_body();
            }
            else
            {
                handle_error();
                container_.erase(shared_from_this());
            }
        });
    }

    void do_read_body()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_,
                                boost::asio::buffer(msg_.body(), msg_.body_length()),
                                [this, self](boost::system::error_code ec, std::uint32_t /*length*/)
        {
            if (!ec)
            {
                socket_.shutdown(tcp::socket::shutdown_receive);
                //do our job.
                adapter_.process(msg_);
                do_write(msg_);
            }
            else
            {
                handle_error();
                container_.erase(shared_from_this());
            }
        });
    }

    void do_write(const Message & msg)
    {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
                                 boost::asio::buffer(msg.data(),
                                         msg.length()),
                                 [this, self](boost::system::error_code ec, std::uint32_t /*length*/)
        {
            if (!ec)
            {
                socket_.shutdown(tcp::socket::shutdown_send);
            }
            else
            {
                handle_error();
            }
            container_.erase(shared_from_this());
        });
    }


    void handle_error()
    {
        if(socket_.is_open())
        {
            socket_.close();
        }
    }

    tcp::socket socket_;
    session_container & container_;
    Adapter & adapter_;
    Message msg_;
};

//----------------------------------------------------------------------

class chat_server
{
public:
    chat_server(boost::asio::io_service& ios,
                const tcp::endpoint& endpoint,
                Adapter && adapter)
        : ios_(ios),
          acceptor_(ios, endpoint),
          adapter_(std::forward<Adapter>(adapter)),
          skt(ios),
	  request_c(0)
    {
        do_accept();
    }

    unsigned long get_request_c()
    {
        return request_c.load();
    }

    void set_request_c(unsigned long i)
    {

        request_c = i;
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(skt,
                               [this](boost::system::error_code ec)
        {
            if (!ec)
            {
                ++request_c;
                std::make_shared<session>(std::move(skt), container_, adapter_)->start();
            }

            do_accept();
        });
    }
    boost::asio::io_service & ios_;
    tcp::acceptor acceptor_;
    Adapter adapter_;
    //session life cycle management
    std::set<std::shared_ptr<session>> container_;
    tcp::socket skt;
    std::atomic_ulong request_c;
};

//----------------------------------------------------------------------
void boost_log_init()
{
    namespace logging = boost::log;
    namespace keywords = boost::log::keywords;
    namespace sinks = boost::log::sinks;
//    logging::add_file_log
//    (
//        keywords::file_name = "sample_%N.log",
//        keywords::rotation_size = 10 * 1024 * 1024,
//        keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
//        keywords::format = "[%TimeStamp%]: %Message%"
//    );
//
    logging::core::get()->set_filter
    (
        logging::trivial::severity > logging::trivial::debug
    );
}
void collector(chat_server & cs, std::ostream & os)
{
    static TimeSpec zero(true);
    static TimeSpec to_sleep(1,0);
    while(true)
    {
        TimeSpec now;
        clock_gettime(CLOCK_REALTIME,&now.time_point_);
        os << (now - zero).to_string()<< "\t" << cs.get_request_c() << endl;
        cs.set_request_c(0);
        if(nanosleep(&to_sleep.time_point_,NULL))
        {
            BOOST_LOG_TRIVIAL(warning) << "nanosleep failed." << endl;
        }
    }
}
int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage: CABDeamon {rules_file} <port> {statistic_file}"
                  << std::endl;
        return 1;
    }
    boost_log_init();
    //initialize CAB
    std::string rulefile(argv[1]);
    rule_list rList(rulefile,true);
    BOOST_LOG_TRIVIAL(debug) << "Loading rules : " << rList.list.size() << std::endl;
    bucket_tree bTree(rList, 15, true);
    Adapter adapter(bTree);
    std::ofstream st_out(argv[3]);
    if(!st_out.is_open())
    {
        std::cerr << "Can not open statistic file." << endl;
        return 2;
    }
    try
    {
        boost::asio::io_service io_service;
        tcp::endpoint endpoint(tcp::v4(), std::atoi(argv[2]));
        chat_server server(io_service, endpoint , std::move(adapter));
        BOOST_LOG_TRIVIAL(info) << "Deamon running..." << endl;
        std::thread collector_t(collector,std::ref(server),std::ref(st_out));
        collector_t.detach();
        BOOST_LOG_TRIVIAL(info) << "Collector running..." << endl;
        io_service.run();

    }
    catch (std::exception& e)
    {
        BOOST_LOG_TRIVIAL(fatal) << "Exception: " << e.what() << "\n";
    }

    return 0;
}
