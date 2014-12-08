#include <arpa/inet.h>
#include <sys/time.h>

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/log/trivial.hpp>
#include <pcap.h>

#include "header_defu.h"

//constant and helper functions with timespec
const unsigned int NSEC_MAX = 1000000000;
void timer_add(timespec *a, timespec *b, timespec *rs)
{
    rs->tv_sec = a->tv_sec + b->tv_sec;
    rs->tv_nsec = a->tv_nsec + b->tv_nsec;
    if(rs->tv_nsec > NSEC_MAX)
    {
        rs->tv_sec -= 1;
        rs->tv_nsec -= NSEC_MAX;
    }
}

char timeercmp(timespec a, timespec b)
{
    if (a.tv_sec != b.tv_sec)
        return a.tv_sec - b.tv_sec;
    else
        return a.tv_nsec - b.tv_nsec;
}


void timespec_set(timespec *tv, double dt)
{
    uint64_t us = dt*NSEC_MAX;
    tv->tv_sec = us / NSEC_MAX;
    tv->tv_nsec = us - tv->tv_sec*NSEC_MAX;
}

//object in headers_pool
class header
{
public:
    header() {}
    header & operator = (const header &h)
    {
        this->timestamp = h.timestamp;
        this->quantum = h.quantum;
        if(h.eth != nullptr)
        {
            eth = new sniff_ethernet;
            memcpy(eth,h.eth,sizeof(sniff_ethernet));
        }
        else
        {
            eth = nullptr;
        }
        if(h.ip != nullptr)
        {
            ip = new sniff_ip;
            memcpy(ip,h.ip,sizeof(sniff_ip));
        }
        else
        {
            ip = nullptr;
        }
        if(h.tcp != nullptr)
        {
            tcp = new sniff_tcp;
            memcpy(tcp,h.tcp,sizeof(sniff_tcp));
        }
        else
        {
            tcp = nullptr;
        }
        return *this;
    }
    //move constructor
    header(header &&h)
    {
        this->timestamp = h.timestamp;
        this->quantum = h.quantum;
        this->eth = h.eth;
        this->ip = h.ip;
        this->tcp = h.tcp;
        h.eth = nullptr;
        h.ip = nullptr;
        h.tcp = nullptr;
    }

    //copy constructor
    header(const header &h)
    {
        *this = h;
    }
    timespec timestamp;
    uint16_t quantum;
    sniff_ethernet *eth;
    sniff_ip *ip;
    sniff_tcp *tcp;
};


class headers_pool
{
public:
    headers_pool()
    {
        curr_pos = pool_.end();
    }
    void addHeader(header&& h)
    {
        std::lock_guard<std::mutex>(this->pool_mutex_);
        timespec now;
        clock_gettime(CLOCK_REALTIME,&now);
        pool_.push_back(h);
    }
    std::pair<bool,std::list<header>::iterator> getHeader()
    {
        auto rs = pool_.end();
        std::lock_guard<std::mutex>(this->pool_mutex_);
        bool found = false;
        timespec now;
        clock_gettime(CLOCK_REALTIME,&now);
        while(!found && !pool_.empty())
        {
            if(curr_pos == pool_.end())
            {
                curr_pos = pool_.begin();
                continue;
            }

            timespec &expir_time = curr_pos->timestamp;

            if(timeercmp(now,expir_time) > 0)
            {
                //a expired header, delete
                curr_pos = pool_.erase(curr_pos);
            }
            else
            {
                //valid header return
                rs = curr_pos;
                ++curr_pos;
                return std::make_pair(true,rs);
            }
        }
        return std::make_pair(false,rs);
    }
private:
    std::list<header> pool_;
    typedef std::list<header>::iterator h_it;
    h_it curr_pos;
    std::mutex pool_mutex_;
};

class FlowGen
{

public:
    enum dstrb {flat,exp};
    FlowGen(headers_pool& hp,unsigned int flows, unsigned int duration)
        :pool_(hp),flows_(flows),duration_(duration)
    {
    }
    void start()
    {
        running_ = true;
        gen();
    };
    void stop()
    {
        running_ = false;
    };

private:
    headers_pool& pool_;
    bool running_;
    unsigned int flows_;
    unsigned int duration_;

private:
    void gen()
    {
        timespec sleep_timer_;
        while(running_)
        {
            pool_.addHeader(make_header());
            get_sleep_time(&sleep_timer_);
            nanosleep(&sleep_timer_,NULL);
        }
    }

    header make_header()
    {
        //you can customize header here
        header rs;
        //timestamp
        timespec dr,now;
        timespec_set(&dr,duration_);
        clock_gettime(CLOCK_REALTIME,&now);
        timer_add(&now,&dr,&rs.timestamp);
        //quantum
        rs.quantum = 1;

        //make ehternet header
        static uint32_t dst = 0;
        static uint32_t src = UINT32_MAX-1;
        rs.eth = new sniff_ethernet;
        sniff_ethernet *eth = rs.eth;
        uint32_t *mac_dst = (uint32_t *)(eth->ether_dhost + 2);
        uint32_t *mac_src = (uint32_t *)(eth->ether_shost + 2);
        *mac_dst = htonl(dst);
        *mac_src = htonl(src);
        eth->ether_dhost[2] = 0x0c;
        eth->ether_shost[0] = 0x00;
        eth->ether_shost[1] = 0x02;
        eth->ether_shost[2] = 0xb3;
        //make ip header
        rs.ip = new sniff_ip;
        rs.ip->ip_src.s_addr = htonl(src);
        rs.ip->ip_dst.s_addr = htonl(dst/2);
        //make tcp header
        rs.tcp = new sniff_tcp;
        rs.tcp->th_dport = htons(10071);
        rs.tcp->th_sport = htons(10087);
        --src;
        ++dst;
        return rs;
    }

    void get_sleep_time(timespec *t)
    {
        t->tv_sec = 0;
        t->tv_nsec = (NSEC_MAX - 1)/flows_;
    }
};

class PacketGen
{
public:
    PacketGen(headers_pool &pool, char * device, unsigned int pkt_rate)
        :pool_(pool),pkt_rate_(pkt_rate),running_(false)
    {
        pd = pcap_open_live(device,1514,1,1000,err_buf);
        counter_ = 0;
    }
    void start()
    {
        running_ = true;
        gen();
    };
    void stop()
    {
        running_ = false;
    };
    
    unsigned int getCounter(){
        unsigned int value = counter_;
        return value;
    }

    void setCounter(unsigned int value){
        counter_ = value;
    }

private:
    headers_pool &pool_;
    pcap_t *pd;
    char err_buf[PCAP_ERRBUF_SIZE];
    unsigned int pkt_rate_;
    bool running_;
    std::atomic_uint counter_;
private:
    void gen()
    {
        timespec sleep;
        while(running_)
        {
            auto h = pool_.getHeader();
            if(h.first == true)
            {
                uint8_t *pkt_data = NULL;
                uint32_t pkt_len = 0;
                gen_pkt(*h.second, &pkt_data, &pkt_len);
                pcap_sendpacket(pd, pkt_data, pkt_len);

                //std::cerr <<"sent a packet." << std::endl;
                delete [] pkt_data;
                ++counter_;
            }
            else
            {
                // std::cerr << "pool empty" << std::endl;
            }
            get_sleep_time(&sleep);
            nanosleep(&sleep,NULL);
        }
    }

    void get_sleep_time(timespec * t)
    {
        t->tv_sec = 0;
        t->tv_nsec = (NSEC_MAX - 1)/pkt_rate_;
    }

    //actual binary packet generate function
    void gen_pkt(header &h, uint8_t ** pkt_data, uint32_t *pkt_len)
    {
        uint32_t payload_size = 0;
        uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp) + payload_size;
        uint8_t * buffer = new uint8_t[buffer_size];
        memset(buffer,0,buffer_size);
        sniff_ethernet * eth = (sniff_ethernet *)buffer;
        sniff_ip * ip = (sniff_ip *)(buffer+sizeof(sniff_ethernet));
        sniff_tcp * tcp = (sniff_tcp *)(buffer + sizeof(sniff_ethernet) + sizeof(sniff_ip));

        if(h.eth != nullptr)
        {
            memcpy(eth,h.eth,sizeof(sniff_ethernet));
        }

        if(h.ip != nullptr)
        {
            *ip = *h.ip;
        }

        if(h.tcp != nullptr)
        {
            if(payload_size != 0)
                h.tcp->th_seq += htonl(payload_size);
            else
                h.tcp->th_seq += htonl(1);
            h.tcp->th_ack += htonl(1);
            memcpy(tcp,h.tcp,sizeof(sniff_tcp));
        }

        ip->ip_len = htons(buffer_size - sizeof(sniff_ethernet));
        tcp->th_win = htons(100);
        *pkt_data = buffer;
        *pkt_len = buffer_size;
    }
};

class PktNDumper{
    public:
        PktNDumper(PacketGen &packet_generator):is_running_(false),packet_generator_(packet_generator){}
        void start(){
            is_running_ = true;
            dump();
        }
    private:
        bool is_running_;
        PacketGen &packet_generator_;
        void dump(){
            while(is_running_){
                sleep(1);
                unsigned int num_sent_packets = packet_generator_.getCounter();
                packet_generator_.setCounter(0);
                printf("%u\n",num_sent_packets);
            }
        }
    
};

int main(int argc, char *argv[])
{
    if(argc < 5)
    {
        printf("Usage: FlowGen2 device flow_rate durarion packet_rate\t");
        return 1;
    }
    char * device = argv[1];
    unsigned int flow_rate = atoi(argv[2]);
    double duration = atof(argv[3]);
    unsigned int packet_rate = atoi(argv[4]);
    headers_pool pool;
    FlowGen flow_generator(pool,flow_rate,duration);
    PacketGen packet_generator(pool,device,packet_rate);
    PktNDumper pkt_dumper(packet_generator);
    std::thread flow_gen_thr(&FlowGen::start,&flow_generator);
    std::thread pkt_gen_thr(&PacketGen::start,&packet_generator);
    std::thread pkt_dump_thr(&PktNDumper::start,&pkt_dumper);
//    flow_gen_thr.detach();
//    pkt_gen_thr.detach();

    flow_gen_thr.join();
    pkt_gen_thr.join();
    pkt_dump_thr.join();
//    getchar();
//    flow_generator.stop();
//    packet_generator.stop();
}
