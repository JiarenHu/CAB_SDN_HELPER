#include <arpa/inet.h>
#include <sys/time.h>
#include <pcap.h>
#include <limits.h>
#include <string.h>
#include <list>
#include <time.h>
#include <thread>
#include <memory>
#include <mutex>
#include <iostream>
#include <stdio.h>
#include "header_def.h"
const unsigned int NSEC_MAX = 999999999;
void timer_add(timespec *a, timespec *b, timespec *rs)
{
    rs->tv_sec = a->tv_sec + b->tv_sec;
    rs->tv_nsec = a->tv_nsec + b->tv_nsec;
    if(rs->tv_nsec > 1000000000)
    {
        rs->tv_sec -= 1;
        rs->tv_nsec -= 1000000000;
    }
}
class header
{
public:
    timespec timestamp;
    uint16_t quantum;
};

class header_eth:
    public header
{
public:
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
    void toString ()
    {
        printf("dst : %x src: %x type: %x duration %d\n",ether_dhost+2,ether_shost+2,ether_type,timestamp.tv_sec);
    }
};

class headers_pool
{
public:
    headers_pool()
    {
        curr_pos = pool_.end();
    }
    void addHeader(header_eth&& h)
    {
        std::lock_guard<std::mutex>(this->pool_mutex_);
        timespec now;
        clock_gettime(CLOCK_REALTIME,&now);
        std::cerr << now.tv_sec<<"."<< now.tv_nsec <<" add a header\t";
        h.toString();
        pool_.push_back(h);
    }
    bool getHeader(header_eth& h)
    {
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

            if(timeercmp(now,expir_time) == 1)
            {
                //a expired header, delete
                std::cerr << now.tv_sec<<"."<< now.tv_nsec <<" delete an expired header\t";
                curr_pos->toString();
                curr_pos = pool_.erase(curr_pos);
            }
            else
            {
                //std::cerr << now.tv_sec<<"."<< now.tv_nsec <<" found a header\t";
                //h.toString();
                //valid header return
                h = *curr_pos;
                ++curr_pos;
                return true;
            }
        }

        return false;
    }
private:
    std::list<header_eth> pool_;
    std::list<header_eth>::iterator curr_pos;
    std::mutex pool_mutex_;
private:
    char timeercmp(timespec a, timespec b)
    {
        if(a.tv_sec > b.tv_sec)
        {
            return 1;
        }
        else if(a.tv_sec < b.tv_sec)
        {
            return -1;
        }
        else
        {
            if(a.tv_nsec > b.tv_nsec)
            {
                return 1;
            }
            else if(a.tv_nsec < b.tv_nsec)
            {
                return -1;
            }
            else
            {
                return 0;
            }
        }

    }
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

    void timespec_set(timespec *tv, double dt)
    {
        uint64_t us = dt*1000000000;
        tv->tv_sec = us / 1000000000;
        tv->tv_nsec = us - tv->tv_sec*1000000000;
    }

    header_eth make_header()
    {
        static uint32_t dst = 0;
        static uint32_t src = UINT32_MAX-1;
        header_eth eth;
        uint32_t *mac_dst = (uint32_t *)(eth.ether_dhost + 2);
        uint32_t *mac_src = (uint32_t *)(eth.ether_shost + 2);
        *mac_dst = htonl(dst--);
        *mac_src = htonl(src++);
        eth.ether_dhost[2] = 0x0c;
        eth.ether_shost[0] = 0x00;
        eth.ether_shost[1] = 0x02;
        eth.ether_shost[2] = 0xb3;
        timespec dr,now;
        timespec_set(&dr,duration_);
        clock_gettime(CLOCK_REALTIME,&now);
        timer_add(&now,&dr,&eth.timestamp);
        eth.quantum = 1;
        return eth;
    }
    void get_sleep_time(timespec *t)
    {
        t->tv_sec = 0;
        t->tv_nsec = NSEC_MAX/flows_;
    }
};

class PacketGen
{
public:
    PacketGen(headers_pool &pool, char * device, unsigned int pkt_rate)
        :pool_(pool),pkt_rate_(pkt_rate),running_(false)
    {
        pd = pcap_open_live(device,1514,1,1000,err_buf);
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
    headers_pool &pool_;
    pcap_t *pd;
    char err_buf[PCAP_ERRBUF_SIZE];
    unsigned int pkt_rate_;
    bool running_;

    void make_header(header_eth &h, uint8_t ** pkt_data, uint32_t *pkt_len)
    {
        uint32_t payload_size = 0;
        uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp) + payload_size;
        uint8_t * buffer = new uint8_t[buffer_size];
        memset(buffer,0,buffer_size);
        sniff_ethernet * eth = (sniff_ethernet *)buffer;
        sniff_ip * ip = (sniff_ip *)(buffer+sizeof(sniff_ethernet));
        sniff_tcp * tcp = (sniff_tcp *)(buffer + sizeof(sniff_ethernet) + sizeof(ip));

        eth->ether_type = ETHER_TYPE_IP;
        ip->ip_len = htons(buffer_size - sizeof(sniff_ethernet));
        memcpy(eth->ether_dhost,h.ether_dhost,6);
        memcpy(eth->ether_shost,h.ether_shost,6);
        *pkt_data = buffer;
        *pkt_len = buffer_size;
    }

    void gen()
    {
        timespec sleep;
        sleep.tv_sec = 0;
        sleep.tv_nsec = NSEC_MAX/pkt_rate_;
        while(running_)
        {
            header_eth h;
            if(pool_.getHeader(h))
            {
                uint8_t *pkt_data = NULL;
                uint32_t pkt_len = 0;
                make_header(h, &pkt_data, &pkt_len);
                pcap_sendpacket(pd, pkt_data, pkt_len);
                std::cerr <<"sent a packet." << std::endl;
                delete [] pkt_data;
            }
            else
            {
                // std::cerr << "pool empty" << std::endl;
            }
            nanosleep(&sleep,NULL);
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

    std::thread flow_gen_thr(&FlowGen::start,&flow_generator);
    std::thread pkt_gen_thr(&PacketGen::start,&packet_generator);
//    flow_gen_thr.detach();
//    pkt_gen_thr.detach();

    flow_gen_thr.join();
    pkt_gen_thr.join();
//    getchar();
//    flow_generator.stop();
//    packet_generator.stop();
}
