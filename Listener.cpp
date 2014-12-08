#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>

#include <unordered_map>
#include <iostream>
#include <boost/functional/hash.hpp>
#include "TimeSpec.hpp"
#include "header_defu.h"

unsigned int pkt_cnt = 0;
pcap_t * pd = NULL;

double delays[100000];


struct ip_pair
{
    std::pair<uint32_t,uint32_t> key;
    bool operator==(const ip_pair &other) const
    {
        return key.first == other.key.first && key.second == other.key.second;
    }
};

namespace std
{
template <>
struct hash<ip_pair>
{
    std::size_t operator()(const ip_pair& k) const
    {
        using boost::hash_value;
        using boost::hash_combine;
        std::size_t seed = 0;
        hash_combine(seed,hash_value(k.key.first));
        hash_combine(seed,hash_value(k.key.second));
        return seed;
    }
};
}

std::unordered_map<ip_pair,TimeSpec> flow_stt;

void call_back( uint8_t *user,
                const struct pcap_pkthdr *pkthdr,
                const uint8_t *pktdata)
{
    const int body_offset = SIZE_ETHERNET + SIZE_IP + SIZE_TCP;
    const int ip_offset = SIZE_ETHERNET;
    if(pkthdr->len > body_offset)
    {
        const uint8_t *body = pktdata + body_offset;
        TimeSpec now(true);
        TimeSpec sent(*(timespec* )body);
        sent.time_point_.tv_sec = be64toh(sent.time_point_.tv_sec);
        sent.time_point_.tv_nsec = be64toh(sent.time_point_.tv_nsec);
        TimeSpec delay = now - sent;
        delays[pkt_cnt] = now.to_double() - sent.to_double(); 

//        sniff_ip *ip = (sniff_ip *)(pktdata + ip_offset);
//        uint32_t ip_src = ntohl(ip->ip_src.s_addr);
//        uint32_t ip_dst = ntohl(ip->ip_dst.s_addr);
//        ip_pair ipp = {std::make_pair(ip_src,ip_dst)};
//        if(flow_stt.find(ipp) != flow_stt.end())
//        {
//            //exist do nothing
//        }
//        else
//        {
//            //new flow
//            flow_stt[ipp] = delay;
//            char ip_src_str[16],ip_dst_str[16];
//            strcpy(ip_src_str,inet_ntoa(ip->ip_src));
//            strcpy(ip_dst_str,inet_ntoa(ip->ip_dst));
//            std::cout << "pkt #: "<< pkt_cnt<<"\t\t"
//                << ip_src_str << " -> " << ip_dst_str <<"\t\t"
//                << delay.to_double()*1000<<"ms"<<std::endl;
//        }
        pkt_cnt++;
    }
}

void int_handler(int sig)
{
    pcap_breakloop(pd);

}

int main(int argc,char * argv [])
{
    if(argc < 3)
    {
        printf("Usage Listener {interface} {delay_file}");
        return 1;
    }
    FILE * log = fopen(argv[2],"wb");
    char errbuf[PCAP_ERRBUF_SIZE];
    pd = pcap_open_live(argv[1],1514,1,1000,errbuf);
    signal(SIGINT,int_handler);
    pcap_loop(pd,-1,call_back,NULL);

    for(int i = 0; i < pkt_cnt; ++i){
        fprintf(log,"packet # : %u\t%lfs\n",i,delays[i]);
    }
    fclose(log);
}
