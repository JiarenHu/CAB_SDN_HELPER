#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <fstream>
#include <string>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>
#include "header_defu.h"
#include "TimeSpec.hpp"
#include "../CAB_SDN/Address.hpp"
using namespace std;
namespace fs = boost::filesystem;
namespace io = boost::iostreams;

int make_pkt(const addr_5tup & h, uint8_t ** data, uint32_t * pkt_len)
{
    
    uint32_t payload_size = sizeof(timespec);
    uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp) + payload_size;
    uint8_t * buffer = new uint8_t[buffer_size];
    memset(buffer,0,buffer_size);
    sniff_ethernet * eth = (sniff_ethernet *)buffer;
    sniff_ip * ip = (sniff_ip *)(buffer+sizeof(sniff_ethernet));
    sniff_tcp * tcp = (sniff_tcp *)(buffer + sizeof(sniff_ethernet) + sizeof(sniff_ip));
    uint8_t * body = buffer + sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp);


    *eth = sniff_ethernet();
    *ip = sniff_ip();
    *tcp = sniff_tcp();
    ip->ip_src.s_addr = htonl(h.addrs[0]);
    ip->ip_dst.s_addr = htonl(h.addrs[1]);
    ip->ip_len = htonl(buffer_size - sizeof(sniff_ethernet));
    
    //make time stamp
    timespec * timestamp = (timespec *)body;
    clock_gettime(CLOCK_REALTIME,timestamp);

    *data = buffer;
    *pkt_len = buffer_size;
    return 0;
}

int main(int argc, char * argv[])
{
    if(argc < 4)
    {
        cerr << "Usage: FlowGen {trace_file} {-i interface |-f pcap_file} "<< endl;
        return 1;
    }

    ifstream trace_file(argv[1]);
    if(!trace_file.is_open())
    {
        cerr << "Can not open trace file : " << argv[1] << endl;
        return 2;
    }
    pcap_t * pd = nullptr;
    char pebuf[PCAP_ERRBUF_SIZE];
    if( strcmp("-i",argv[2]) == 0)
    {
        pd = pcap_open_live(argv[3],1514,1,1000,pebuf);
    }
    else if(strcmp("-f",argv[2] ) == 0)
    {
        pd = pcap_open_dead(DLT_EN10MB,144);
        pcap_dumper_t * pfile = pcap_dump_open(pd,argv[3]);
    }
    else
    {
        cerr << "second parameter should be -i or -f" <<endl;
        return 3;
    }

    try
    {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        in.push(trace_file);
        string line;
        TimeSpec zero,now;
        clock_gettime(CLOCK_MONOTONIC,&zero.time_point_);
        while(getline(in,line))
        {
            //read header.
            addr_5tup pkt_header(line);

            //prepare packet data.
            uint8_t * pkt = nullptr;
            uint32_t  pkt_len = 0;

            //get next packet out time.
            TimeSpec next_pkt(pkt_header.timestamp);
            clock_gettime(CLOCK_MONOTONIC,&now.time_point_);
            if(now < zero + next_pkt)
            {
                TimeSpec to_sleep = next_pkt + zero - now;
                nanosleep(&to_sleep.time_point_,nullptr);
            }

            make_pkt(pkt_header,&pkt,&pkt_len);
            pcap_sendpacket(pd,pkt,pkt_len);
            delete [] pkt;
        }
    }
    catch(std::exception & e)
    {
        cerr << e.what() << endl;
    }
}
