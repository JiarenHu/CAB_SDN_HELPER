#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "TimeSpec.hpp"
#include "header_defu.h"

double delay[10000000];
unsigned int pkt_cnt = 0;
pcap_t * pd = NULL;
void call_back( uint8_t *user,
                const struct pcap_pkthdr *pkthdr,
                const uint8_t *pktdata)
{
    const int body_offset = SIZE_ETHERNET + SIZE_IP + SIZE_TCP;
    if(pkthdr->len > body_offset)
    {
        const uint8_t *body = pktdata + body_offset;
        TimeSpec now(true);
        TimeSpec tst(*(timespec* )body);
        TimeSpec pkt_d = now - tst;
        delay[pkt_cnt] = pkt_d.to_double();
        //printf("%1.10lf\n",delay[pkt_cnt]);
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

    fwrite(delay,sizeof(double),pkt_cnt,log);
    fclose(log);
}
