#include <error.h>
#include <arpa/inet.h>
#include <signal.h>
#include <ctime>
#include <climits>
#include <cstring>
#include <string>
#include <iostream>
#include <pcap.h>
#include <vector>
#include "header_def.h"
using namespace std;
bool is_run = true;
// Subtract the `struct timeval' values X and Y,
// storing the result in RESULT.
// Return 1 if the difference is negative, otherwise 0. */
int timeval_subtract (timespec *result,timespec * x, timespec *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_nsec < y->tv_nsec)
    {
        int nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
        y->tv_nsec -= 1000000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000)
    {
        int nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
        y->tv_nsec += 1000000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
     *           tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_nsec = x->tv_nsec - y->tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}
void make_pkt(u_char **pkt_data, u_int *pkt_len)
{
    uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp) + 1400;
    u_char * buffer = new u_char[buffer_size];
    static uint32_t src = UINT_MAX - 1;
    static uint32_t dst = 0;
    sniff_ethernet eth;
    sniff_ip ip;
    sniff_tcp tcp;
    ip.ip_len = sizeof(ip) + sizeof(tcp) + 1400;
    uint32_t *mac_dst = (uint32_t *)(eth.ether_dhost + 2);
    uint32_t *mac_src = (uint32_t *)(eth.ether_shost + 2);
    *mac_src = htonl(src--);
    *mac_dst = htonl(dst++);
    eth.ether_dhost[2] = 0x0c;
    eth.ether_shost[0] = 0x00;
    eth.ether_shost[1] = 0x02;
    eth.ether_shost[2] = 0xb3;
    memcpy(buffer, &eth, sizeof(eth));
    memcpy(buffer + sizeof(eth), &ip, sizeof(ip));
    memcpy(buffer + sizeof(eth) + sizeof(ip), &tcp,sizeof(tcp));
    *pkt_data = buffer;
    *pkt_len = buffer_size; 
}

static void handle_int(int signo){
    is_run = false;
};

int main(int argc, char * argv[])
{
    timespec pgm_start;
    timespec pgm_end;
    clock_gettime(CLOCK_REALTIME,&pgm_start);
    signal(SIGINT,handle_int);
    unsigned int failed = 0;
    unsigned int pkt_cnt = 0;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t * pd = pcap_open_live(argv[1],1514,1,1000,ebuf);
    unsigned int flow_per_sec = atoi(argv[2]);
    unsigned int fector = atoi(argv[3]);
    long unsigned int nsec = 1000000000;
    timespec nsleep = {0,(long int)nsec/flow_per_sec};
    vector<unsigned int> out_per_sec;

    unsigned int pkt_cnt_per_sec = 0;
    timespec sec_beg,sec_end;
    clock_gettime(CLOCK_REALTIME,&sec_beg);
    while(is_run)
    {
        timespec start,end;
        clock_gettime(CLOCK_REALTIME,&start);
        clock_gettime(CLOCK_REALTIME,&sec_end);
        if(sec_end.tv_sec - sec_beg.tv_sec >= 1)
        {
            out_per_sec.push_back(pkt_cnt_per_sec);
            cout <<sec_end.tv_sec<< " "<< pkt_cnt_per_sec << endl;
            clock_gettime(CLOCK_REALTIME,&sec_beg);
            pkt_cnt_per_sec = 0;
        }
        for(int i = 0; i < fector; ++i)
        {
            u_char *pkt_data = NULL;
            u_int pkt_len = 0;
            ++pkt_cnt;
            ++pkt_cnt_per_sec;
            make_pkt(&pkt_data,&pkt_len);
            if(pcap_sendpacket(pd,pkt_data,pkt_len) == -1)
            {
                ++failed;
                cerr << pcap_geterr(pd) << endl ;
            }
            delete (sniff_ethernet*)pkt_data;
        }
        clock_gettime(CLOCK_REALTIME, &end);
        timespec real_s = {0,0};
        timespec temp = {0,0};
        timeval_subtract(&temp,&end,&start);
        if(timeval_subtract(&real_s,&nsleep,&temp) != 1)
        {//not negative
            if(nanosleep(&real_s, NULL) == -1)
            {
                cerr << "nanosleep():" << strerror(errno) << endl;
                cerr << "real_sleep "<<real_s.tv_sec  << "." << real_s.tv_nsec << endl;
            }
        }

        timespec loop_timer;
        clock_gettime(CLOCK_REALTIME,&loop_timer);
    }
    clock_gettime(CLOCK_REALTIME, &pgm_end);
    cout << "failed : " << failed << endl;
    cout << "successed : " << pkt_cnt << endl;
    timespec run_time;
    timeval_subtract(&run_time, &pgm_end, &pgm_start);  
    cout << "run time : " << run_time.tv_sec << "." << run_time.tv_nsec << endl;
    cout << "avg per sec : " << (double)pkt_cnt/run_time.tv_sec << endl;
    return 0;
}
