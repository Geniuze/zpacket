#include <iostream>
using namespace std;
extern "C"
{
#include <sys/types.h>  
#include <sys/time.h>  
#include <time.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/if_ether.h>  
#include <net/if_arp.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>  
#include <errno.h>  
#include <netinet/if_ether.h>  
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if_arp.h>  
#include <net/if.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <sys/ioctl.h>  
#include <netpacket/packet.h>  
#include <pthread.h>
#include <getopt.h>
}
#include <cstdlib>  
#include "threads.h"
#include "netlink.h"


#define PKT_LEN 1400

void *work_func(void *arg);

struct pkt
{
	struct ethhdr eheader;
	struct iphdr ipheader;
	struct udphdr udpheader;
	char a[PKT_LEN];
}__attribute__ ((__packed__));

struct thread_arg
{
	char dip[32];
	unsigned char dmac[8];
	unsigned short dport;
	unsigned short sport;
	unsigned char smac[8];
	char sip[32];
};

unsigned long long htonll(unsigned long long src)
{
	unsigned long long dst = 0;
	char *ps = NULL, *pd = NULL;

	ps = (char *) &src;
	pd = (char *) &dst;

	for (int i=0; i<8; ++i)
	{
		pd[i] = ps[7-i];
	}

	return dst;
}

int get_iface_index(int fd, const char* interface_name)  
{  
    struct ifreq ifr;  
    memset(&ifr, 0, sizeof(ifr));  
    strcpy (ifr.ifr_name, interface_name);  
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)  
    {  
        return (-1);  
    }  
    return ifr.ifr_ifindex;  
}  

unsigned short check_sum(unsigned short *addr,int len)
{
	unsigned short cksum;
    unsigned int sum=0;
 
    while(len>1)
    {
        sum+=*addr++;
        len-=2;
    }
    if(len==1)
        sum+=*(unsigned char*)addr;
    sum=(sum>>16)+(sum&0xffff);  //\u628a\u9ad8\u4f4d\u7684\u8fdb\u4f4d\uff0c\u52a0\u5230\u4f4e\u516b\u4f4d\uff0c\u5176\u5b9e\u662f32\u4f4d\u52a0\u6cd5
    sum+=(sum>>16);  //add carry
    cksum=~sum;   //\u53d6\u53cd
    return (cksum);
}

int send_udp(char *dip, unsigned char *dmac, unsigned short dport, 
					char *sip, unsigned char *smac, unsigned short sport)
{
	struct sockaddr_ll addr;
	
	char dest_mac[6] = {0};
	char source_mac[6] = {0};

	memcpy(dest_mac, dmac, 6);
	memcpy(source_mac, smac, 6);
	
	int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (0 > sockfd) { cout << "socket perror" << endl; perror("socket"); return -1;}

	memset(&addr, 0, sizeof(addr));  
	addr.sll_family = AF_PACKET;  
	addr.sll_ifindex = get_iface_index(sockfd, "eth0"); 
	addr.sll_protocol = htons(ETH_P_IP);  
	
	pkt udp;
	memset(&udp, 0, sizeof(udp));
	
	memcpy(udp.eheader.h_dest, dest_mac, 6);
	memcpy(udp.eheader.h_source, source_mac, 6);
	udp.eheader.h_proto = htons(ETH_P_IP);

	udp.ipheader.version = 4;
	udp.ipheader.ihl = sizeof(udp.ipheader)>>2;
	udp.ipheader.tos = 0;
	udp.ipheader.tot_len = htons(sizeof(udp.ipheader) + sizeof(udp.udpheader) + PKT_LEN);
	udp.ipheader.id = 0;
	udp.ipheader.frag_off = 0;
	udp.ipheader.ttl = MAXTTL;
	udp.ipheader.protocol = IPPROTO_UDP;
	udp.ipheader.daddr = inet_addr(dip);
	udp.ipheader.saddr = inet_addr(sip);
	udp.ipheader.check = check_sum((unsigned short*)&udp.ipheader, sizeof(udp.ipheader));
	
	udp.udpheader.source = htons(sport);
	udp.udpheader.dest = htons(dport);
	udp.udpheader.len = htons(sizeof(udp.udpheader) + PKT_LEN);
	udp.udpheader.check = check_sum((unsigned short*)&udp.udpheader, sizeof(udp.udpheader));

	udp.a[0] = 1;
	
	sendto(sockfd, &udp, sizeof(udp), 0, (struct sockaddr*)&addr, sizeof(addr));

	close(sockfd);
	return 0;
}

int test(mthreads_pool &mp)
{
	unsigned char mac_start[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
//	unsigned int ip_start = 0xc0a80001;
	unsigned int ip_start = 0xc0a8000a;

	unsigned int count = 2000;

	char dip[32] = "10.0.1.119";
//	char dip[32] = "192.168.15.170";

	// A4:FB:8D:99:88:0F   d8:cb:8a:ae:5d:c8  1E:C5:6E:40:02:19
//	unsigned char dmac[6] = {0xd8,0xcb,0x8a,0xae,0x5d,0xc8};
//	unsigned char dmac[6] = {0xA4,0xFB,0x8D,0x99,0x88,0x0F};
	unsigned char dmac[6] = {0x1E,0xC5,0x6E,0x40,0x02,0x19};

	unsigned char *mac_cur = mac_start;
	unsigned int ip_cur = ip_start;
	
	for (int i = 0; i < count ; i++)
	{
		unsigned long long mac = htonll(*((unsigned long long*)mac_cur));
		unsigned char *pmac = (unsigned char *)&mac;
		unsigned int ip = htonl(ip_cur);
		mac += i;
		mac = htonll(mac);
		unsigned char *p = (unsigned char *)&ip;
		char ip_str[32] = {0};
		snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);

		struct thread_arg *arg = (struct thread_arg *)malloc(sizeof(thread_arg));

		memcpy(arg->dip, dip, sizeof(dip));
		memcpy(arg->dmac, dmac, 6);
		arg->dport = 8080;
		memcpy(arg->sip, ip_str, sizeof(ip_str));
		memcpy(arg->smac, pmac+2, 6);
		arg->sport = 5555;

		mtpool_work work(work_func, arg);
		mp.mthreads_addwork(work);
				
		ip_cur++;
	}
	return 0;
}

const struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"mac-start", 1, NULL, '2'},
	{"ip-start", 1, NULL, '1'},
	{"count", 1, NULL, 'c'},
	{"dport", 1, NULL, '3'},
	{"sport", 1, NULL, '4'},
	{"dest", 1, NULL, 'd'},
	{"dest-mac", 1, NULL, '5'},
	{"proto", 1, NULL, 'p'},
	{NULL, 0, NULL, 0},
};

struct config
{
	string mac_start;
	string ip_start;
	string count;
	string dport;
	string sport;
	string dest;
	string dest_mac;
	string proto;
}cnf;

void arg_options(int argc, char **argv)
{
	char opt;
	int opt_index;
	while ((opt = getopt_long(argc, argv, NULL, long_options, &opt_index)) != -1)
	{
		switch (opt)
		{
		case 'h':break;
		case 'c':cnf.count = string(optarg); break;
		case 'd':cnf.dest  = string(optarg); break;
		case 'p':cnf.proto  = string(optarg); break;
		case '1':cnf.ip_start  = string(optarg); break;
		case '2':cnf.mac_start  = string(optarg); break;
		case '3':cnf.dport  = string(optarg); break;
		case '4':cnf.sport  = string(optarg); break;
		case '5':cnf.dest_mac  = string(optarg); break;
		default:break;
		}
	}
}

void *work_func(void *arg)
{
	struct thread_arg *p = (struct thread_arg *)arg;
	send_udp(p->dip,p->dmac,p->dport,p->sip,p->smac,p->sport);
	free(p);
}

string rand_str(int count)
{
	 string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
	 struct timeval tv;
	 gettimeofday(&tv, NULL);
	 string s;

	 srand(tv.tv_usec);

	 for (int i=0; i<count; i++)
	 {
	 	s += str.substr(rand()%str.size(), 1);
	 }
	 cout << s << endl;
	 return s;
}
int radius_test(mthreads_pool &mp)
{
	unsigned char mac_start[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
//	unsigned int ip_start = 0xc0a80001;
	unsigned int ip_start = 0xc0a8000a;

	unsigned int count = 2000;

	char dip[32] = "10.0.1.119";
//	char dip[32] = "192.168.15.170";

	// A4:FB:8D:99:88:0F   d8:cb:8a:ae:5d:c8  1E:C5:6E:40:02:19
//	unsigned char dmac[6] = {0xd8,0xcb,0x8a,0xae,0x5d,0xc8};
//	unsigned char dmac[6] = {0xA4,0xFB,0x8D,0x99,0x88,0x0F};
	unsigned char dmac[6] = {0x1E,0xC5,0x6E,0x40,0x02,0x19};

	unsigned char *mac_cur = mac_start;
	unsigned int ip_cur = ip_start;
	
	for (int i = 0; i < count ; i++)
	{
		unsigned long long mac = htonll(*((unsigned long long*)mac_cur));
		unsigned char *pmac = (unsigned char *)&mac;
		unsigned int ip = htonl(ip_cur);
		mac += i;
		mac = htonll(mac);
		unsigned char *p = (unsigned char *)&ip;
		char ip_str[32] = {0};
		snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);

		struct dc_wx_auth_args *arg = (struct dc_wx_auth_args *)malloc(sizeof(struct dc_wx_auth_args));
		memset(arg, 0, sizeof(*arg));
		arg->ip_addr = ip;
		memcpy(arg->mac, pmac+2, 6);
//		strcpy(arg->wx_openid, "oqgp3v-QMg_3BtCB4bknt99eR244");
		strcpy(arg->wx_openid, rand_str(20).c_str());
		strcpy(arg->wx_publicid, "gh_902093de1a52");
		strcpy(arg->wx_accesstoken, "ILxFV9pCW47z2UqPyA0q3Zq7FtKPpbut61yEMIXGMsNiYjFJchrkRqX1_5Ehi2WV6NJN4iRIJ_R3GMtnQXpw17UgUOLTIq0W7hui9Ob6tS4MEAbAGASKG");

		mtpool_work work(wx_auth_work_func, arg);
		mp.mthreads_addwork(work);
				
		ip_cur++;
	}
	return 0;
}


int main(int argc, char **argv)
{
	radius_pid = get_radius_pid();
	mthreads_pool mp;
	mp.mthreads_init();
	if (argc > 1)
	{
		test(mp);
	}
	else
	{
		radius_test(mp);
	}
	while (mp.mthreads_workcount()) {}
		
	mp.mthreads_finit();
		
}
