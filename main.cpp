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
} __attribute__((__packed__));

struct thread_arg
{
	char dip[32];
	unsigned char dmac[8];
	unsigned short dport;
	unsigned short sport;
	unsigned char smac[8];
	char sip[32];
	char interface[128];
};

unsigned long long htonll(unsigned long long src)
{
	unsigned long long dst = 0;
	char *ps = NULL, *pd = NULL;

	ps = (char *)&src;
	pd = (char *)&dst;

	for (int i = 0; i < 8; ++i)
	{
		pd[i] = ps[7 - i];
	}

	return dst;
}

int get_iface_index(int fd, const char *interface_name)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, interface_name);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
	{
		return (-1);
	}
	return ifr.ifr_ifindex;
}

unsigned short check_sum(unsigned short *addr, int len)
{
	unsigned short cksum;
	unsigned int sum = 0;

	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1)
		sum += *(unsigned char *)addr;
	sum = (sum >> 16) + (sum & 0xffff); //\u628a\u9ad8\u4f4d\u7684\u8fdb\u4f4d\uff0c\u52a0\u5230\u4f4e\u516b\u4f4d\uff0c\u5176\u5b9e\u662f32\u4f4d\u52a0\u6cd5
	sum += (sum >> 16);					//add carry
	cksum = ~sum;						//\u53d6\u53cd
	return (cksum);
}

int send_udp(char *dip, unsigned char *dmac, unsigned short dport,
			 char *sip, unsigned char *smac, unsigned short sport, const char *interface)
{
	struct sockaddr_ll addr;

	char dest_mac[6] = {0};
	char source_mac[6] = {0};

	memcpy(dest_mac, dmac, 6);
	memcpy(source_mac, smac, 6);

	int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (0 > sockfd)
	{
		cout << "socket perror" << endl;
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = get_iface_index(sockfd, interface);
	addr.sll_protocol = htons(ETH_P_IP);

	pkt udp;
	memset(&udp, 0, sizeof(udp));

	memcpy(udp.eheader.h_dest, dest_mac, 6);
	memcpy(udp.eheader.h_source, source_mac, 6);
	udp.eheader.h_proto = htons(ETH_P_IP);

	udp.ipheader.version = 4;
	udp.ipheader.ihl = sizeof(udp.ipheader) >> 2;
	udp.ipheader.tos = 0;
	udp.ipheader.tot_len = htons(sizeof(udp.ipheader) + sizeof(udp.udpheader) + PKT_LEN);
	udp.ipheader.id = 0;
	udp.ipheader.frag_off = 0;
	udp.ipheader.ttl = MAXTTL;
	udp.ipheader.protocol = IPPROTO_UDP;
	udp.ipheader.daddr = inet_addr(dip);
	udp.ipheader.saddr = inet_addr(sip);
	udp.ipheader.check = check_sum((unsigned short *)&udp.ipheader, sizeof(udp.ipheader));

	udp.udpheader.source = htons(sport);
	udp.udpheader.dest = htons(dport);
	udp.udpheader.len = htons(sizeof(udp.udpheader) + PKT_LEN);
	udp.udpheader.check = check_sum((unsigned short *)&udp.udpheader, sizeof(udp.udpheader));

	udp.a[0] = 1;

	sendto(sockfd, &udp, sizeof(udp), 0, (struct sockaddr *)&addr, sizeof(addr));

	close(sockfd);
	return 0;
}

int hexchar_to_int(const char ch)
{
	switch(ch)
	{
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': 
    case 'A': return 10;
    case 'b': 
    case 'B': return 11;
    case 'c':
    case 'C': return 12;
    case 'd': 
    case 'D': return 13;
    case 'e': 
    case 'E': return 14;
    case 'f':
    case 'F': return 15;
    default : return -1;
	}
    
	return 0;
}

void string_to_mac(const char *pszString, unsigned char *aucMac)
{
    int i = 0;
    const char *p = pszString;
    /* 01:02:03:04:05:06 > 010203040506*/
	for (;i < 6; i++)
	{
		aucMac[i] = hexchar_to_int(*p++) << 4;
		aucMac[i] += hexchar_to_int(*p++);
        if (0 > hexchar_to_int(*p))
        {
		    p++;
        }
	}

    return;
}



int help()
{
	printf("-h/--help 	print help info\n");
	printf("--mac-start set source mac start default:00:00:00:00:00:01\n");
	printf("--ip-start  set source ip start default:192.168.5.10\n");
	printf("-c/--count  set station count default:100\n");
	printf("--dport  	set dest port default:8080\n");
	printf("--sport  	set source port default:5555\n");
	printf("-d/--dest  	set dest ip default:192.168.5.1\n");
	printf("--dest-mac  	set dest mac default:00:11:00:00:00:01\n");
	printf("-p/--proto  	set protocol support only udp default:udp\n");

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
	{"interface", 1, NULL, 'i'},
	{NULL, 0, NULL, 0},
};

const char *short_options = "h2:1:c:3:4:d:5:p:i:";

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
	string interface;
} cnf;

int test(mthreads_pool &mp)
{
	unsigned char mac_start[6];
	unsigned int ip_start;
	unsigned int count = atoi(cnf.count.c_str());
	unsigned char dmac[6];

	string_to_mac(cnf.mac_start.c_str(), mac_start);
	string_to_mac(cnf.dest_mac.c_str(), dmac);
	inet_pton(AF_INET, cnf.ip_start.c_str(), &ip_start);
	ip_start = ntohl(ip_start);

	unsigned char *mac_cur = mac_start;
	unsigned int ip_cur = ip_start;

	for (int i = 0; i < count; i++)
	{
		unsigned long long mac = htonll(*((unsigned long long *)mac_cur));
		unsigned char *pmac = (unsigned char *)&mac;
		unsigned int ip = htonl(ip_cur);
		mac += i << 16;
		mac = htonll(mac);
		unsigned char *p = (unsigned char *)&ip;
		char ip_str[32] = {0};
		snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);

		struct thread_arg *arg = (struct thread_arg *)malloc(sizeof(thread_arg));
		memset(arg, 0, sizeof(struct thread_arg));

		memcpy(arg->dip, cnf.dest.c_str(), cnf.dest.length());
		memcpy(arg->dmac, dmac, 6);
		arg->dport = atoi(cnf.dport.c_str());
		memcpy(arg->sip, ip_str, sizeof(ip_str));
		memcpy(arg->smac, pmac, 6);
		memcpy(arg->interface, cnf.interface.c_str(), cnf.interface.length());
		arg->sport = atoi(cnf.sport.c_str());

		mtpool_work work(work_func, arg);
		mp.mthreads_addwork(work);

		ip_cur++;
	}
	return 0;
}

void arg_options(int argc, char **argv)
{
	char opt;
	int opt_index;
	while ((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1)
	{
		switch (opt)
		{
		case 'h':
			help();
			break;
		case 'c':
			cnf.count = string(optarg);
			break;
		case 'd':
			cnf.dest = string(optarg);
			break;
		case 'p':
			cnf.proto = string(optarg);
			break;
		case '1':
			cnf.ip_start = string(optarg);
			break;
		case '2':
			cnf.mac_start = string(optarg);
			break;
		case '3':
			cnf.dport = string(optarg);
			break;
		case '4':
			cnf.sport = string(optarg);
			break;
		case '5':
			cnf.dest_mac = string(optarg);
			break;
		case 'i':
			cnf.interface = string(optarg);
			break;
		default:
			break;
		}
	}

	if (cnf.count == "") cnf.count = "100";
	if (cnf.dest == "") cnf.dest = "192.168.5.1";
	if (cnf.proto == "") cnf.proto = "udp";
	if (cnf.ip_start == "") cnf.ip_start = "192.168.5.10";
	if (cnf.mac_start == "") cnf.mac_start = "00:00:00:00:00:01";
	if (cnf.dport == "") cnf.dport = "8080";
	if (cnf.sport == "") cnf.sport = "5555";
	if (cnf.dest_mac == "") cnf.dest_mac = "00:11:00:00:00:01";
	if (cnf.interface == "") cnf.interface = "eth0";

	printf("count %s,dest ip %s,protocol %s, ip start %s, mac start %s, dest port %s, source port %s, dest mac %s\n",
	cnf.count.c_str(), cnf.dest.c_str(), cnf.proto.c_str(), cnf.ip_start.c_str(), cnf.mac_start.c_str(), cnf.dport.c_str(), cnf.sport.c_str(), cnf.dest_mac.c_str());
}

void *work_func(void *arg)
{
	struct thread_arg *p = (struct thread_arg *)arg;
	send_udp(p->dip, p->dmac, p->dport, p->sip, p->smac, p->sport, p->interface);
	free(p);
}

string rand_str(int count)
{
	string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
	struct timeval tv;
	gettimeofday(&tv, NULL);
	string s;

	srand(tv.tv_usec);

	for (int i = 0; i < count; i++)
	{
		s += str.substr(rand() % str.size(), 1);
	}
	cout << s << endl;
	return s;
}
int radius_test(mthreads_pool &mp)
{
	unsigned char mac_start[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	//	unsigned int ip_start = 0xc0a80001;
	unsigned int ip_start = 0xc0a8000a;

	unsigned int count = 2000;

	char dip[32] = "10.0.1.119";
	//	char dip[32] = "192.168.15.170";

	// A4:FB:8D:99:88:0F   d8:cb:8a:ae:5d:c8  1E:C5:6E:40:02:19
	//	unsigned char dmac[6] = {0xd8,0xcb,0x8a,0xae,0x5d,0xc8};
	//	unsigned char dmac[6] = {0xA4,0xFB,0x8D,0x99,0x88,0x0F};
	unsigned char dmac[6] = {0x1E, 0xC5, 0x6E, 0x40, 0x02, 0x19};

	unsigned char *mac_cur = mac_start;
	unsigned int ip_cur = ip_start;

	for (int i = 0; i < count; i++)
	{
		unsigned long long mac = htonll(*((unsigned long long *)mac_cur));
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
		memcpy(arg->mac, pmac + 2, 6);
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
	//radius_pid = get_radius_pid();
	arg_options(argc, argv);

	mthreads_pool mp;
	mp.mthreads_init();
	//if (argc > 1)
	//{
	test(mp);
	//	}
	//	else
	//	{
	//		radius_test(mp);
	//	}
	while (mp.mthreads_workcount())
	{
	}

	mp.mthreads_finit();
}
