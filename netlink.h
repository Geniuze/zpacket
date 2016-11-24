#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h> 

#include <fstream>

#include <linux/netlink.h>


#define LE_NETLINK_MSG 30
#define DUNCHONG_WEIXIN_AUTH 103

struct NL_MSG
{
    struct nlmsghdr hdr;
	unsigned short	msgId;
	unsigned short	dataLen;
	unsigned char	data[0];
};

struct dc_wx_auth_args
{
	unsigned int ip_addr;
	unsigned char mac[8];
	char wx_openid[64];
	char wx_publicid[64];
	char wx_accesstoken[512];
};
extern pid_t radius_pid;

void * wx_auth_work_func(void *arg);
pid_t get_radius_pid();



