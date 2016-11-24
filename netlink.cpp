#include "netlink.h"
#include "threads.h"


pid_t get_radius_pid()
{
	system("ps | grep radius | grep -v grep | awk '{print $1}' > /tmp/radius.pid");

	ifstream f;
	f.open("/tmp/radius.pid");
	pid_t pid;
	f >> pid;
	f.close();
	cout << "pid == " << pid << endl;
	return pid;
}

pid_t radius_pid;

int LE_Sendmsg(char *pbuf, int len, pid_t pid, int type)
{
	struct sockaddr_nl nlskaddr;
    int socketfd = -1;
    struct NL_MSG *pNLMsg = NULL;
    int size = sizeof(struct NL_MSG) + len;

    pNLMsg = (struct NL_MSG *)malloc(size);
    if (NULL != pNLMsg)
    {
		socketfd = socket(PF_NETLINK, SOCK_DGRAM, LE_NETLINK_MSG);
		if (socketfd < 0)
		{
			perror("socket error: ");
		}
		else
		{
			memset(&nlskaddr, 0, sizeof(nlskaddr));
			nlskaddr.nl_family = AF_NETLINK;
			nlskaddr.nl_pid = getpid();
			nlskaddr.nl_groups = 0;
			if (-1 == bind(socketfd, (struct sockaddr *)&nlskaddr, sizeof(nlskaddr)))
			{
				close(socketfd);
			}
			else
			{
				nlskaddr.nl_pid = pid;

				memset(pNLMsg, 0, size);
			    pNLMsg->hdr.nlmsg_len = size;
			    pNLMsg->msgId = type;
			    pNLMsg->dataLen = len;
			    memcpy(pNLMsg->data, pbuf, len);

				if (-1 == sendto(socketfd, pNLMsg, size, 0, (struct sockaddr *)&nlskaddr, sizeof(nlskaddr)))
				{
					perror("sendto error: ");
				}
				cout << "send success " << endl;
			    close(socketfd);
			}
		}
		free(pNLMsg);
		
    }

    return 0;
}

int wx_auth(int ipaddr, unsigned char *mac, char *openid, char *publicid, char *accesstoken, pid_t pid)
{
	struct dc_wx_auth_args args;
	args.ip_addr = ipaddr;
	memcpy(args.mac, mac, sizeof(args.mac));
	memcpy(args.wx_openid, openid, sizeof(args.wx_openid));
	memcpy(args.wx_publicid, publicid, sizeof(args.wx_publicid));
	memcpy(args.wx_accesstoken, accesstoken, sizeof(args.wx_accesstoken));

	LE_Sendmsg((char *)&args,sizeof(args), pid, DUNCHONG_WEIXIN_AUTH);
}

void * wx_auth_work_func(void *arg)
{
	struct dc_wx_auth_args *args = (struct dc_wx_auth_args*)arg;
	cout << "aaaaaaaa" << endl;
	wx_auth(args->ip_addr,args->mac,args->wx_openid,args->wx_publicid,args->wx_accesstoken,radius_pid);
	free(args);
}



