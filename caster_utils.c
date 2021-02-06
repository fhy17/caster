/**********************************************************************************
*Company: chengdu HWA
*Engineer:lushenghong
*Create Date:2017.9.4
*Version:V1.0
*
************************************************************************************/
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <time.h>


int make_socket_non_blocking (int sfd) {
  int flags, s;

  flags = fcntl(sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror("fcntl");
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl(sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror("fcntl");
      return -1;
    }

  return 0;
}

int create_and_bind(char *port) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, retval;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices. */
  hints.ai_socktype = SOCK_STREAM; /*  We want a TCP socket. */
  hints.ai_flags = AI_PASSIVE;     /*  All interfaces. */

  retval = getaddrinfo(NULL, port, &hints, &result);
  if (retval != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retval));
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    retval = bind(sfd, rp->ai_addr, rp->ai_addrlen);
    if (retval == 0) {
      /*  We managed to bind successfully! */
      break;
    }

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "Could not bind\n");
    return -1;
  }

  freeaddrinfo(result);

  return sfd;
}


/**
 * get local ipv4 address
 * @netdev: net device name
 * @ipaddr: save return ipaddr
 * @len: ipaddr buffer len
 * @return: ok:0, error:-1
 */
int get_local_ipaddr(const char *netdev, char *ipaddr, int len)
{
	int sfd;
	struct ifreq ifr;
	struct sockaddr_in *saddr;
	char buf[64] = {0};

	if(!netdev || !strcmp(netdev, "")) {
		fprintf(stderr, "%s, netdev can not be empty.\n", __func__);
		return -1;
	}

	if((sfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s, socket error:%s\n", __func__, strerror(errno));
		return -1;
	}

	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, "eth0");
	if(ioctl(sfd, SIOCGIFADDR, &ifr) == -1) {
		fprintf(stderr, "%s, ioctl error:%s\n", __func__, strerror(errno));
		return -1;
	}
	
	saddr = (struct sockaddr_in *)&ifr.ifr_addr;
	if(!inet_ntop(AF_INET, &saddr->sin_addr, buf, sizeof(buf))) {
		fprintf(stderr, "%s, inet_ntop error:%s\n", __func__, strerror(errno));
		return -1;
	}
	if(len <= strlen(buf)) {
		fprintf(stderr, "%s, buffer len is not enough.\n", __func__);
		return -1;
	}
	strcpy(ipaddr, buf);

	return 0;
}


/**
 * Delete comments and trailing whitespace characters
 */
void chop(char *str)
{
	char *p = NULL;

	for(p=str; *p != '#' && *p != '\0'; p++)
		continue;

	*p = '\0';

	for(p=str+strlen(str) - 1; p>=str && !isgraph((int)*p); p--)
		*p = '\0';
}


void base64_decode( const char *base64, char *bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
	const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
}

char* caster_get_time(char *buf)
{
	time_t ti = time(0);
	char *p = NULL;
	
	ctime_r(&ti, buf);
	p = strstr(buf, "\n");
	if(p)
		*p = '\0';
	
	return buf;
}

