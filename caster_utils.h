/**********************************************************************************
*Company: chengdu HWA
*Engineer:lushenghong
*Create Date:2017.9.4
*Version:V1.0
*
************************************************************************************/
#ifndef CASTER_UTILS_H_
#define CASTER_UTILS_H_

extern int make_socket_non_blocking (int sfd);
extern int create_and_bind(char *port);
extern int get_local_ipaddr(const char *netdev, char *ipaddr, int len);
extern void chop(char *str);
extern void base64_decode( const char *base64, char *bindata);
extern char* caster_get_time(char *buf);

#endif