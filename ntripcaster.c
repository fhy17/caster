/**
 * ntripcaster.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <pthread.h>

#define _GNU_SOURCE
#include <sys/socket.h>


//#include "rtklib.h"
#include "ntripcaster.h"
#include "caster_utils.h"
#include "caster_event.h"

#define CASTERCONFFILE	"./etc/caster.conf"
#define MNTPTFILE		"./etc/mountpt.conf"
#define CLIUSERFILE		"./etc/userinfo.conf"


static struct ntripcaster caster;


static int update_caster_userfile()
{
	int i;
	FILE *fp;

	if(!(fp = fopen(CLIUSERFILE, "w"))) {
		fprintf(stderr, "%s: fopen error.\n", __func__);
		return -1;
	}

	for(i = 0; i < caster.user_num; i++) {
		fprintf(fp, "%s:%s\n", caster.user[i].name, caster.user[i].passwd);		
	}

	fclose(fp);
	fflush(fp);
	sync();
	return 0;
}

static int update_caster_mntptfile()
{
	int i;
	FILE *fp;

	if(!(fp = fopen(MNTPTFILE, "w"))) {
		fprintf(stderr, "%s: fopen error.\n", __func__);
		return -1;
	}

	for(i = 0; i < caster.mntpt_num; i++) {
		fprintf(fp, "%s:%s:%d\n", caster.mntpt[i].name, \
				caster.mntpt[i].passwd, caster.mntpt[i].datafmt);		
	}

	fclose(fp);
	fflush(fp);
	sync();
	return 0;
}

/************* ntrip caster connected ntrip server information *******************/

static int add_connsvr_info(const char *mntpt)
{
	char date[1024] = {0};
	struct list_head *list;
	struct caster_event *entry;

	if(!mntpt || caster.connsvr_len >= MAXNTRIPSVR) {
		return -1;
	}

	strncpy(caster.connsvr[caster.connsvr_len].mntpt, 
			mntpt, sizeof(caster.connsvr[0].mntpt));
	strncpy(caster.connsvr[caster.connsvr_len].uptime, 
			caster_get_time(date), sizeof(caster.connsvr[0].uptime));

	for(list = caster.event.next; list != &caster.event; list = list->next) {
		entry = list_event_entry(list);
		if(entry->conn_level == NTRIPCLI && !strcmp(entry->mntpt, mntpt)) {
			caster.connsvr[caster.connsvr_len].cli_connects++;
		}
	}
	caster.connsvr_len++;

	return 0;
}

static int update_connsvr_out_amount(const char *mntpt, int n_out) 
{
	int i = 0;
	char date[1024] = {0};

	for(i = 0; i < caster.connsvr_len; i++) {
		if(!strcmp(caster.connsvr[i].mntpt, mntpt)) {
			strncpy(caster.connsvr[i].uptime, caster_get_time(date), 
					sizeof(caster.connsvr[0].uptime));
			caster.connsvr[i].output += n_out;

			return 0;
		}
	}
	return -1;
}

static int update_connsvr_in_amount(const char *mntpt, int n_in) 
{
	int i = 0;
	char date[1024] = {0};

	for(i = 0; i < caster.connsvr_len; i++) {
		if(!strcmp(caster.connsvr[i].mntpt, mntpt)) {
			strncpy(caster.connsvr[i].uptime, caster_get_time(date), 
					sizeof(caster.connsvr[0].uptime));
			caster.connsvr[i].input += n_in;

			return 0;
		}
	}
	return -1;
}

static int connsvr_cli_connects_add(const char *mntpt)
{
	int i = 0;

	for(i = 0; i < caster.connsvr_len; i++) {
		if(!strcmp(caster.connsvr[i].mntpt, mntpt)) {
			caster.connsvr[i].cli_connects++;
			return 0;
		}
	}
	return -1;
}

static int connsvr_cli_connects_del(const char *mntpt)
{
	int i = 0;

	for(i = 0; i < caster.connsvr_len; i++) {
		if(!strcmp(caster.connsvr[i].mntpt, mntpt)) {
			caster.connsvr[i].cli_connects--;
			return 0;
		}
	}
	return -1;
}

static void del_connsvr_info(const char *mntpt)
{
	int i, j;
	
	for(i = 0; i < caster.connsvr_len; i++) {
		if(!strcmp(caster.connsvr[i].mntpt, mntpt)) {
			for(j = i; j < caster.connsvr_len-1; j++) {
				caster.connsvr[j] = caster.connsvr[j+1];
			}
			bzero(&caster.connsvr[j], sizeof(caster.connsvr[0]));
			caster.connsvr_len--;
			return ;
		}
	}
}


/************* ntrip caster connected ntrip client information *******************/
static int add_conncli_info(const char *mntpt, int connfd)
{
	char date[1024] = {0};
	struct list_head *list;
	struct caster_event *entry;

	if(!mntpt || caster.conncli_len >= MAXNTRIPCLI) {
		return -1;
	}

	caster.conncli[caster.conncli_len].connfd = connfd;
	strncpy(caster.conncli[caster.conncli_len].mntpt, 
			mntpt, sizeof(caster.conncli[0].mntpt));
	strncpy(caster.conncli[caster.conncli_len].uptime, 
			caster_get_time(date), sizeof(caster.conncli[0].uptime));

	caster.conncli_len++;

	return 0;
}

static int update_conncli_out_amount(int connfd, int n_out) 
{
	int i = 0;
	char date[1024] = {0};

	for(i = 0; i < caster.connsvr_len; i++) {
		if(caster.conncli[i].connfd == connfd) {
			strncpy(caster.conncli[i].uptime, caster_get_time(date), 
					sizeof(caster.conncli[0].uptime));
			caster.conncli[i].output += n_out;

			return 0;
		}
	}
	return -1;
}

static void del_conncli_info(int connfd)
{
	int i, j;
	
	for(i = 0; i < caster.conncli_len; i++) {
		if(caster.conncli[i].connfd == connfd) {
			for(j = i; j < caster.conncli_len-1; j++) {
				caster.conncli[j] = caster.conncli[j+1];
			}
			bzero(&caster.conncli[j], sizeof(caster.conncli[0]));
			caster.conncli_len--;
			return ;
		}
	}
}

static void init_logbuf(struct caster_log_ring_buffer *logbuf)
{
	bzero(logbuf->buf, sizeof(logbuf->buf));
	logbuf->read  = 0;
	logbuf->write = -1;
}

static char *caster_log_time(char *buf, int len)
{
	time_t ti;
	struct tm local_tm;

	bzero(buf, len);
	
	ti = time(0);
	if(localtime_r(&ti, &local_tm) == NULL) {
		return NULL;
	}

	snprintf(buf, len, "%d-%d-%d", local_tm.tm_hour, 
			local_tm.tm_min, local_tm.tm_sec);
	return buf;
}

static void caster_log(char *fmt, ...)
{
	char buf[LOGBUFSIZE] = {0};
	char date[128] = {0};
	va_list ap;
	
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if(*(buf+strlen(buf)-1) != '\n') {
		if(strlen(buf) < sizeof(buf)-1) {
			*(buf+strlen(buf)) = '\n';
		} else {
			*(buf+strlen(buf)-1) = '\n';
		}
	}
	caster_log_time(date, sizeof(date));
	snprintf(caster.logbuf.buf[(++caster.logbuf.write) & (LOGBUFNUM-1)], LOGBUFSIZE, 
			"%s:%s", date, buf);;

	if(caster.logbuf.write - caster.logbuf.read >= LOGBUFNUM) {
		/* buffer is full, overwriting the oldest log */
		caster.logbuf.read = caster.logbuf.write - LOGBUFNUM -1;
	}
}


/*********************** Init ntrip caster ******************************/

#if 1
static opt_t *searchopt(const char *name, const opt_t *opts)
{
    int i;

    //trace(3,"searchopt: name=%s\n",name);

    for (i=0;*opts[i].name;i++) {
        if (strstr(opts[i].name,name)) return (opt_t *)(opts+i);
    }
    return NULL;
}

static int str2enum(const char *str, const char *comment, int *val)
{
    const char *p;
    char s[32];

    for (p=comment;;p++) {
       if (!(p=strstr(p,str))) break;
       if (*(p-1)!=':') continue;
       for (p-=2;'0'<=*p&&*p<='9';p--) ;
       return sscanf(p+1,"%d",val)==1;
    }
    sprintf(s,"%30.30s:",str);
    if ((p=strstr(comment,s))) { /* number */
        return sscanf(p,"%d",val)==1;
    }
    return 0;
}

static int str2opt(opt_t *opt, const char *str)
{
    switch (opt->format) {
        case 0: *(int    *)opt->var=atoi(str); break;
        case 1: *(double *)opt->var=atof(str); break;
        case 2: strcpy((char *)opt->var,str);  break;
        case 3: return str2enum(str,opt->comment,(int *)opt->var);
        default: return 0;
    }
    return 1;
}

static int loadopts(const char *file, opt_t *opts)
{
    FILE *fp;
    opt_t *opt;
    char buff[2048],*p;
    int n=0;

    //trace(3,"loadopts: file=%s\n",file);

    if (!(fp=fopen(file,"r"))) {
        //trace(1,"loadopts: options file open error (%s)\n",file);
        return 0;
    }
    while (fgets(buff,sizeof(buff),fp)) {
        n++;
        chop(buff);

        if (buff[0]=='\0') continue;

        if (!(p=strstr(buff,"="))) {
            /* fprintf(stderr,"invalid option %s (%s:%d)\n",buff,file,n); */
            continue;
        }
        *p++='\0';
        chop(buff);
        if (!(opt=searchopt(buff,opts))) continue;

        if (!str2opt(opt,p)) {
            fprintf(stderr,"invalid option value %s (%s:%d)\n",buff,file,n);
            continue;
        }
    }
    fclose(fp);

    return 1;
}
#endif

/**
 * @return: ok:0, error:-1
 */
static int load_mntpt()
{
	FILE *fp;
	char buf[1024] = {0};
	int i;
	char *p = NULL, *saveptr = NULL;

	if(!(fp=fopen(MNTPTFILE, "r"))) {
		fprintf(stderr, "%s, fopen error: %s\n", __func__, strerror(errno));
		return -1;
	}

	for(i=0; i<MAXMPNUM && fgets(buf, sizeof(buf), fp); i++) { 
		chop(buf);
		if((p = strtok_r(buf, ":", &saveptr)) == NULL) {
			i--;
			continue;
		}
		strncpy(caster.mntpt[i].name, p, sizeof(caster.mntpt[i].name));
		
		if((p = strtok_r(NULL, ":", &saveptr)) == NULL) {
			bzero(caster.mntpt[i].name, sizeof(caster.mntpt[i].name));
			i--;
			continue;
		}
		strncpy(caster.mntpt[i].passwd, p, sizeof(caster.mntpt[i].passwd));

		if((p = strtok_r(NULL, ":", &saveptr)) != NULL) {
			caster.mntpt[i].datafmt = atoi(p);
		}
	}
	caster.mntpt_num = i;
	fclose(fp);

	return 0;
}

/**
 * @return: ok:0, error:-1
 */
static int load_cliuser()
{
	FILE *fp;
	char buf[1024] = {0};
	int i;

	if(!(fp=fopen(CLIUSERFILE, "r"))) {
		fprintf(stderr, "%s, fopen error: %s\n", __func__, strerror(errno));
		return -1;
	}

	for(i=0; i<MAXUSERNUM && fgets(buf, sizeof(buf), fp); i++) {
		chop(buf);
		if(sscanf(buf,"%[^:]:%[^:]",caster.user[i].name,caster.user[i].passwd)<=0){
			i--;
		}
	}
	caster.user_num = i;

	fclose(fp);
	return 0;
}

static int load_port()
{
	opt_t caster_opts[] = { 
		{ "port", 0, (void *) &caster.port, "" }, 

		{ "", 0, NULL, "" }
	};
	
	if (loadopts(CASTERCONFFILE, caster_opts) == 0) {
		caster.port = 2101;
	}
	
	return 0;	
}


#define	NETDEV	"eth0"
static void init_caster()
{
	bzero(&caster, sizeof(caster));
	caster.sfd = -1;
	caster.epfd = -1;
	
	load_port();
	load_mntpt();
	load_cliuser();

	init_logbuf(&caster.logbuf);

	get_local_ipaddr(NETDEV, caster.ipaddr, sizeof(caster.ipaddr));

	list_init(&caster.event);
}


/**
 * @return: 0:ok, -1:error
 */
static int add_epoll_events(int epfd, int sfd)
{
	struct epoll_event ep_event;
	
	ep_event.data.fd = sfd;
	ep_event.events = EPOLLIN || EPOLLET || EPOLLRDHUP;
	if(epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ep_event) == -1) {
		fprintf(stderr, "%s:epoll_ctl error: %s\n", __func__, strerror(errno));
		return -1;
	}

	return 0;
}


static void set_event_remove(int fd)
{
	struct list_head *list = NULL;
	struct caster_event *entry = NULL;

	for(list = caster.event.next; list != &(caster.event); list = list->next) {
		entry = list_event_entry(list);
		if(entry->connfd == fd) {
			entry->removeflag = 1;
		}
	}
}


static void new_connect()
{
	struct sockaddr saddr;
	socklen_t slen = 0;
	int connfd = -1;
	struct epoll_event ep;
	struct caster_event *pevent;


	while(1) {
		slen = sizeof(saddr);
		bzero(&saddr, slen);
#ifdef __X86
		connfd = accept4(caster.sfd, &saddr, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if(connfd == -1) {
			break;
		}
#else 
		if((connfd = accept(caster.sfd, &saddr, &slen)) == -1) {
			break;
		}
		make_socket_non_blocking(connfd);
#endif
		
		if(add_epoll_events(caster.epfd, connfd) == 0){
			pevent = init_event_data();
			if(pevent) {
				pevent->connfd = connfd;

				if(getnameinfo(&saddr, slen, pevent->hostbuf, sizeof(pevent->hostbuf), \
					pevent->svrbuf, sizeof(pevent->svrbuf),  NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
					caster_log("Accepted connection on descriptor %d (host=%s, port=%s)", \
						connfd, pevent->hostbuf, pevent->svrbuf);
				}

				list_add_tail(&caster.event, &pevent->list);
			} else {
				close(connfd);
			}
		} else {
			close(connfd);
		}
	}
}

static void msg_to_sendqueue(struct caster_event *entry, const char *buf, int len)
{
	if(entry->send_queue_cnt < DATABUF_NUM) {
		bcopy(buf, entry->send_queue[entry->send_queue_cnt], len);
		entry->send_queue_len[entry->send_queue_cnt] = len;
		entry->send_queue_cnt++;
	}
}

static void gen_srctbl(struct caster_event *entry)
{
	char ST[4096] = {0};
	char msg[4096] = {0};
	int idx = 0;
	char date[1024] = {0};

	for(idx = 0; idx < caster.mntpt_num; idx++){
		strcat(ST, "STR;");
		strcat(ST, caster.mntpt[idx].name);
		strcat(ST, ";OpenRTK");
		strcat(ST, ";;");
		strcat(ST, ";0;0;Unknown;none;B;N;9600;\r\n");
	}

	if(entry->version == NTRIP_V1){
		snprintf(msg, sizeof(msg), "SOURCETABLE 200 OK\r\n"
								"Server: NTRIP ExampleCaster 2.0/1.0\r\n"
								"Connection: close\r\n"
								"Content-Type: text/plain\r\n"
								"Content-Length: %u\r\n"
								"\r\n"
								"%s"
								"ENDSOURCETABLE\r\n", strlen(ST), ST);
	}
	else if(entry->version == NTRIP_V2){
		snprintf(msg, sizeof(msg), "HTTP/1.1 200 OK\r\n"
								"NTRIP-Version: Ntrip/2.0\r\n"
								"Ntrip-Flags: st_filter, st_auth, st_match, st_strict, rtsp\r\n"
								"Server: NTIRP ExampleCaster/2.0\r\n"
								"Date: %s\r\n"
								"Connection: close\r\n"
								"Content-Type: gnss/sourcetable\r\n"
								"Content-Length: %u\r\n"
								"\r\n"
								"%s", caster_get_time(date),strlen(ST), ST); 
	}
	
	msg_to_sendqueue(entry, msg, strlen(msg));
}



#define GET             "GET "
#define VERSION         "Ntrip-Version: "
#define AUTHORIZATION   "Authorization: Basic "
#define SOURCE          "SOURCE "
#define POST            "POST "

/**
 * process ntrip client protocol first line
 *	1. set connection level ntrip client
 *	2. get mount point
 * @return: 0:ok, -1:do not find mount point
 */
static int ntripcli_getmp(struct caster_event *entry, char *line)
{
	char *p = NULL, *q = NULL;
	int i;

	entry->conn_level = NTRIPCLI;

	p = line + strlen(GET);
	q = strstr(p, " ");
	if(q) {
		*q = '\0';
	}
	p++;
	for(i = 0; i < caster.mntpt_num; i++) {
		if(!strcmp(p, caster.mntpt[i].name)) {
			strncpy(entry->mntpt, p, sizeof(entry->mntpt));
			
			connsvr_cli_connects_add(entry->mntpt);
			return 0;
		}
	}

	bzero(entry->mntpt, sizeof(entry->mntpt));
	return -1;
}

static int ntripcli_authorization(struct caster_event *entry, char *decode_str)
{
	char *p = NULL;
	char passwd[256] = {0};
	char username[256] = {0};
	char *saveptr = NULL;
	int idx;

	p = strtok_r(decode_str, ":", &saveptr);
	if(!p) {
		return -1;
	}
	strncpy(username, p, sizeof(username));
	p = strtok_r(NULL, ":", &saveptr);
	if(!p) {
		return -1;
	}
	strncpy(passwd, p, sizeof(passwd));

	for(idx = 0; idx < caster.user_num; idx++){
		if(strcmp(caster.user[idx].name, username) == 0){
			if(strcmp(caster.user[idx].passwd, passwd) == 0){
				entry->islogin = 1;
				return 0;
			}
		}
	}
	return -1;
}

static int ntripsvr_v2_authorization(struct caster_event *entry, char *decode_str)
{
	int idx = 0;

	for(idx = 0; idx < caster.mntpt_num; idx++) {
		if(!strcmp(caster.mntpt[idx].name, entry->mntpt)) {
			if(!strcmp(caster.mntpt[idx].passwd, decode_str)) {
				entry->islogin = 1;
				return 0;
			}
		}
	}
	return -1;
}

/**
 * @return: 0:ok, -1:authorization failed
 */
static int authorization(struct caster_event *entry, char *line)
{
	char *p = NULL;
	char decode_str[1024] = {0};
	
	p = line + strlen(AUTHORIZATION);
	base64_decode(p, decode_str);

	if(entry->conn_level == NTRIPCLI) {
		return ntripcli_authorization(entry, decode_str);
	} else if(entry->conn_level == NTRIPSVR) {
		return ntripsvr_v2_authorization(entry, decode_str);
	}

	return -1;
}

/**
 * @return: 0:ok, -1:not findn mount point or authorizetion failed
 */
static int ntripsvr_v1_getmp_authorized(struct caster_event *entry, char *line)
{
	char *p = NULL;
	char *saveptr = NULL;
	char passwd[256] = {0};
	int idx = 0;

	entry->conn_level = NTRIPSVR;

	p = line + strlen(SOURCE);
	p = strtok_r(p, " ", &saveptr);
	if(!p) {
		return -1;
	}
	strncpy(passwd, p, sizeof(passwd));
	p = strtok_r(NULL, " ", &saveptr);
	if(!p) {
		return -1;
	}
	
	if(*p == '/') {
	    ++p;	
	}
	strncpy(entry->mntpt, p, sizeof(entry->mntpt));

	for(idx = 0; idx < caster.mntpt_num; idx++) {
		if(!strcmp(caster.mntpt[idx].name, entry->mntpt)) {
			if(!strcmp(caster.mntpt[idx].passwd, passwd)) {
				entry->islogin = 1;

				return 0;
			}
		}
	}
	bzero(entry->mntpt, sizeof(entry->mntpt));
	return -1;
}

/**
 * @retrun: 0:ok, -1:not find mount point
 */
static int ntripsvr_v2_getmp(struct caster_event *entry, char *line)
{
	char *p = NULL, *q = NULL;
	char *saveptr = NULL;
	int i = 0;

	entry->conn_level = NTRIPSVR;

	p = line + strlen(POST);
	q = strstr(p, " ");
	if(q) {
		*q = '\0';
	}

	for(i = 0; i < caster.mntpt_num; i++) {
		if(!strcmp(p+1, caster.mntpt[i].name)) {
			strncpy(entry->mntpt, p, sizeof(entry->mntpt));
			return 0;
		}
	}
	bzero(entry->mntpt, sizeof(entry->mntpt));
	return -1;
}

static void set_ntrip_version(struct caster_event *entry, char *line)
{
	if(strstr(line, "2.0")) {
		entry->version = NTRIP_V2;
	}
}

static void resolve_protocol(struct caster_event *entry, char *buf, int len)
{
	char *p;
	char *saveptr;

	p = strtok_r(buf, "\r\n", &saveptr);
	do {
		if(!strncmp(p, GET, strlen(GET))) {
			ntripcli_getmp(entry, p);
		} 
		else if(!strncmp(p, SOURCE, strlen(SOURCE))) {
			ntripsvr_v1_getmp_authorized(entry, p);
		} 
		else if(!strncmp(p, POST, strlen(POST))) {
			ntripsvr_v2_getmp(entry, p);
		}
		else if(!strncmp(p, VERSION, strlen(VERSION))) {
			set_ntrip_version(entry, p);
		}
		else if(!strncmp(p, AUTHORIZATION, strlen(AUTHORIZATION))) {
			authorization(entry, p);
		} 
	
		p = strtok_r(NULL, "\r\n", &saveptr);
	} while(p);

}

static void ntripcli_resp(struct caster_event *entry)
{
	char msg[1024] = {0};
	char date[1024] = {0};

	if(entry->mntpt[0] == '\0') {
		gen_srctbl(entry);

		entry->removeflag = 1;
		return ;
	}

	if(entry->islogin == 0) {
		if(entry->version == NTRIP_V1) {
			snprintf(msg, sizeof(msg), "401 Unauthorized\r\n");
		} else {
			snprintf(msg, sizeof(msg), "HTTP/1.1 401 Unathorized\r\n"
									"Ntrip-Version: Ntrip/2.0\r\n"
									"Server: Ntrip ExampleCaster/2.0\r\n"
									"Date: %s\r\n"
									"Content-Type: text/html\r\n"
									"Connection: close\r\n"
									"\r\n", caster_get_time(date));
		}
		entry->removeflag = 1;
	}
	else {
		if(entry->version ==  NTRIP_V1) {
			snprintf(msg, sizeof(msg), "ICY 200 OK\r\n");
		} else {
			snprintf(msg, sizeof(msg), "HTTP/1.1 200 OK\r\n"
									"Ntrip-Version: Ntrip/2.0\r\n"
									"Server: NTRIP ExampleCaster/2.0\r\n"
									"Date: %s\r\n"
									"Cache-Control: no-store, no-cache, max-age=0\r\n"
									"Pragma: no-cache\r\n"
									"Connection: close\r\n"
									"Content-Type: gnss/data\r\n"
									"\r\n", caster_get_time(date));
		}
		add_conncli_info(entry->mntpt, entry->connfd);
	}
	msg_to_sendqueue(entry, msg, strlen(msg));
}


static void del_same_mntpt_svr(struct caster_event *entry)
{
	struct list_head *list;
	struct caster_event *tmp_entry;

	for(list = caster.event.next; list != &caster.event; list = list->next) {
		tmp_entry = list_event_entry(list);
		if(tmp_entry != entry && tmp_entry->conn_level == NTRIPSVR && 
				!strcmp(tmp_entry->mntpt, entry->mntpt)) {
			set_event_remove(tmp_entry->connfd);
		}
	}
}


static void ntripsvr_resp(struct caster_event *entry)
{
	char msg[1024] = {0};
	char date[1024] = {0};
	
	if(entry->mntpt[0] == '\0') {
		if(entry->version == NTRIP_V1) {
			snprintf(msg, sizeof(msg), "ERROR - Invalid MountPoint\r\n");
		} else {
			snprintf(msg, sizeof(msg), "HTTP/1.1 404 Not Found\r\n"
									"Ntrip-Version: Ntrip/2.0\r\n"
									"Server: Ntrip ExampleCaster/2.0\r\n"
									"Date: %s\r\n"
									"Content-Type: text/html\r\n"
									"Connection: close\r\n"
									"\r\n", caster_get_time(date));
		}
		entry->removeflag = 1;
	}
	else if(entry->islogin == 0) {
		if(entry->version == NTRIP_V1) {
			snprintf(msg, sizeof(msg), "ERROR - Bad Password\r\n");
		} else {
			snprintf(msg, sizeof(msg), "HTTP/1.1 401 Unathorized\r\n"
									"Ntrip-Version: Ntrip/2.0\r\n"
									"Server: Ntrip ExampleCaster/2.0\r\n"
									"Date: %s\r\n"
									"Content-Type: text/html\r\n"
									"Connection: close\r\n"
									"\r\n", caster_get_time(date));
		}
		entry->removeflag = 1;		
	}
	else { /* everthing ok */
		if(entry->version == NTRIP_V1) {
			snprintf(msg, sizeof(msg), "ICY 200 OK\r\n");
		} else {
			snprintf(msg, sizeof(msg), "HTTP/1.1 200 OK\r\n"
									"Ntrip-Version: Ntrip/2.0\r\n"
									"Server: NTRIP ExampleCaster/2.0\r\n"
									"Date: %s\r\n"
									"Connection: close\r\n"
									"\r\n", caster_get_time(date));
		}
		del_same_mntpt_svr(entry);
		add_connsvr_info(entry->mntpt);
	}
	msg_to_sendqueue(entry, msg, strlen(msg));
}

static void send_response(struct caster_event *entry)
{
	if(entry->conn_level == NTRIPSVR) {
		ntripsvr_resp(entry);
	} else { 
		ntripcli_resp(entry);
	}
}


/**
 * @return: ok:0, error:-1
 */
static int recv_msg(int fd)
{
	struct caster_event *entry = NULL;
	char buf[CASTERBUF_LEN] = {0};
	int cnt;

	entry = find_event(&caster.event, fd);
	if(entry == NULL)
		return -1;

	while(1) {
		/* make sure read the complete data */
		bzero(buf, sizeof(buf));
		cnt = read(fd, buf, sizeof(buf));
		if(cnt == -1) {
			/* EAGAIN or EWOULDBLOCK means have no more data that can be read.
			 * Everthing else is a real error. */
			if( !(errno == EAGAIN || errno ==  EWOULDBLOCK) ) {
				return -1;
			}
			return 0;
		} else if(cnt == 0) {
			/* The socket peer has closed the connection */
			return -1;
		} else {		
			if(entry->conn_level == NTRIPSVR) {
				update_connsvr_in_amount(entry->mntpt, cnt);
				if(entry->indata_cnt <= DATABUF_NUM) {
					bcopy(buf, entry->indata[entry->indata_cnt], cnt);
					entry->indata_len[entry->indata_cnt] = cnt;
					entry->indata_cnt++;
				}
			} else if(entry->conn_level == NTRIPNONE) {
				resolve_protocol(entry, buf, cnt);
				send_response(entry);
			}
		}
	}

	return 0;
}

static void indata_to_sendqueue(struct caster_event *svr_event)
{
	struct caster_event *entry = NULL;
	int idx;
	struct list_head *list = NULL;

	for(list = caster.event.next; list != &caster.event; list = list->next) {
		entry = list_event_entry(list);
		if(entry->conn_level == NTRIPCLI && 
				!strcmp(entry->mntpt, svr_event->mntpt)) {
			for(idx = 0; idx < svr_event->indata_cnt; idx++) {
				bcopy(svr_event->indata[idx], entry->send_queue[idx], CASTERBUF_LEN);
				entry->send_queue_len[idx] = svr_event->indata_len[idx];
			}
			entry->send_queue_cnt = idx;
		}
	}
}

static void send_data()
{
	struct caster_event *entry = NULL;
	struct list_head *list = NULL;
	int idx;
	int cnt;
	char *p;

	for(list = caster.event.next; list != &caster.event; list = list->next) {
		entry = list_event_entry(list);

		for(idx = 0; idx < entry->send_queue_cnt; idx++) {
			p = entry->send_queue[idx];
			while(entry->send_queue_len[idx] > 0) {
				cnt = write(entry->connfd, p, entry->send_queue_len[idx]);
				if(cnt <= 0){
	    			if(errno == EINTR){
	    				continue;
	    			}else if(errno == EAGAIN){
	    				break;
	    			}else{
	    				break;
	    			}
	    		}
				if(entry->conn_level == NTRIPCLI) {
					update_connsvr_out_amount(entry->mntpt, cnt);
					update_conncli_out_amount(entry->connfd, cnt);
				}

				entry->send_queue_len[idx] -= cnt;
				p += cnt;
			}
		}
	}
	
}

static void reset_event_buf()
{
	struct caster_event *entry = NULL;
	struct list_head *list = NULL;;

	for(list = caster.event.next; list != &caster.event; list = list->next) {
		entry = list_event_entry(list);
		bzero(entry->indata, sizeof(entry->indata));
		bzero(entry->indata_len, sizeof(entry->indata_len));
		entry->indata_cnt = 0;

		bzero(entry->send_queue, sizeof(entry->send_queue));
		bzero(entry->send_queue_len, sizeof(entry->send_queue_len));
		entry->send_queue_cnt = 0;
	}
}

static void release_source()
{
	struct caster_event *entry = NULL;
	struct list_head *list = NULL;
	int idx;

	for(list = caster.event.next; list != &caster.event; ) {
		entry = list_event_entry(list);
		list = list->next;	/* after free entry, list can not access */
		if(entry->removeflag == 1) {
			close(entry->connfd);
			if(entry->conn_level ==  NTRIPSVR) {
				del_connsvr_info(entry->mntpt);
				
				caster_log("Disconnect ntrip server on descriptor %d (host=%s, port=%s)",
						entry->connfd, entry->hostbuf, entry->svrbuf);
			} else if(entry->conn_level == NTRIPCLI) {
				del_conncli_info(entry->connfd);
				connsvr_cli_connects_del(entry->mntpt);

				caster_log("Disconnect ntrip client on descriptor %d (host=%s, port=%s)",
						entry->connfd, entry->hostbuf, entry->svrbuf);
			}

			del_and_free_event(entry);
		}
	}
}


/**
 * listen fd, process new connect and receive message
 */
void start_server()
{
	int n, i;
	struct epoll_event ep, cur_ep;
	struct epoll_event *ep_events;
	struct sockaddr in_addr;
	socklen_t in_len = 0;
	int connfd = -1;
	struct caster_event *entry = NULL;

	ep_events = (struct epoll_event *)calloc(MAXEPEVENTS, sizeof(ep));

	while(caster.state == 1) {
		n = epoll_wait(caster.epfd, ep_events, MAXEPEVENTS, -1);
		for(i=0; i<n; i++) {
			cur_ep = ep_events[i];
			if(!(cur_ep.events & EPOLLIN)) {
				fprintf(stderr, "epoll_wait error on fd:%d\n", cur_ep.data.fd);
				set_event_remove(cur_ep.data.fd);
				
			} else if(cur_ep.data.fd == caster.sfd) {
				/* An event on the listening socket, process new connection */
				new_connect();
		    } else {
				/* process message */
				if(recv_msg(cur_ep.data.fd) == -1) {
					/* error, close this connection and release source */
					set_event_remove(cur_ep.data.fd);
				}
				entry = find_event(&caster.event, cur_ep.data.fd);
				if(entry && entry->conn_level == NTRIPSVR) {
					indata_to_sendqueue(entry);
				}
			}
			if(cur_ep.events & EPOLLRDHUP) {
				set_event_remove(cur_ep.data.fd);
			}
		}

		send_data();
		reset_event_buf();

		release_source();
	} /* end of while(caster.state == 1) */
}



/**
 * @port: listen port
 * @return: ok:0, error:-1
 */
//static void *caster_thread(void *arg)
int main()
{
	char port_buf[64] = {0};
	
    init_caster();

	sprintf(port_buf, "%d", caster.port);
    caster.sfd = create_and_bind(port_buf);
    if(caster.sfd == -1) {
        fprintf(stderr, "%s:gen_tcp error\n", __func__);
        //return (void *)-1;
        return -1;
    }
    if(make_socket_non_blocking(caster.sfd) == -1) {
        //return (void *)-1;
        return -1;
    }
	if(listen(caster.sfd, 5) == -1) {
		fprintf(stderr, "%s:listen error:%s\n", __func__, strerror(errno));
		//return (void *)-1;
        return -1;
	}

	caster.epfd = epoll_create1(0);
	if(caster.epfd == -1) {
	 	//return (void *)-1;
        return -1;
	}
	add_epoll_events(caster.epfd, caster.sfd);

    caster.state = 1; /* running */

    start_server();

	//return (void *)0;
    return 0;
}

#if 0
int start_caster()
{
	pthread_t caster_tid;

	if(pthread_create(&caster_tid, NULL, caster_thread, NULL) != 0) {
		return -1;
	}
	pthread_detach(caster_tid);

	return 0;
}
#endif

#if 0

/***************web page interface *************************/
int get_caster_base_info(struct caster_base_info *baseInfo)
{
	strncpy(baseInfo->caster_ip, caster.ipaddr, sizeof(baseInfo->caster_ip));
	snprintf(baseInfo->caster_port, sizeof(baseInfo->caster_port), "%d", caster.port);
	baseInfo->state = caster.state;

	return 0;
}

/**
 * @return: the logstr string length
 */
int show_caster_log(char *logstr, int len)
{
	char *p = logstr;
	char *end = logstr + len;

	while(caster.logbuf.read <= caster.logbuf.write) {
		if((size_t)(end-p) < strlen(caster.logbuf.buf[(caster.logbuf.read & (LOGBUFNUM-1))])) {
			break;
		}
		p += snprintf(p, end-p, "%s", caster.logbuf.buf[caster.logbuf.read++]);		
	}

	if(caster.logbuf.read > caster.logbuf.write) {
		/* All logs have been read */
		init_logbuf(&caster.logbuf);
	}

	return (p-logstr);
}

/**
 * @return: the srctbl string length
 */
int get_caster_srctbl(char *srctbl, int len)
{
	int i; 
	char *p, *end;

	p = srctbl;
	end = p + len;
	for(i = 0; i < caster.mntpt_num; i++) {
		p += snprintf(p, (size_t)(end-p), "%s\n", caster.mntpt[i].name);
	}
	return strlen(srctbl);
}

/**
 * @return: the number of connected servers
 */
int get_caster_connect_svr_info(struct caster_connect_svr_info* svr_info, int size)
{
	int i; 

	for(i = 0; i < size && i < caster.connsvr_len; i++) {
		svr_info[i] = caster.connsvr[i];
	}
	return i;
}

int get_caster_connect_cli_info(struct caster_connect_cli_info *cli_info, int size)
{
	int i; 

	for(i = 0; i < size && i < caster.conncli_len; i++) {
		cli_info[i] = caster.conncli[i];
	}
	return i;	
}

/**
 * @return: The number of caster client users
 */
int get_caster_cliuser(struct cliuser *users, int size)
{
	int i;

	for(i = 0; i < size && i <caster.user_num; i++) {
		users[i] = caster.user[i];
	}

	return i;
}

int add_caster_cliuser(struct cliuser *user)
{
	int i;
	
	if(!user || caster.user_num >= MAXUSERNUM) {
		return -1;
	}

	for(i = 0; i < caster.user_num; i++) {
		if(!strcmp(caster.user[i].name, user->name)) {
			fprintf(stderr, "user <%s> is already exsit.\n", user->name);
			return -1;
		}
	}

	caster.user[caster.user_num++] = *user;

	update_caster_userfile();

	return 0;
}

int edit_caster_cliuser_passwd(struct cliuser *user)
{
	int i;
	
	if(!user) 
		return -1;

	for(i = 0; i < caster.user_num; i++) {
		if(!strcmp(caster.user[i].name, user->name)) {
			caster.user[i] = *user;

			update_caster_userfile();
			
			return 0;
		}
	}
	return -1;
}

int del_caster_cliuser(char *username)
{
	int i, j; 
	
	if(!username)
		return -1;

	for(i = 0; i < caster.user_num; i++) {
		if(!strcmp(caster.user[i].name, username)) {
			for(j = i; j < caster.user_num -1; j++) {
				caster.user[j] = caster.user[j+1];
			}
			bzero(&caster.user[j], sizeof(caster.user[0]));
			caster.user_num--;

			update_caster_userfile();

			return 0;
		}
	}

	return -1;
}

/**
 * @return: The number  of caster mount point
 */
int get_caster_mntpt(struct mountpoint *mntpts, int size) 
{
	int i;

	if(!mntpts)
		return -1;

	for(i = 0; i < size && i < caster.mntpt_num; i++) {
		mntpts[i] = caster.mntpt[i];
	}

	return i;
}

int add_caster_mntpt(struct mountpoint *mntpt)
{
	int i;
	
	if(!mntpt || caster.mntpt_num >= MAXMPNUM) {
		return -1;
	}

	for(i = 0; i < caster.mntpt_num; i++) {
		if(!strcmp(caster.mntpt[i].name, mntpt->name)) {
			fprintf(stderr, "mntpt <%s> is already exsit.\n", mntpt->name);
			return -1;
		}
	}

	caster.mntpt[caster.mntpt_num++] = *mntpt;

	update_caster_mntptfile();

	return 0;

}

int edit_caster_mntpt(struct mountpoint *mntpt)
{
	int i;
	
	if(!mntpt) 
		return -1;

	for(i = 0; i < caster.mntpt_num; i++) {
		if(!strcmp(caster.mntpt[i].name, mntpt->name)) {
			caster.mntpt[i] = *mntpt;

			update_caster_mntptfile();
			
			return 0;
		}
	}
	return -1;
}

int del_caster_mntpt(char *mp_name)
{
	int i, j; 
	
	if(!mp_name)
		return -1;

	for(i = 0; i < caster.mntpt_num; i++) {
		if(!strcmp(caster.mntpt[i].name, mp_name)) {
			for(j = i; j < caster.mntpt_num -1; j++) {
				caster.mntpt[j] = caster.mntpt[j+1];
			}
			bzero(&caster.mntpt[j], sizeof(caster.mntpt[0]));
			caster.mntpt_num--;

			update_caster_mntptfile();

			return 0;
		}
	}
	return -1;
}


/********************* stm32 interface ***************************/

int set_caster_ip(char *ipaddr)
{
	if(!ipaddr)
		return -1;

	strncpy(caster.ipaddr, ipaddr, sizeof(caster.ipaddr));

	return 0;
}

#endif
