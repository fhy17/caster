/**
 * ntripcaster.h
 */

#ifndef _NTRIPCASTER_H
#define	_NTRIPCASTER_H

#include "caster_event.h"



#define MAXMPNUM	32
#define MAXUSERNUM	32


#define MAXNTRIPSVR MAXMPNUM
#define MAXNTRIPCLI 64
#define MAXEPEVENTS (MAXNTRIPSVR+MAXNTRIPCLI+1)

#define	LOGBUFSIZE	1024
#define LOGBUFNUM	(1<4)	/* must be 2 for n power */

typedef struct {        /* option type */
    char *name;         /* option name */
    int format;         /* option format (0:int,1:double,2:string,3:enum) */
    void *var;          /* pointer to option variable */
    char *comment;      /* option comment/enum labels/unit */
} opt_t;

struct caster_log_ring_buffer {
	char buf[LOGBUFNUM][LOGBUFSIZE];
	int read;
	int write;
};


struct caster_base_info{
	char caster_ip[64];
	char caster_port[16];
	int state;  /*0:stop, 1:running */
};

struct caster_connect_svr_info {
	char mntpt[256];
	char uptime[64];
	int input;
	int output;
	int cli_connects;
};


struct caster_connect_cli_info {
	int connfd; /* identify ntrip client */
	char mntpt[256];
	char uptime[64];
	int output;
};


struct mountpoint {
	char name[128];
	char passwd[128];
	int datafmt; /* 1.RTCM2.3, 2.RTCM3.0, 3.RAW */
};

struct cliuser {
	char name[128];
	char passwd[128];
};


struct ntripcaster {
	int state; /* 0:stop, 1:running */
	
	struct mountpoint mntpt[MAXMPNUM];
	int mntpt_num;
	struct cliuser user[MAXUSERNUM];
	int user_num;
	
	char ipaddr[64];
	int port;
	int sfd; /* listen sock */
	int epfd; /* epoll fd */

	struct caster_connect_svr_info connsvr[MAXNTRIPSVR];
	int connsvr_len;

	struct caster_connect_cli_info conncli[MAXNTRIPCLI];
	int conncli_len;

	struct caster_log_ring_buffer logbuf;

	
	/* caster event list head */
	struct list_head event;
};

extern int start_caster();

/********************* web page interface ***************************/

extern int get_caster_base_info(struct caster_base_info *baseInfo);

/**
 * @return: the logstr string length
 */
extern int show_caster_log(char *logstr, int len);

/**
 * @return: the srctbl string length
 */
extern int get_caster_srctbl(char *srctbl, int len);

/**
 * @return: the number of connected servers
 */
extern int get_caster_connect_svr_info(struct caster_connect_svr_info *svr_info, int size);

/**
 * @return: client user number
 */
extern int get_caster_cliuser(struct cliuser *users, int size);

/**
 * @return: The number of caster client users
 */
extern int add_caster_cliuser(struct cliuser *user);
extern int edit_caster_cliuser_passwd(struct cliuser *user);
extern int del_caster_cliuser(char *username);

/**
 * @return: The number  of caster mount point
 */
extern int get_caster_mntpt(struct mountpoint *mntpts, int size) ;

extern int add_caster_mntpt(struct mountpoint *mntpt);
extern int edit_caster_mntpt(struct mountpoint *mntpt);
extern int del_caster_mntpt(char *mp_name);


/********************* stm32 interface ***************************/
extern int set_caster_ip(char *ipaddr);


#endif /* _NTRIPCASTER_H */
