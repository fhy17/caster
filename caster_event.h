/**
 * caster_event.h
 */

#ifndef	_CASTER_EVENT_H
#define _CASTER_EVENT_H

#ifdef DEBUG
#define	DBG(fmt, ...)	printf("%s,%d: "fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define	DBG(fmt, ...)	
#endif


struct list_head {
	struct list_head *next, *prev;
};

#define	NTRIPNONE	0
#define NTRIPCLI	1
#define	NTRIPSVR	2

#define	NTRIP_V1 	1
#define	NTRIP_V2	2


#define DATABUF_NUM  	50
#define	CASTERBUF_LEN	4096


struct caster_event {
    int connfd;

    int removeflag;
	
    char mntpt[256];
	int conn_level;	/* (0:none, 1:ntrip client, 2:ntrip server) */
	int version; /* 1:version1, 2:version2 */
	int islogin;
	
    char indata[DATABUF_NUM][CASTERBUF_LEN];
    int indata_len[DATABUF_NUM];
    int indata_cnt;

    char send_queue[DATABUF_NUM][CASTERBUF_LEN];
    int send_queue_len[DATABUF_NUM];
    int send_queue_cnt;

	char hostbuf[1025];
	char svrbuf[32];

	struct list_head list;
};




extern void list_init(struct list_head *head);
extern void list_add_tail(struct list_head *head, struct list_head *entry);
extern void list_del(struct list_head *entry);
extern struct caster_event *list_event_entry(struct list_head *list);

extern struct caster_event *init_event_data();
extern void del_and_free_event(struct caster_event *pevent);

extern struct caster_event *find_event(const struct list_head *head, int fd);


#endif /* _CASTER_EVENT_H */
