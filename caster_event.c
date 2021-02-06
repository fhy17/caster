/**
 * caster_event.c
 */

#include <stdlib.h>

#include "caster_event.h"


void list_init(struct list_head *head)
{
	head->next = head;
	head->prev = head;
}

void list_add_tail(struct list_head *head, struct list_head *entry)
{
	struct list_head *prev;

	prev = head->prev;

	prev->next = entry;
	entry->prev = prev;
	entry->next = head;
	head->prev = entry;
}

void list_del(struct list_head *entry)
{
	struct list_head *next, *prev;

	next = entry->next;
	prev = entry->prev;

	next->prev = prev;
	prev->next = next;

	entry->next = NULL;
	entry->prev = NULL;
}

struct caster_event *list_event_entry(struct list_head *list)
{
	struct caster_event *pevent = NULL;
	size_t offset = 0;

	offset = (size_t)&((struct caster_event *)0)->list;
	pevent = (struct caster_event *)((char *)list - offset);

	return pevent;
}


/**
 * @return: ok:return a pointer specify this struct event_data; error: NULL
 */
struct caster_event *init_event_data()
{
	struct caster_event *pevent = NULL;

	pevent = (struct caster_event *)calloc(1, sizeof(*pevent));
	if(!pevent)
		return NULL;

	pevent->connfd = -1;
	pevent->removeflag = 0;
	pevent->conn_level = NTRIPNONE;
	pevent->version = NTRIP_V1;

	list_init(&pevent->list);

	return pevent;
}


void del_and_free_event(struct caster_event *pevent)
{
	list_del(&pevent->list);
	
	free(pevent);
	pevent = NULL;
}

struct caster_event *find_event(const struct list_head *head, int fd)
{
	struct caster_event *entry;
	struct list_head *list;
	
	for(list = head->next; list != head; list = list->next) {
		entry = list_event_entry(list);
		if(entry->connfd == fd) {
			return entry;
		}
	}

	return NULL;
}

