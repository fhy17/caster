
CC = gcc
CFLAGS = 
LIBS = 

Target = ntripcaster
OBJS = ntripcaster.o caster_event.o caster_utils.o


$(Target):$(OBJS)
	$(CC) -o $(Target) $(OBJS) $(CFLAGS) $(LIBS)

ntripcaster.o:ntripcaster.c ntripcaster.h caster_event.h caster_utils.h
	$(CC) -c ntripcaster.c

caster_event.o:caster_event.c caster_event.h
	$(CC) -c caster_event.c

caster_utils.o:caster_utils.c caster_utils.h
	$(CC) -c caster_utils.c

.PHONY:clean
clean:
	rm $(Target) $(OBJS) 
