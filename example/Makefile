# Makefile

OBJS	= example.o

CC	= gcc
CFLAGS	= -g -Wall -ansi -pedantic -lfirm-dkim

example:	$(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -o example

example.o:	example.c
		$(CC) $(CFLAGS) -c example.c -o example.o
		
clean:
	rm -f *.o *~ example



