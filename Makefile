# Makefile

OBJS	= firm-dkim.o

CC	= gcc
CFLAGS	= -g -fPIC -Wall -ansi -pedantic -lcrypto

firm-dkim:	$(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -shared -Wl,-soname,libfirm-dkim.so -o libfirm-dkim.so

firm-dkim.o:	firm-dkim.c
		$(CC) $(CFLAGS) -c firm-dkim.c -o firm-dkim.o

install:
	echo "Copying headers and lib files..."
	cp firm-dkim.h /usr/local/include/
	cp libfirm-dkim.so /usr/local/lib/
	ldconfig

