CFLAGS=-g -Wall -Werror -D_GNU_SOURCE
LDFLAGS=-lreadline -lpcap

all:	streams	

streams: cmd.o hash.o sig.o strm.o util.o streams.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

%o: %c
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o streams
