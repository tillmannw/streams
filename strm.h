// strm.h -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#ifndef __TRACKER_H
#define __TRACKER_H

#include <netinet/in.h>
#include <pcap.h>
#include <sys/types.h>


typedef struct {
	int number;
	int complete;
	int match;
	size_t len;
	u_char *data;
	struct {
		in_addr_t addr;
		u_int16_t port;
	} s, d;
	u_int32_t isn;
	struct timeval start;
	struct timeval end;
} stream;

stream **slist;

pcap_t *pktsrc;
int stream_total_count;
int stream_complete_count;
int relative_timestamps;
int filter_streams;
struct timeval global_start;

void strm_assemble(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int strm_list(int number);

#endif
