/*
  strm.h
  Copyright (C) 2011 Tillmann Werner, tillmann.werner@gmx.de

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as 
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
	int64_t relisn;
	struct timeval start;
	struct timeval end;
} stream;

stream **slist;

typedef struct {
	uint16_t port;
	size_t count;
} portstat;

portstat pstats[0x10000];

pcap_t *pktsrc;
int stream_total_count;
int stream_complete_count;
int relative_timestamps;
int filter_streams;
unsigned int tcp_timeout;
struct timeval global_start;

void strm_assemble(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int strm_list(int number);
int portcmp(const void *a, const void *b);

#endif
