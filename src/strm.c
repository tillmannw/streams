/*
  strm.c
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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>

#include "hash.h"
#include "streams.h"
#include "strm.h"
#include "util.h"

#define max(a, b) (a) > (b) ? (a) : (b)


// Note that TCP stream reassembly is quite an expensive task. To quote the Wireshark Wiki: "Warning : memory is consumed like there is no tomorrow"


void strm_assemble(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	int dl_offset = *(int *) user;
	struct iphdr *ip;
	struct tcphdr *tcp;
	hash_entry_t *he;
	stream *strm;
	u_int32_t plen;
	u_char *payload;
	int embd_offset = 0;

	if (!h || !bytes) return;

	if (global_start.tv_sec == 0 && global_start.tv_usec == 0)
		global_start = h->ts;

	if (h->len < dl_offset + sizeof(struct iphdr)) return;

	if (dl_offset == 14 && ((u_short *)bytes)[6] == 0x6488) embd_offset = 8;

	ip = (struct iphdr *) (bytes + dl_offset + embd_offset);

	// ignore non-TCP packets for now
	if (ip->protocol != 6) return;

	if (h->len < dl_offset + embd_offset + (4 * ip->ihl) + sizeof(struct tcphdr)) return;
	tcp = (struct tcphdr *) (bytes + dl_offset + embd_offset + (4 * ip->ihl));

	payload = (u_char *) (bytes + dl_offset + embd_offset + (4 * (ip->ihl + tcp->doff)));
	plen = ntohs(ip->tot_len) - (4 * (ip->ihl + tcp->doff));

/*
char s[16], d[16];
printf("%s:%d > %s:%d %c%c%c%c %u (%d bytes)\n", inet_ntop(AF_INET, &ip->saddr, s, 16), ntohs(tcp->source), inet_ntop(AF_INET, &ip->daddr, d, 16), ntohs(tcp->dest),
	tcp->fin ? 'F' : '.', tcp->syn ? 'S' : '.', tcp->rst ? 'R' : '.', tcp->ack ? 'A' : '.', ntohl(tcp->seq), plen);
*/

	// search for a stream this segment may belong to
	he = hash_lookup(ip->saddr, tcp->source, ip->daddr, tcp->dest, 0);

	if (he != NULL) {
		// tcp session timeout exceeded?
		strm = he->data;
		if (h->ts.tv_sec - strm->end.tv_sec > tcp_timeout) {
			// stream timed out, remove it from hash table
			if ((he = hash_lookup(ip->saddr, tcp->source, ip->daddr, tcp->dest, 1)) == NULL) {
				fprintf(stderr, "Error while processing timed out stream.\n");
				exit(EXIT_FAILURE);
			}

			// if a match expression is defined: check if stream matches
			strm->match = 1;
			if (matchexpr && memmem(strm->data, strm->len, matchexpr, strlen(matchexpr)) == NULL)
				strm->match = 0;

			// hashmap entry has already been removed from the map, now free it
			free(he);
			he = NULL;
		}
	}

	if (tcp->syn) {
		if (he == NULL) {
			// new stream, insert it into the hash table
			if (((strm = calloc(1, sizeof(stream))) == NULL) ||
			    ((strm->data = malloc(plen)) == NULL)) {
				perror("malloc()");
				exit(EXIT_FAILURE);
			}
			if ((he = hash_add(ip->saddr, tcp->source, ip->daddr, tcp->dest, strm)) == NULL) {
				fprintf(stderr, "Cannot add hashmap entry: key already exists.\n");
				exit(EXIT_FAILURE);
			}
			strm = he->data;
			strm->number = stream_total_count;
			strm->isn = ntohl(tcp->seq);
			strm->relisn = ntohl(tcp->seq);
			strm->s.addr = ip->saddr;
			strm->s.port = tcp->source;
			strm->d.addr = ip->daddr;
			strm->d.port = tcp->dest;
			strm->start = h->ts;
			strm->match = matchexpr ? 0 : 1;

			pstats[ntohs(tcp->dest)].count++;

			// add stream to chronological list
			if ((slist = realloc(slist, (stream_total_count + 1) * sizeof(stream *))) == NULL) {
				perror("realloc()");
				exit(EXIT_FAILURE);
			}
			slist[stream_total_count] = strm;

			stream_total_count++;
		} else strm = he->data;

		strm->end = h->ts;

		// data on syn? then add it to the stream (allowed per RFC, but should not really happen in practice)
		if (plen) {
			memmove(strm->data, payload, plen);
			strm->len += plen;
		}
	} else {
		// if a stream exists, add payload
		if (he != NULL) {
			strm = he->data;
			strm->end = h->ts;

			// check if sequence number wrapped around and is in a valid range
			if (strm->isn == strm->relisn && strm->isn > ntohl(tcp->seq)) {
				// sanity check, drop stream if wrapped segment is more than one megabyte into the stream
				if (ntohl(tcp->seq) - strm->isn > 1024 * 1024) {
					char s[16], d[16];
					printf("Error: cannot handle packet with wrapped sequence number %d for stream: %s:%d > %s:%d %c%c%c%c %u (ISN was %u)\n",
						ntohl(tcp->seq),
						inet_ntop(AF_INET, &ip->saddr, s, 16), ntohs(tcp->source),
						inet_ntop(AF_INET, &ip->daddr, d, 16), ntohs(tcp->dest),
						tcp->fin ? 'F' : '.', tcp->syn ? 'S' : '.', tcp->rst ? 'R' : '.', tcp->ack ? 'A' : '.',
						ntohl(tcp->seq), strm->isn);
					exit(EXIT_FAILURE);
				}
			}

			// basic overwrite style stream reassembly
			if (strm && plen) {
				// FIXME: bad things happen if a duplicate ISN segments with data arrives
				if (strm->len < (ntohl(tcp->seq) - strm->isn + plen)) {
					// need more space
					if ((strm->data = realloc(strm->data, (u_int32_t) (ntohl(tcp->seq) - strm->isn + plen))) == NULL) {
						perror("realloc()");
						exit(EXIT_FAILURE);
					}
				}
				memmove(strm->data + (ntohl(tcp->seq) - strm->isn) - 1, payload, plen);
				strm->len = max(strm->len, ntohl(tcp->seq) - strm->isn + plen - 1);
			}

			// if segment has the FIN or RST flag set, terminate the stream
			if (tcp->fin || tcp->rst) {
				if ((he = hash_lookup(ip->saddr, tcp->source, ip->daddr, tcp->dest, 1)) != NULL) {
					// stream terminated, mark it as complete
					strm = he->data;
					strm->end = h->ts;

					if (strm->len) {
						// non-empty stream
						stream_complete_count++;
						strm->complete = 1;
					}

					// if a match expression is defined: check if stream matches
					strm->match = 1;
					if (matchexpr && memmem(strm->data, strm->len, matchexpr, strlen(matchexpr)) == NULL)
						strm->match = 0;
				}
			}
		}
	}

	return;
}


int strm_list(int number) {
	stream *s;
	int i;
	char saddr[16], daddr[16], start[20], end[20];
	struct timeval sdiff, ediff;

	for (i = 0; i < stream_total_count; ++i) {
		if (number >= 0 && i != number) continue;

		s = slist[i];
		if (s->match == 0) continue;
		if (number == -1 && filter_streams && (s->complete == 0 || s->len == 0)) continue;

		inet_ntop(AF_INET, &s->s.addr, saddr, sizeof(struct sockaddr_in));
		inet_ntop(AF_INET, &s->d.addr, daddr, sizeof(struct sockaddr_in));
		if (relative_timestamps) {
			sdiff = timediff(global_start, s->start);
			ediff = timediff(global_start, s->end);

			printf("%5d:  %6d.%06d  %6d.%06d  %s:%d > %s:%d (%lu bytes)%s\n",
				s->number,
				(unsigned int) sdiff.tv_sec, (unsigned int) sdiff.tv_usec, (unsigned int) ediff.tv_sec, (unsigned int) ediff.tv_usec,
				saddr, ntohs(s->s.port), daddr, ntohs(s->d.port), (long unsigned int) s->len,
				s->complete ? "" : " [empty/incomplete]");
		} else {
			strftime(start, 20, "%Y-%m-%d %H:%M:%S", gmtime((time_t *) &s->start.tv_sec));
			strftime(end, 20, "%Y-%m-%d %H:%M:%S", gmtime((time_t *) &s->end.tv_sec));
			printf("%5d:  %s.%06u  %s.%06u  %s:%d > %s:%d (%lu bytes)%s\n",
				s->number,
				start, (unsigned int) s->start.tv_usec, end, (unsigned int) s->end.tv_usec,
				saddr, ntohs(s->s.port), daddr, ntohs(s->d.port), (long unsigned int) s->len,
				s->complete ? "" : " [empty/incomplete]");
		}
		if (number >= 0 && i == number) break;
	}
	return 0;
}


int portcmp(const void *a, const void *b) {
	portstat *pa = (portstat *) a;
	portstat *pb = (portstat *) b;

	if (pa->count > pb->count) return 1;
	if (pa->count < pb->count) return -1;
	return 0;
}
