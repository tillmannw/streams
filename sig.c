// sig.c -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#include <stdio.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>

#include "hash.h"
#include "strm.h"

void sh_general(int s) {
	int i;
	hash_entry_t *he, *next;

	switch (s) {
	case SIGINT:
		if (slist) {
			for (i = 0; i < stream_total_count; ++i) {
				free(slist[i]->data);
				free(slist[i]);
			}

			free(slist);
		}

		for (i=0; i<0x10000; ++i) {
			he = hashmap[i];
			while (he) {
				next = he->next;
				free(he);
				he = next;
			}
		}

		exit(EXIT_SUCCESS);
	case SIGCHLD:
		printf("--> sigchild\n");
		break;
	default:
		break;
	}

	return;
}
