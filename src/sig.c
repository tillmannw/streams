/*
  sig.c
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
