/*
  cmd.c
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

#include <argz.h>
#include <ctype.h>
#include <pcap.h>
#include <history.h>
#include <readline.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cmd.h"
#include "hash.h"
#include "streams.h"
#include "strm.h"
#include "util.h"


int cmd_analyze(char *arg) {
	char *filename;
	struct bpf_program bpf;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	hash_entry_t *he, *next;

	if (arg) {
		// close previous tracefile
		if (pktsrc) pcap_close(pktsrc);

		// get file name
		if ((filename = strtok(strchr(arg, ' '), " ")) == NULL) {
			printf("need an argument.\n");
			return -1;
		}
		tracefile = strdup(filename);
	} else {
		// re-analyze currently selected packet source
		if (pktsrc == NULL) {
			printf("Error: cannot re-analyze, no source selected\n");
			return -1;
		}
	}

	// initialize chronological stream list
	if (slist) free(slist);
	slist = NULL;

	// initialize stream hash map
	he = NULL;
	next = NULL;
	for (i=0; i<0x10000; ++i) {
		he = hashmap[i];
		while (he) {
			next = he->next;
			if (((stream *)(he->data))->data) free(((stream *)(he->data))->data);
			free(he->data);
			free(he);
			he = next;
		}
	}
	memset(hashmap, 0, 0x10000 * sizeof(hash_entry_t *));

	// open tracefile
	if ((pktsrc = pcap_open_offline(tracefile, errbuf)) == NULL) {
		fprintf(stderr, "could not open trace file: %s\n", errbuf);
		return -1;
	}

	// activate filter for new tracefile
	if (filter) {
		if (pcap_compile(pktsrc, &bpf, filter, 1, 0) == -1) {
			fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(pktsrc));
			return -1;
		}
		if (pcap_setfilter(pktsrc, &bpf) == -1) {
			fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(pktsrc));
			return -1;
		}
		pcap_freecode(&bpf);
	}


	if (pktsrc == NULL) {
		printf("no packet source selected\n");
		return -1;
	}

	if (!offset) switch (pcap_datalink(pktsrc)) {
	case DLT_RAW: offset = 0; break;
	case DLT_PPP: offset = 2; break;
	case DLT_LOOP: offset = 14; break;
	case DLT_EN10MB: offset = 14; break;
	default:
		printf("unsupported data link type.\n");
		return -1;
	}

	stream_total_count = 0;
	stream_complete_count = 0;

	switch (pcap_loop(pktsrc, 0, strm_assemble, (u_char *) &offset)) {
	case 0:
		// count exhausted
		break;
	case -1:
	case -2:
	default:
		fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(pktsrc));
//		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "file processed, %d streams (%d non-empty and complete).\n", stream_total_count, stream_complete_count);

	return 0;
}


int cmd_count(char *arg) {
	printf("number of streams: %u (%u non-empty and complete)\n", stream_total_count, stream_complete_count);
	return 0;
};


int cmd_offset(char *arg) {
	char *o;

	if ((o = strchr(arg, ' ')) == NULL) {
		printf("offset: need an argument\n");
		return -1;
	}
	offset = strtoul(o, NULL, 0);

	// apply offset to selected packet source
	if (pktsrc) {
		printf("applying new offset...\n");
		cmd_analyze(NULL);
	}

	return 0;
}


int cmd_outfile(char *arg) {
	char *name;

	if ((name = strchr(arg, ' ')) == NULL) {
		printf("outfile: need an argument\n");
		return -1;
	}

	outfile = strdup(name + 1);

	return 0;
};


int cmd_dump(char *arg) {
	char *number;
	int n = -1;

	if (pktsrc == NULL) {
		printf("select a packet source first\n");
		return -1;
	}

	if (outfile == NULL) {
		printf("no output file specified\n");
		return -1;
	}

	if ((number = strchr(arg, ' ')) == NULL) {
		printf("dump: need an argument\n");
		return -1;
	}
	
	n = strtoul(number, NULL, 0);
	if (n > stream_total_count) {
		printf("no such stream\n");
		return -1;
	}

	FILE *f;
	if ((f = fopen(outfile, "w")) == NULL) {
		perror("fopen()");
		return -1;
	}
	size_t bytes = fwrite(slist[n]->data, 1, slist[n]->len, f);

	if (ferror(f)) {
		perror("fwrite()");
		fclose(f);
		return -1;
	}

	fclose(f);
	printf("%lu bytes written to %s\n", (long unsigned int) bytes, outfile);


	return 0;
};


int cmd_quit(char *arg) {
	// delete hash map
	int i;
	hash_entry_t *he, *next;
	he = NULL;
	next = NULL;

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

	// set done flag to stop looping
	done = 1;

	return 0;
};


int cmd_bpf(char *arg) {
	free(filter);

	if ((filter = strchr(arg, ' ')) == NULL)
		filter = strdup("tcp");
	else 
		filter = strdup(strchr(arg, ' ') + 1);

	if (strlen(filter) == 0) filter = NULL;

	// apply filter to selected packet source
	if (pktsrc) {
		printf("applying new filter...\n");
		cmd_analyze(NULL);
	}

	return 0;
};


int cmd_help(char *arg) {
	int i;

	putchar('\n');
	for (i = 0; commands[i].name; ++i)
		printf("  %s\t%s\n", commands[i].name, commands[i].desc);
	putchar('\n');

	return 0;
};


int cmd_list(char *arg) {
	char *number;
	int n = -1;

	if (pktsrc == NULL) {
		printf("select a packet source first\n");
		return -1;
	}

	if ((number = strchr(arg, ' ')) != NULL) {
		n = strtoul(number, NULL, 0);
		if (n > stream_total_count) {
			printf("no such stream\n");
			return -1;
		}
	}

	strm_list(n);

	return 0;
};


int cmd_match(char *arg) {
	char *argz, *s;
	int i;
	size_t argzlen;

	argz = NULL;
	argzlen = 0;

	// clear old match expression
	if (matchexpr) free(matchexpr);
	matchexpr = NULL;

	// create argument vector from extprog string
	s = strchr(arg, ' ');
	if (s && argz_create_sep(s, ' ', &argz, &argzlen) != 0) {
		perror("argz_create_sep()");
		return -1;
	}

	// if one argument is given, take it as the pattern, two arguments indicate a hex pattern and the first one must be an 'x'
	switch (argz_count(argz, argzlen)) { 
	case 0:
		for (i = 0; i < stream_total_count; ++i)
			slist[i]->match = 1;

		printf("match expression removed\n");
		return 0;
	case 1:
		matchexpr = strdup(s + 1);
		matchexprlen = strlen(matchexpr);
		break;
	default:
		// we have at least 2 arguments, the first one must be an 'x'
		if (strcmp(argz, "x") != 0) {
			printf("invalid arguments");
			return -1;
		}
		// get second arg
		char *entry;
		entry = argz_next(argz, argzlen, NULL);
		entry = argz_next(argz, argzlen, entry);

		// make sure len is a multiple of 2
		size_t len = (strlen(entry) >> 1) << 1;
		matchexprlen = len/2;

		if ((matchexpr = (malloc(matchexprlen))) == NULL) {
			perror("malloc()");
			return -1;
		}

		// convert hex string into binary string
		size_t i;
		for (i = 0; i < matchexprlen; i ++)
			if (sscanf(entry + (2 * i), "%02x", (unsigned int *) &matchexpr[i]) != 1) {
				printf("pattern is not a valid hex string\n");
				free(matchexpr);
				matchexpr = NULL;
				return -1;
			}

		break;
	}

	free(argz);

	// apply match expression to selected packet source
	if (pktsrc) {
		printf("applying new match expression...\n");
		for (i = 0; i < stream_total_count; ++i) {
			if (matchexpr == NULL) {
				slist[i]->match = 1;
			} else {
				// match expression defined, check if stream matches
				if (memmem(slist[i]->data, slist[i]->len, matchexpr, matchexprlen) != NULL)
					slist[i]->match = 1;
				else
					slist[i]->match = 0;
			}
		}
	}

	return 0;
}


int cmd_pipe(char *arg) {
	char **argv, *argz, *number;
	int fpipefd[2], bpipefd[2]; // pipes for bidirectional communication with a child process
	int pid, n;
	size_t argzlen;

	if (pktsrc == NULL) {
		printf("select a packet source first\n");
		return -1;
	}

	if (extprog == NULL) {
		printf("no external program specified\n");
		return -1;
	}

	// create argument vector from extprog string
	if (argz_create_sep(extprog, ' ', &argz, &argzlen) != 0) {
		perror("argz_create_sep()");
		return -1;
	}
	if ((argv = calloc(argz_count(argz, argzlen) + 1, sizeof(char *))) == NULL) {
		perror("calloc()");
		return -1;
	}
	argz_extract(argz, argzlen, argv);

	if ((number = strchr(arg, ' ')) == NULL) {
		printf("pipe: need a stream number.\n");
		return -1;
	}
	n = strtoul(number, NULL, 0);

	if (n > stream_total_count) {
		printf("no such stream\n");
		return -1;
	}

	// insert pipe, fork, dup2, exec here
	if ((pipe(fpipefd) == -1) || (pipe(bpipefd) == -1)) {
		perror("pipe()");
		return -1;
	}

	switch (pid = fork()) {
	case -1:
		perror("fork()");
		return -1;
	case 0:
		// client code
		close(fpipefd[1]);
		close(bpipefd[0]);

		dup2(fpipefd[0], STDIN_FILENO); // connect stdin to 1st pipe's read end
		close(fpipefd[0]);

		dup2(bpipefd[1], STDOUT_FILENO); // connect stdout to 2nd pipe's write end
		dup2(bpipefd[1], STDERR_FILENO); // connect stdout to 2nd pipe's write end
		close(bpipefd[1]);

		// execute external program
		execvp(argv[0], argv);

		perror("execvp()"); // should never get here...
		_exit(EXIT_FAILURE);
		break;
	}
	// server code
	free(argv);
	free(argz);

	close(fpipefd[0]); // close 1st pipe's read end
	close(bpipefd[1]); // close 2nd pipe's write end
	
	// pipe stream to child's stdin
	int total, written;
	total = 0;
	while (total < slist[n]->len) {
		switch (written = write(fpipefd[1], slist[n]->data + total, slist[n]->len - total)) {
		case -1:
			perror("write()");
			close(fpipefd[1]);
			close(bpipefd[0]);
			return -1;
		default:
			total += written;
			break;
		}
	}
	close(fpipefd[1]);

	// read child's stdout and dump it
	char buffer[BUFSIZ];
	int bytes;
	int complete = 0;
	while (complete == 0) {
		switch (bytes = read(bpipefd[0], buffer, BUFSIZ)) {
		case -1:
			perror("read()");
			close(bpipefd[0]);
			return -1;
		case 0:
			complete = 1;
			break;
		default:
			*buffer = toupper(*buffer);
			if (write(STDOUT_FILENO, buffer, bytes) == -1) {
				perror("write()");
				close(bpipefd[0]);
				return -1;
			};
			break;
		}
	}
	close(bpipefd[0]);

	// wait for child process to terminate
	// do not catch SIGCHILD, that screws it up
	int status;
	if (waitpid(pid, &status, WUNTRACED) == -1) {
		perror("waitpid()");
		return -1;
	}

	return 0;
};


int cmd_ext(char *arg) {
	char *prog;

	if ((prog = strchr(arg, ' ')) == NULL) {
		printf("no program specified.\n");
		return -1;
	}

	extprog = strdup(prog + 1);

	return 0;
};


int cmd_status(char *arg) {
	putchar('\n');
	printf("  trace file:\t\t%s\n", tracefile ? tracefile : "[none]");
	printf("  bpf expression:\t%s\n", filter ? filter: "[none]");
	printf("  match expression:\t");
	if (matchexpr  == NULL) {
		printf("[none]\n");
	} else {
		int binary = 0;
		size_t i;
		for (i = 0; i < matchexprlen; ++i) {
			if (!isprint(matchexpr[i])) {
				binary = 1;
				break;
			}
		}

		if (binary == 0) {
			printf("%s\n", matchexpr);
		} else {
			putchar('\n');
			hd((u_char *) matchexpr, matchexprlen);
		}
	}
	printf("  stream filter:\t%s\n", filter_streams ? "on (exclude empty and incomplete streams)" : "off (list all streams)");
	printf("  time display mode:\t%s\n", relative_timestamps ? "relative" : "absolute");
	printf("  external program:\t%s\n", extprog ? extprog : "[none]");
	printf("  output file:\t\t%s\n", outfile ? outfile : "[none]");
	putchar('\n');
	return 0;
};


int cmd_filter(char *arg) {
	filter_streams ^= 1;
	printf("stream filter: %s\n", filter_streams ? "on (list only non-empty, complete streams)" : "off (list all streams)");
	return 0;
};


int cmd_timestamps(char *arg) {
	relative_timestamps ^= 1;
	printf("timestamps: %s\n", relative_timestamps ? "relative" : "absolute");
	return 0;
};
