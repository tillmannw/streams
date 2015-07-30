/*
  streams.c
  Copyright (C) 2011-2015 Tillmann Werner, tillmann.werner@gmx.de

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

#include <pcap.h>
#include <history.h>
#include <readline.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "cmd.h"
#include "sig.h"
#include "streams.h"
#include "strm.h"


char *command_generate(const char *line, int state) {
	static int i;
	static size_t len;
	char *c;

	if (state == 0) {
		i = 0;
		len = strlen(line);
	}
	while ((c = commands[i].name) != NULL) {
		i++;
		if (strncmp(c, line, len) == 0) return strdup(c);
	}

	return NULL;
}

char **command_complete(const char *line, int start, int end) {
	char **matches = NULL;

	if (start == 0)
		matches = rl_completion_matches(line, command_generate);

	return matches;
}

cmd *command_find(const char *line, size_t len) {
	int i;

	for (i = 0; commands[i].name; ++i) {
		if (strncmp(commands[i].name, line, len) == 0) {
			return &commands[i];
		}
	}

	return NULL;
}

char *stripwhite(char *string) {
	register char *s, *t;

	for (s = string; whitespace(*s); s++);

	if (*s == 0) return (s);

	t = s + strlen (s) - 1;
	while (t > s && whitespace (*t)) t--;
	*++t = '\0';

	return s;
}

int main(int argc, char *argv[]) {
	char *line, *c;
	int wordlen;
	cmd *command;
	const char *prompt = "streams> ";
	struct sigaction saction;


	// signal stuff
	memset(&saction, 0, sizeof(struct sigaction));
	saction.sa_handler = sh_general;
	saction.sa_flags |= SA_NOCLDWAIT;
	if (sigaction(SIGINT, &saction, NULL) == -1) {
		perror("sigaction()");
		exit(EXIT_FAILURE);
	}

	printf( "                                  _\n" \
		"              _____ _____     ___| |_ _ __ ___  __ _ _ __ ___  ___\n" \
		"   _____     |_____|_____|   / __| __| '__/ _ \\/ _` | '_ ` _ \\/ __|\n" \
		"  |_____| _  |_____|_____|   \\__ \\ |_| | |  __/ (_| | | | | | \\__ \\  _   _ _\n" \
		"       (_|_)____        (_)  |___/\\__|_|  \\___|\\__,_|_| |_| |_|___/ (_) (_|_)\n" \
		"          |_____|\n" \
		"                      version %s, Copyright (C) 2011-2015 by Tillmann Werner\n\n", VERSION);


	rl_attempted_completion_function = command_complete;

	filter = strdup("tcp");
	tracefile = NULL;
	pktsrc = NULL;
	slist = NULL;
	extprog = NULL;
	matchexpr = NULL;
	outfile = NULL;
	global_start.tv_sec = 0;
	global_start.tv_usec = 0;
	relative_timestamps = 1;
	filter_streams = 1;
	offset = 0;
	tcp_timeout = 30;	// set default tcp timeout to 30 seconds

	if (argc > 1) {
		char *command;
		if ((command = calloc(strlen(argv[1]) + 6, 1)) == NULL) {
			perror("calloc()");
			exit(EXIT_FAILURE);
		}
		sprintf(command, "file %s", argv[1]);
		cmd_analyze(command);
		free(command);
	}

	for (done = 0; done == 0; ) {
		line = readline(prompt);

		if (line && *line) {
			c = stripwhite(line);

			add_history(c);

			wordlen = strlen(c);
			if (strchr(c, ' '))
				wordlen = strchr(c, ' ') - line;

			if ((command = command_find(c, wordlen)) != NULL) command->fn(c);
			else printf("Command not implemented. Type 'help' for a list of supported commands.\n");
		} else putchar('\r');

		free(line);
	}

	// close packet source
	if (pktsrc) pcap_close(pktsrc);

	free(tracefile);

	return EXIT_SUCCESS;
}
