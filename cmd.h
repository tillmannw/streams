// cmd.h -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#ifndef __CMD_H
#define __CMD_H


typedef struct {
	char *name;		// command string
	rl_icpfunc_t *fn;	// command handler
	char *desc;		// command description
} cmd;

int cmd_analyze(char *arg);
int cmd_bpf(char *arg);
int cmd_count(char *arg);
int cmd_dump(char *arg);
int cmd_ext(char *arg);
int cmd_help(char *arg);
int cmd_list(char *arg);
int cmd_match(char *arg);
int cmd_offset(char *arg);
int cmd_outfile(char *arg);
int cmd_pipe(char *arg);
int cmd_quit(char *arg);
int cmd_status(char *arg);
int cmd_filter(char *arg);
int cmd_timestamps(char *arg);

static cmd commands[] = {
	{ "analyze", cmd_analyze, "analyze trace file" },
	{ "bpf", cmd_bpf, "\tspecify a berkeley packet filter expression" },
	{ "count", cmd_count, "\tdisplay number of streams" },
	{ "dump", cmd_dump, "\tdump selected stream to a file (see outfile)" },
	{ "ext", cmd_ext, "\tspecify external program (+ arguments) to pipe streams through (see pipe)" },
	{ "filter", cmd_filter, "toggle stream filter status (include/exclude empty and incomplete streams)" },
	{ "help", cmd_help, "\tshow help (this output)" },
	{ "list", cmd_list, "\tlist streams" },
	{ "match", cmd_match, "\tspecify a content pattern, use 'x [pattern]' for patterns in hexadecimal encoding" },
	{ "offset", cmd_offset, "\tset datalink layer offset for packet trace file" },
	{ "outfile", cmd_outfile, "specify an output file for stream dumps (see dumo)" },
	{ "pipe", cmd_pipe, "\tpipe selected stream through an external program (see ext)" },
	{ "quit", cmd_quit, "\tquit program" },
	{ "status", cmd_status, "display program status" },
	{ "timestamps", cmd_timestamps, "toggle time display format (absolute/relative)" },
	{ NULL, NULL, NULL }
};

#endif
