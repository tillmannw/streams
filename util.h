// util.h -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#ifndef __UTIL_H
#define __UTIL_H

#include <sys/types.h>
#include <time.h>

void hd(const u_char *data, size_t len);
struct timeval timediff(struct timeval x, struct timeval y);

#endif
