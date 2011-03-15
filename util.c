// util.c -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>


void hd(const u_char *data, size_t len) {
        register int i, j;

        if (!data || !len) return;

        for (i = 0; i < len; i += 0x10) {
                printf("0x%08x  ", i);

                for (j = 0; j < 0x10 && i+j<len; j++) {
                        if (j == 0x8) putchar(' ');
                        printf("%02x ", data[i+j]);
                }

                printf("%-*c|", (3 * (0x10 - j)) + (j > 0x8 ? 1 : 2), ' ');

                for (j = 0; j < 0x10 && i + j < len; j++)
                        putchar(isprint(data[i+j]) ? data[i+j] : '.');

                puts("|");
        }
        putchar('\n');

        return;
}
 	
struct timeval timediff(struct timeval x, struct timeval y) {
	struct timeval result = y;
/*
printf("--> x: %d\n", (unsigned int) x.tv_sec);
printf("--> y: %d\n", (unsigned int) y.tv_sec);
printf("--> y-x: %d\n", (unsigned int) y.tv_sec - (unsigned int) x.tv_sec);
*/

	result.tv_sec -= x.tv_sec;

	if (x.tv_usec > result.tv_usec) {
		result.tv_sec -= 1;
		result.tv_usec += 1000000;
	}
	result.tv_usec -= x.tv_usec;

	return result;
}

