// hash.h -- (C) 2011 Tillmann Werner, <tillmann.werner@kaspersky.com

#ifndef __HASH_H
#define __HASH_H

#include <sys/types.h>

typedef struct hash_entry_t {
	u_int32_t	hash;
	u_char		key[12];
	void		*data;
	struct hash_entry_t *next;
} hash_entry_t;

hash_entry_t *hashmap[0x10000];

hash_entry_t *hash_add(u_int32_t addr1, u_int16_t port1, u_int32_t addr2, u_int16_t port2, void *data);
void *hash_lookup(u_int32_t addr1, u_int16_t port1, u_int32_t addr2, u_int16_t port2, int remove);

#endif
