/*
  hash.h
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
