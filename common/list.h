/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2006  Johan Hedberg <johan.hedberg@nokia.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __LIST_H
#define __LIST_H

struct slist {
	void *data;
	struct slist *next;
};

typedef int (*cmp_func_t)(const void *a, const void *b);
typedef void (*slist_func_t)(void *data, void *user_data);

struct slist *slist_append(struct slist *list, void *data);

struct slist *slist_prepend(struct slist *list, void *data);

struct slist *slist_insert_before(struct slist *list, struct slist *sibling, void *data);

struct slist *slist_remove(struct slist *list, void *data);

struct slist *slist_find(struct slist *list, const void *data,
			cmp_func_t cmp_func);

int slist_length(struct slist *list);

void slist_foreach(struct slist *list, slist_func_t func, void *user_data);
void slist_free(struct slist *list);

#endif /* __LIST_H */
