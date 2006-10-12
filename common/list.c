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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <malloc.h>

#include "list.h"

struct slist *slist_append(struct slist *list, void *data)
{
	struct slist *entry, *tail;

	entry = malloc(sizeof(struct slist));
	/* FIXME: this currently just silently fails */
	if (!entry)
		return list;

	entry->data = data;
	entry->next = NULL;

	if (!list)
		return entry;

	/* Find the end of the list */
	for (tail = list; tail->next; tail = tail->next);

	tail->next = entry;

	return list;
}

struct slist *slist_prepend(struct slist *list, void *data)
{
	struct slist *entry;

	entry = malloc(sizeof(struct slist));
	/* FIXME: this currently just silently fails */
	if (!entry)
		return list;

	entry->data = data;
	entry->next = list;

	return entry;
}

struct slist *slist_insert_before(struct slist *list, struct slist *sibling, void *data)
{
	struct slist *entry, *prev, *cur;

	entry = malloc(sizeof(struct slist));
	if (!entry)
		return list;

	entry->data = data;
	entry->next = NULL;

	if (!list)
		return entry;

	for (cur = list, prev = NULL; cur != NULL; prev = cur, cur = prev->next) {
		if (cur == sibling)
			break;
	}

	if (!prev) {
		entry->next = list;
		return entry;
	}

	entry->next = prev->next;
	prev->next = entry;

	return list;
}

struct slist *slist_insert_sorted(struct slist *list, void *data, cmp_func_t cmp_func)
{
	struct slist *tmp, *prev, *entry;
	int cmp;

	entry = malloc(sizeof(struct slist));
	if (!entry)
		return list;

	entry->data = data;
	entry->next = NULL;

	if (!list)
		return entry;

	prev = NULL;
	tmp = list;

	cmp = cmp_func(data, tmp->data);

	while (tmp->next && cmp > 0) {
		prev = tmp;
		tmp = tmp->next;

		cmp = cmp_func(data, tmp->data);
	}

	if (!tmp->next && cmp > 0) {
		tmp->next = entry;
		return list;
	}

	if (prev) {
		prev->next = entry;
		entry->next = tmp;
		return list;
	} else {
		entry->next = list;
		return entry;
	}
}

struct slist *slist_remove(struct slist *list, void *data)
{
	struct slist *l, *next, *prev = NULL, *match = NULL;

	if (!list)
		return NULL;

	for (l = list; l != NULL; l = l->next) {
		if (l->data == data) {
			match = l;
			break;
		}
		prev = l;
	}

	if (!match)
		return list;

	next = match->next;

	free(match);

	/* If the head was removed, return the next element */
	if (!prev)
		return next;

	prev->next = next;

	return list;
}

struct slist *slist_find(struct slist *list, const void *data,
			cmp_func_t cmp_func)
{
	struct slist *l;

	for (l = list; l != NULL; l = l->next) {
		if (!cmp_func(l->data, data))
			return l;
	}

	return NULL;
}

static struct slist *slist_sort_merge(struct slist *l1, struct slist *l2,
					cmp_func_t cmp_func)
{
	struct slist list, *l;
	int cmp;

	l = &list;

	while (l1 && l2) {
		cmp = cmp_func(l1->data, l2->data);

		if (cmp <= 0) {
			l = l->next = l1;
			l1 = l1->next;
		} else {
			l = l->next = l2;
			l2 = l2->next;
		}
	}

	l->next = l1 ? l1 : l2;

	return list.next;
}

struct slist *slist_sort(struct slist *list, cmp_func_t cmp_func)
{
	struct slist *l1, *l2;

	if (!list || !list->next) 
		return list;

	l1 = list; 
	l2 = list->next;

	while ((l2 = l2->next) != NULL) {
		if ((l2 = l2->next) == NULL) 
			break;
		l1 = l1->next;
	}

	l2 = l1->next; 
	l1->next = NULL;

	return slist_sort_merge(slist_sort(list, cmp_func),
				slist_sort(l2, cmp_func), cmp_func);
}

int slist_length(struct slist *list)
{
	int len;

	for (len = 0; list != NULL; list = list->next)
		len++;

	return len;
}

void slist_foreach(struct slist *list, slist_func_t func, void *user_data)
{
	while (list) {
		struct slist *next = list->next;
		func(list->data, user_data);
		list = next;
	}
}

void slist_free(struct slist *list)
{
	struct slist *l, *next;

	for (l = list; l != NULL; l = next) {
		next = l->next;
		free(l);
	}
}
