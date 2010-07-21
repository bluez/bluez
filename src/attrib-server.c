/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>

#include <bluetooth/sdp.h>

#include "attrib-server.h"

static GSList *database = NULL;

struct attribute {
	uint16_t handle;
	uuid_t uuid;
	int len;
	uint8_t data[0];
};

static int handle_cmp(struct attribute *a, uint16_t *handle)
{
	return a->handle - *handle;
}

int attrib_server_init(void)
{
	return 0;
}

void attrib_server_exit(void)
{
	g_slist_foreach(database, (GFunc) g_free, NULL);
	g_slist_free(database);
}

int attrib_db_add(uint16_t handle, uuid_t *uuid, const uint8_t *value, int len)
{
	struct attribute *a;

	/* FIXME: handle conflicts */

	a = g_malloc0(sizeof(struct attribute) + len);
	a->handle = handle;
	memcpy(&a->uuid, uuid, sizeof(uuid_t));
	a->len = len;
	memcpy(a->data, value, len);

	database = g_slist_append(database, a);

	return 0;
}

int attrib_db_del(uint16_t handle)
{
	struct attribute *a;
	GSList *l;

	l = g_slist_find_custom(database, &handle, (GCompareFunc) handle_cmp);
	if (!l)
		return -ENOENT;

	a = l->data;
	database = g_slist_remove(database, a);
	g_free(a);

	return 0;
}
