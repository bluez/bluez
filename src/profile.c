/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "uuid.h"
#include "error.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"

struct ext_profile {
	struct btd_profile p;
	char *name;
	char *owner;
	char *uuid;
	char *path;
};

static GSList *profiles = NULL;
static GSList *ext_profiles = NULL;

void btd_profile_foreach(void (*func)(struct btd_profile *p, void *data),
								void *data)
{
	GSList *l, *next;

	for (l = profiles; l != NULL; l = next) {
		struct btd_profile *profile = l->data;

		next = g_slist_next(l);

		func(profile, data);
	}

	for (l = ext_profiles; l != NULL; l = next) {
		struct ext_profile *profile = l->data;

		next = g_slist_next(l);

		func(&profile->p, data);
	}
}

int btd_profile_register(struct btd_profile *profile)
{
	profiles = g_slist_append(profiles, profile);
	return 0;
}

void btd_profile_unregister(struct btd_profile *profile)
{
	profiles = g_slist_remove(profiles, profile);
}

static struct ext_profile *find_ext_profile(const char *owner,
						const char *path)
{
	GSList *l;

	for (l = ext_profiles; l != NULL; l = g_slist_next(l)) {
		struct ext_profile *ext = l->data;

		if (!g_str_equal(ext->owner, owner))
			continue;

		if (g_str_equal(ext->path, path))
			return ext;
	}

	return NULL;
}

static struct ext_profile *create_ext(const char *owner, const char *path,
					const char *uuid,
					DBusMessageIter *opts)
{
	struct btd_profile *p;
	struct ext_profile *ext;

	ext = g_new0(struct ext_profile, 1);

	ext->name = g_strdup_printf("%s-%s/%s", owner, path, uuid);
	ext->owner = g_strdup(owner);
	ext->path = g_strdup(path);
	ext->uuid = g_strdup(uuid);

	p = &ext->p;

	p->name = ext->name;

	ext_profiles = g_slist_append(ext_profiles, ext);

	return ext;
}

static void remove_ext(struct ext_profile *ext)
{
	ext_profiles = g_slist_remove(ext_profiles, ext);

	g_free(ext->name);
	g_free(ext->owner);
	g_free(ext->uuid);
	g_free(ext->path);

	g_free(ext);
}

DBusMessage *btd_profile_reg_ext(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	const char *path, *sender, *uuid;
	DBusMessageIter args, opts;
	struct ext_profile *ext;

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	ext = find_ext_profile(sender, path);
	if (ext)
		return btd_error_already_exists(msg);

	dbus_message_iter_get_basic(&args, &uuid);
	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &opts);
	if (dbus_message_iter_get_arg_type(&opts) != DBUS_TYPE_DICT_ENTRY)
		return btd_error_invalid_args(msg);

	ext = create_ext(sender, path, uuid, &opts);
	if (!ext)
		return btd_error_invalid_args(msg);

	return dbus_message_new_method_return(msg);
}

DBusMessage *btd_profile_unreg_ext(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	const char *path, *sender;
	struct ext_profile *ext;

	sender = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	ext = find_ext_profile(sender, path);
	if (!ext)
		return btd_error_does_not_exist(msg);

	remove_ext(ext);

	return dbus_message_new_method_return(msg);
}
