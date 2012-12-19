/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#include <glib.h>
#include <gdbus/gdbus.h>

#include "log.h"
#include "dbus.h"

static void append_variant(DBusMessageIter *iter,
				int type, void *value)
{
	char sig[2];
	DBusMessageIter valueiter;

	sig[0] = type;
	sig[1] = 0;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						sig, &valueiter);

	dbus_message_iter_append_basic(&valueiter, type, value);

	dbus_message_iter_close_container(iter, &valueiter);
}

void obex_dbus_dict_append(DBusMessageIter *dict,
			const char *key, int type, void *value)
{
	DBusMessageIter keyiter;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) value);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &keyiter);

	dbus_message_iter_append_basic(&keyiter, DBUS_TYPE_STRING, &key);

	append_variant(&keyiter, type, value);

	dbus_message_iter_close_container(dict, &keyiter);
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter variant, array;
	char typesig[2];
	char arraysig[3];
	const char **str_array = *(const char ***) val;
	int i;

	arraysig[0] = DBUS_TYPE_ARRAY;
	arraysig[1] = typesig[0] = type;
	arraysig[2] = typesig[1] = '\0';

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						arraysig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						typesig, &array);

	for (i = 0; str_array[i]; i++)
		dbus_message_iter_append_basic(&array, type,
						&(str_array[i]));

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

static void append_dict_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter variant, array, entry;
	char typesig[5];
	char arraysig[6];
	const void **val_array = *(const void ***) val;
	int i;

	arraysig[0] = DBUS_TYPE_ARRAY;
	arraysig[1] = typesig[0] = DBUS_DICT_ENTRY_BEGIN_CHAR;
	arraysig[2] = typesig[1] = DBUS_TYPE_STRING;
	arraysig[3] = typesig[2] = type;
	arraysig[4] = typesig[3] = DBUS_DICT_ENTRY_END_CHAR;
	arraysig[5] = typesig[4] = '\0';

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						arraysig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						typesig, &array);

	for (i = 0; val_array[i]; i += 2) {
		dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
						&(val_array[i + 0]));

		/*
		 * D-Bus expects a char** or uint8* depending on the type
		 * given. Since we are dealing with an array through a void**
		 * (and thus val_array[i] is a pointer) we need to
		 * differentiate DBUS_TYPE_STRING from the others. The other
		 * option would be the user to pass the exact type to this
		 * function, instead of a pointer to it. However in this case
		 * a cast from type to void* would be needed, which is not
		 * good.
		 */
		if (type == DBUS_TYPE_STRING) {
			dbus_message_iter_append_basic(&entry, type,
							&(val_array[i + 1]));
		} else {
			dbus_message_iter_append_basic(&entry, type,
							val_array[i + 1]);
		}

		dbus_message_iter_close_container(&array, &entry);
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

int obex_dbus_signal_property_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL) {
		error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_variant(&iter, type, value);

	return g_dbus_send_message(conn, signal);
}
