/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2008  Intel Corporation
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <gdbus.h>

#include "session.h"
#include "pbap.h"

static DBusMessage *pbap_pull_phonebook(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return NULL;
}

static DBusMessage *pbap_set_phonebook(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return NULL;
}

static DBusMessage *pbap_pull_vcard_listing(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return NULL;
}

static DBusMessage *pbap_pull_vcard_entry(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return NULL;
}

static GDBusMethodTable pbap_methods[] = {
	/* PullPhoneBook input parameters : Name, Filter, Format,
					MaxListCount, ListStartOffset */
	{ "PullPhoneBook",	"styqq", "s",	pbap_pull_phonebook,
						G_DBUS_METHOD_FLAG_ASYNC },
	/* SetPhoneBook input parameters : Name */
	{ "SetPhoneBook",	"s", "",	pbap_set_phonebook },
	/* PullvCardListing input parameters : Name, Order, SearchValue,
			SearchAttribute, MaxListCount, ListStartOffset */
	{ "PullvCardListing",	"sysyqq", "s",	pbap_pull_vcard_listing,
						G_DBUS_METHOD_FLAG_ASYNC },
	/* PullPhoneBook input parameters : Name, Filter, Format */
	{ "PullvCardEntry",	"sty", "s",	pbap_pull_vcard_entry,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

gboolean pbap_register_interface(DBusConnection *connection, const char *path,
				void *user_data, GDBusDestroyFunction destroy)
{
	return g_dbus_register_interface(connection, path, PBAP_INTERFACE,
				pbap_methods, NULL, NULL, user_data, destroy);
}

void pbap_unregister_interface(DBusConnection *connection, const char *path)
{
	g_dbus_unregister_interface(connection, path, PBAP_INTERFACE);
}
