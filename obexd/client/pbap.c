/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <gdbus.h>

#include "session.h"

static DBusMessage *pbap_pull_phone_book(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return NULL;
}

static DBusMessage *pbap_set_phone_book(DBusConnection *connection,
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

GDBusMethodTable pbap_methods[] = {
/* PullPhoneBook input parameters : Name, Filter, Format, MaxListCount, ListStartOffset */
	{ "PullPhoneBook",	"styqq", "s",	pbap_pull_phone_book,
						G_DBUS_METHOD_FLAG_ASYNC },
/* SetPhoneBook input parameters : Name */
	{ "SetPhoneBook",	"s", "",	pbap_set_phone_book },
/* PullvCardListing input parameters : Name, Order, SearchValue, SearchAttribute, MaxListCount, ListStartOffset */
	{ "PullvCardListing",	"sysyqq", "s",	pbap_pull_vcard_listing,
						G_DBUS_METHOD_FLAG_ASYNC },
/* PullPhoneBook input parameters : Name, Filter, Format */
	{ "PullvCardEntry",	"sty", "s",	pbap_pull_vcard_entry,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};
