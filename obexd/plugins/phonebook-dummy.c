/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <string.h>
#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "phonebook.h"

#define VCARD0				\
        "BEGIN:VCARD\n"			\
        "VERSION:3.0\n"			\
        "N:Klaus;Santa\n"		\
        "FN:\n"				\
        "TEL:+001122334455\n"		\
        "END:VCARD\n"


struct dummy_data {
	phonebook_cb	cb;
	gpointer	user_data;
};

int phonebook_init(void)
{
	return 0;
}

void phonebook_exit(void)
{
}

static gboolean dummy_result(gpointer data)
{
	struct dummy_data *dummy = data;

	dummy->cb(VCARD0, strlen(VCARD0), 1, 0, dummy->user_data);

	return FALSE;
}

int phonebook_query(const gchar *name, phonebook_cb cb, gpointer user_data)
{
	struct dummy_data *dummy;

	dummy = g_new0(struct dummy_data, 1);
	dummy->cb = cb;
	dummy->user_data = user_data;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE,
			dummy_result, dummy, g_free);
	return 0;
}
