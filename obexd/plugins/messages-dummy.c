/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010-2011  Nokia Corporation
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

#include "messages.h"

int messages_init(void)
{
	return 0;
}

void messages_exit(void)
{
}

int messages_connect(void **session)
{
	*session = 0;
	return 0;
}

void messages_disconnect(void *session)
{
}

int messages_set_notification_registration(void *session,
		void (*send_event)(void *session,
			struct messages_event *event, void *user_data),
		void *user_data)
{
	return -EINVAL;
}

int messages_set_folder(void *session, const char *name, gboolean cdup)
{
	return -EINVAL;
}

int messages_get_folder_listing(void *session,
		const char *name,
		uint16_t max, uint16_t offset,
		void (*callback)(void *session, int err, uint16_t size,
			const char *name, void *user_data),
		void *user_data)
{
	return -EINVAL;
}

int messages_get_messages_listing(void *session,
		const char *name,
		uint16_t max, uint16_t offset, struct messages_filter *filter,
		void (*callback)(void *session, int err, uint16_t size,
			gboolean newmsg, const struct messages_message *message,
			void *user_data),
		void *user_data)
{
	return -EINVAL;
}

int messages_get_message(void *session,
		const char *handle,
		unsigned long flags,
		void (*callback)(void *session, int err, gboolean fmore,
			const char *chunk, void *user_data),
		void *user_data)
{
	return -EINVAL;
}

void messages_abort(void *session)
{
}
