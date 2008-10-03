/*
 *
 *  OBEX Client
 *
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

#include <errno.h>

#include <glib.h>

#include "session.h"

int session_create(const char *source,
			const char *destination, const char *target,
				session_callback callback, void *user_data)
{
	struct session_data *session;

	if (destination == NULL)
		return -EINVAL;

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return -ENOMEM;

	if (source == NULL)
		bacpy(&session->src, BDADDR_ANY);
	else
		str2ba(source, &session->src);

	str2ba(destination, &session->dst);

	if (target != NULL)
		session->target = g_strdup(target);

	callback(session, user_data);

	g_free(session->agent);
	g_free(session->target);
	g_free(session);

	return 0;
}

int session_set_agent(struct session_data *session, const char *agent)
{
	if (session == NULL)
		return -EINVAL;

	if (session->agent != NULL)
		return -EALREADY;

	printf("Using agent at %s\n", agent);

	session->agent = g_strdup(agent);

	return 0;
}

int session_send(struct session_data *session, const char *filename)
{
	printf("Sending file %s\n", filename);

	return 0;
}
