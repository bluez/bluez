/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Intel Corporation
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

#include <gdbus.h>

struct obc_agent;

struct obc_agent *obc_agent_create(DBusConnection *conn, const char *name,
					const char *path, GFunc destroy,
					void *user_data);
void obc_agent_free(struct obc_agent *agent);
const char *obc_agent_get_name(struct obc_agent *agent);
const char *obc_agent_get_path(struct obc_agent *agent);
int obc_agent_request(struct obc_agent *agent, const char *path,
				DBusPendingCallNotifyFunction function,
				void *user_data, DBusFreeFunction destroy);
void obc_agent_notify_progress(struct obc_agent *agent, const char *path,
							guint64 transferred);
void obc_agent_notify_complete(struct obc_agent *agent, const char *path);
void obc_agent_notify_error(struct obc_agent *agent, const char *path,
							const char *err);
void obc_agent_release(struct obc_agent *agent);
