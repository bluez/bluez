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

struct agent_data;

struct agent_data *agent_create(DBusConnection *conn, const char *name,
					const char *path, GFunc destroy,
					void *user_data);
void agent_free(struct agent_data *agent);
const char *agent_get_name(struct agent_data *agent);
const char *agent_get_path(struct agent_data *agent);
int agent_request(struct agent_data *agent, const char *path,
				DBusPendingCallNotifyFunction function,
				void *user_data, DBusFreeFunction destroy);
void agent_notify_progress(struct agent_data *agent, const char *path,
							guint64 transferred);
void agent_notify_complete(struct agent_data *agent, const char *path);
void agent_notify_error(struct agent_data *agent, const char *path,
							const char *err);
void agent_release(struct agent_data *agent);
