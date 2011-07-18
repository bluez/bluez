/*
 *
 *  OBEX Client
 *
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

#include <glib.h>
#include <gdbus.h>
#include <gw-obex.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

struct session_data;

typedef void (*session_callback_t) (struct session_data *session,
					GError *err, void *user_data);

struct session_data *session_create(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner,
						session_callback_t function,
						void *user_data);

struct session_data *session_ref(struct session_data *session);
void session_unref(struct session_data *session);
void session_shutdown(struct session_data *session);

int session_set_owner(struct session_data *session, const char *name,
			GDBusWatchFunction func);
const char *session_get_owner(struct session_data *session);

int session_set_agent(struct session_data *session, const char *name,
							const char *path);
const char *session_get_agent(struct session_data *session);

const char *session_get_path(struct session_data *session);
const char *session_get_target(struct session_data *session);
GwObex *session_get_obex(struct session_data *session);

struct transfer_data *session_get_transfer(struct session_data *session);
void session_add_transfer(struct session_data *session,
					struct transfer_data *transfer);
void session_remove_transfer(struct session_data *session,
					struct transfer_data *transfer);

int session_send(struct session_data *session, const char *filename,
				const char *remotename);
int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func, void *user_data);
int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data);
const char *session_register(struct session_data *session,
						GDBusDestroyFunction destroy);
int session_put(struct session_data *session, char *buf,
				const char *targetname);
