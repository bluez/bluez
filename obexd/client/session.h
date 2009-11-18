/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <gw-obex.h>

struct session_data {
	gint refcount;
	bdaddr_t src;
	bdaddr_t dst;
	uint8_t channel;
	const char *target;	/* OBEX Target UUID */
	int target_len;
	uuid_t uuid;		/* Bluetooth Service Class */
	gchar *name;
	gchar *path;		/* Session path */
	gchar *transfer_path;	/* Transfer path */
	int sock;
	int fd;
	DBusConnection *conn;
	DBusMessage *msg;
	GwObex *obex;
	GwObexXfer *xfer;
	char *buffer;
	size_t buffer_len;
	int filled;
	gint64 size;
	gint64 transferred;
	gchar *filename;
	gchar *agent_name;
	gchar *agent_path;
	guint agent_watch;
	gchar *owner;		/* Session owner */
	guint owner_watch;
	GPtrArray *pending;
	void *priv;
};

typedef void (*session_callback_t) (struct session_data *session,
							void *user_data);

int session_create(const char *source,
			const char *destination, const char *target,
			uint8_t channel, session_callback_t function,
			void *user_data);
int session_set_agent(struct session_data *session, const char *name,
							const char *path);
int session_send(struct session_data *session, const char *filename,
				const char *remotename);
int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func);
int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data);
int session_register(struct session_data *session);
void *session_get_data(struct session_data *session);
void session_set_data(struct session_data *session, void *priv);
int session_put(struct session_data *session, char *buf,
				const char *targetname);
