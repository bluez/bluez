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

#include <stdint.h>
#include <glib.h>
#include <gdbus.h>

struct obc_session;

typedef void (*session_callback_t) (struct obc_session *session,
					GError *err, void *user_data);

struct obc_session *obc_session_create(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner,
						session_callback_t function,
						void *user_data);

struct obc_session *obc_session_ref(struct obc_session *session);
void obc_session_unref(struct obc_session *session);
void obc_session_shutdown(struct obc_session *session);

int obc_session_set_owner(struct obc_session *session, const char *name,
			GDBusWatchFunction func);
const char *obc_session_get_owner(struct obc_session *session);

int obc_session_set_agent(struct obc_session *session, const char *name,
							const char *path);
const char *obc_session_get_agent(struct obc_session *session);

const char *obc_session_get_path(struct obc_session *session);
const char *obc_session_get_target(struct obc_session *session);
const char *obc_session_get_buffer(struct obc_session *session, size_t *size);
void *obc_session_get_params(struct obc_session *session, size_t *size);

int obc_session_send(struct obc_session *session, const char *filename,
				const char *remotename);
int obc_session_get(struct obc_session *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func, void *user_data);
int obc_session_pull(struct obc_session *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data);
const char *obc_session_register(struct obc_session *session,
						GDBusDestroyFunction destroy);
int obc_session_put(struct obc_session *session, char *buf,
				const char *targetname);

guint obc_session_setpath(struct obc_session *session, const char *path,
				session_callback_t func, void *user_data,
				GError **err);
guint obc_session_mkdir(struct obc_session *session, const char *folder,
				session_callback_t func, void *user_data,
				GError **err);
guint obc_session_copy(struct obc_session *session, const char *filename,
				const char *destname, session_callback_t func,
				void *user_data, GError **err);
guint obc_session_move(struct obc_session *session, const char *filename,
				const char *destname, session_callback_t func,
				void *user_data, GError **err);
guint obc_session_delete(struct obc_session *session, const char *file,
				session_callback_t func, void *user_data,
				GError **err);
void obc_session_cancel(struct obc_session *session, guint id,
							gboolean remove);
