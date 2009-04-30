/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
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

void emit_session_created(guint32 id);

void emit_session_removed(guint32 id);

void emit_transfer_started(guint32 id);

void emit_transfer_completed(guint32 id, gboolean success);

void emit_transfer_progress(guint32 id, guint32 total, guint32 transfered);

int request_authorization(gint32 cid, int fd, const gchar *filename,
			const gchar *type, gint32 length, gint32 time,
			gchar **new_folder, gchar **new_name);

void register_transfer(guint32 id, struct obex_session *os);

void unregister_transfer(guint32 id);

void register_record(struct server *server, gpointer user_data);

gint request_service_authorization(struct server *server, GIOChannel *io,
					const char *address);

void register_session(guint32 id, struct obex_session *os);

void unregister_session(guint32 id);
