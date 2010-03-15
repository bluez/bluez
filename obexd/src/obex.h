/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
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

#define OBJECT_SIZE_UNKNOWN -1
#define OBJECT_SIZE_DELETE -2

#define OBEX_OPP	(1 << 0)
#define OBEX_FTP	(1 << 2)
#define OBEX_BIP	(1 << 3)
#define OBEX_PBAP	(1 << 4)
#define OBEX_PCSUITE	(1 << 5)
#define OBEX_SYNCEVOLUTION	(1 << 6)

#define TARGET_SIZE 16

struct obex_session;

void obex_connect_cb(GIOChannel *io, GError *err, gpointer user_data);

int obex_stream_start(struct obex_session *os, const gchar *filename);
gint obex_prepare_put(struct obex_session *os, const  gchar *filename);
const char *obex_get_name(struct obex_session *os);
void obex_set_name(struct obex_session *os, const gchar *name);
ssize_t obex_get_size(struct obex_session *os);
const char *obex_get_type(struct obex_session *os);
void obex_set_folder(struct obex_session *os, const char *folder);
const char *obex_get_root_folder(struct obex_session *os);
guint16 obex_get_service(struct obex_session *os);
gboolean obex_get_symlinks(struct obex_session *os);
const char *obex_get_capability_path(struct obex_session *os);
gboolean obex_get_auto_accept(struct obex_session *os);
int obex_remove(struct obex_session *os, const char *path);
char *obex_get_id(struct obex_session *os);

int tty_init(gint service, const gchar *folder, const gchar *capability,
		gboolean symlinks, const gchar *devnode);
gint obex_tty_session_stop(void);
void tty_closed(void);
