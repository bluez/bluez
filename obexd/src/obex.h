/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#define OBJECT_SIZE_UNKNOWN -1
#define OBJECT_SIZE_DELETE -2

#define OBEX_OPP	(1 << 0)
#define OBEX_FTP	(1 << 2)
#define OBEX_BIP	(1 << 3)
#define OBEX_PBAP	(1 << 4)
#define OBEX_PCSUITE	(1 << 5)
#define OBEX_SYNCEVOLUTION	(1 << 6)

#define TARGET_SIZE 16

struct obex_service_driver;
struct obex_mime_type_driver;

struct server {
	gboolean	auto_accept;
	gchar		*folder;
	gboolean	symlinks;
	gchar		*capability;
	guint32		handle;
	gchar		*devnode;
	gboolean	secure;
	GIOChannel	*io;
	guint		watch;
	guint16		tx_mtu;
	guint16		rx_mtu;
	GSList		*drivers;
};

struct obex_session {
	GIOChannel	*io;
	guint32		cid;
	guint16		tx_mtu;
	guint16		rx_mtu;
	guint8		cmd;
	gchar		*name;
	gchar		*type;
	time_t		time;
	gchar		*current_folder;
	guint8		*buf;
	gint32		offset;
	gint32		size;
	gpointer	object;
	gboolean	aborted;
	struct obex_service_driver *service;
	struct server *server;
	gboolean	checked;
	obex_t		*obex;
	struct obex_mime_type_driver *driver;
	gboolean	finished;
};

gint obex_session_start(GIOChannel *io, struct server *server);
struct obex_session *obex_get_session(gpointer object);
gint obex_tty_session_stop(void);

gint os_prepare_get(struct obex_session *os, gchar *file, size_t *size);
gint os_prepare_put(struct obex_session *os);

void server_free(struct server *server);

int tty_init(gint service, const gchar *folder, const gchar *capability,
		gboolean symlinks, const gchar *devnode);
void tty_closed(void);
