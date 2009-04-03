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

#include "phonebook.h"

#define OBEX_OPP	(1 << 0)
#define OBEX_FTP	(1 << 2)
#define OBEX_BIP	(1 << 3)
#define OBEX_PBAP	(1 << 4)
#define OBEX_PCSUITE	(1 << 5)

#define OBJECT_SIZE_UNKNOWN -1
#define OBJECT_SIZE_DELETE -2

struct obex_commands {
	void (*get) (obex_t *obex, obex_object_t *obj);
	void (*put) (obex_t *obex, obex_object_t *obj);
	gint (*chkput) (obex_t *obex, obex_object_t *obj);
	void (*setpath) (obex_t *obex, obex_object_t *obj);
};

struct server {
	guint16		services;
	gboolean	auto_accept;
	gchar		*name;
	gchar		*folder;
	gboolean	symlinks;
	gchar		*capability;
	guint32		handle;
	uint8_t		channel;
	gchar		*devnode;
	gboolean	secure;
	GIOChannel	*io;
	guint		watch;
	guint16		tx_mtu;
	guint16		rx_mtu;
};

struct obex_session {
	guint32		cid;
	guint16		tx_mtu;
	guint16		rx_mtu;
	uint8_t		cmd;
	gchar		*name;
	gchar		*type;
	time_t		time;
	gchar		*current_folder;
	guint8		*buf;
	gint32		offset;
	gint32		size;
	gint		fd;
	gboolean	aborted;
	const guint8	*target;
	struct obex_commands *cmds;
	struct server *server;
	gboolean	checked;
	obex_t		*obex;
	struct phonebook_context *pbctx;
	gboolean	finished;
};

gint obex_session_start(gint fd, struct server *server);
gint obex_session_stop();

void opp_get(obex_t *obex, obex_object_t *obj);
void opp_put(obex_t *obex, obex_object_t *obj);
gint opp_chkput(obex_t *obex, obex_object_t *obj);

void ftp_get(obex_t *obex, obex_object_t *obj);
void ftp_put(obex_t *obex, obex_object_t *obj);
gint ftp_chkput(obex_t *obex, obex_object_t *obj);
void ftp_setpath(obex_t *obex, obex_object_t *obj);

void pbap_get(obex_t *obex, obex_object_t *obj);
void pbap_setpath(obex_t *obex, obex_object_t *obj);
gboolean pbap_phonebook_context_create(struct obex_session *session);
void pbap_phonebook_context_destroy(struct obex_session *session);
struct obex_session *pbap_get_session(struct phonebook_context *context);

gint os_prepare_get(struct obex_session *os, gchar *file, guint32 *size);
gint os_prepare_put(struct obex_session *os);

void server_free(struct server *server);

int tty_init(gint service, const gchar *folder, const gchar *capability,
		const gchar *devnode);
void tty_closed(void);
