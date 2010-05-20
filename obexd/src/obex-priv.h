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

struct server {
	gboolean auto_accept;
	char *folder;
	gboolean symlinks;
	char *capability;
	uint32_t handle;
	char *devnode;
	gboolean secure;
	GIOChannel *io;
	unsigned int watch;
	uint16_t tx_mtu;
	uint16_t rx_mtu;
	GSList *drivers;
};

struct obex_session {
	GIOChannel *io;
	uint32_t cid;
	uint16_t tx_mtu;
	uint16_t rx_mtu;
	uint8_t cmd;
	char *name;
	char *type;
	char *path;
	time_t time;
	uint8_t *buf;
	int32_t pending;
	int32_t offset;
	int32_t size;
	void *object;
	gboolean aborted;
	struct obex_service_driver *service;
	void *service_data;
	struct server *server;
	gboolean checked;
	obex_t *obex;
	obex_object_t *obj;
	struct obex_mime_type_driver *driver;
	gboolean finished;
};

int obex_session_start(GIOChannel *io, struct server *server);
void server_free(struct server *server);

void register_record(struct server *server);
int request_service_authorization(struct server *server, GIOChannel *io,
							const char *address);
