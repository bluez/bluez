/*
 *
 *  OBEX Server
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

struct obex_service_driver {
	const char *name;
	guint16 service;
	guint8 channel;
	const guint8 *target;
	guint target_size;
	const guint8 *who;
	guint who_size;
	const gchar *record;
	int (*connect) (struct OBEX_session *os);
	void (*progress) (struct OBEX_session *os);
	int (*get) (struct OBEX_session *os, obex_object_t *obj);
	int (*put) (struct OBEX_session *os);
	gint (*chkput) (struct OBEX_session *os);
	int (*setpath) (struct OBEX_session *os, obex_object_t *obj);
	void (*disconnect) (struct OBEX_session *os);
	void (*reset) (struct OBEX_session *os);
};

int obex_service_driver_register(struct obex_service_driver *driver);
void obex_service_driver_unregister(struct obex_service_driver *driver);
GSList *obex_service_driver_list(guint16 services);
struct obex_service_driver *obex_service_driver_find(GSList *drivers,
					const guint8 *target, guint target_size,
					const guint8 *who, guint who_size);
