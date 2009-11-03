/*
 *
 *  OBEX Server
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

#define TARGET_SIZE 16

struct obex_mime_type_driver {
	const guint8 *target;
	const char *mimetype;
	gpointer (*open) (const char *name, int oflag, mode_t mode, size_t *size);
	int (*close) (gpointer object);
	ssize_t (*read) (gpointer object, void *buf, size_t count);
	ssize_t (*write) (gpointer object, const void *buf, size_t count);
	int (*remove) (const char *name);
};

int obex_mime_type_driver_register(struct obex_mime_type_driver *driver);
void obex_mime_type_driver_unregister(struct obex_mime_type_driver *driver);
struct obex_mime_type_driver *obex_mime_type_driver_find(const guint8 *target,
							const char *mimetype);
