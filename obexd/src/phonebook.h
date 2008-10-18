/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

struct phonebook_context {
};

struct phonebook_driver {
	const char *name;
	int (*create) (struct phonebook_context *context);
	void (*destroy) (struct phonebook_context *context);
	int (*pullphonebook) (struct phonebook_context *context, ...);
	int (*pullvcardlisting) (struct phonebook_context *context, ...);
	int (*pullvcardentry) (struct phonebook_context *context, ...);
};

extern int phonebook_driver_register(struct phonebook_driver *driver);
extern void phonebook_driver_unregister(struct phonebook_driver *driver);

extern void phonebook_return(struct phonebook_context *context,
					unsigned char *buf, int size);
