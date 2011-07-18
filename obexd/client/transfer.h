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

#include <gw-obex.h>

struct transfer_params {
	guint8 *data;
	size_t size;
};

struct transfer_callback;
struct transfer_data;

typedef void (*transfer_callback_t) (struct transfer_data *transfer,
					gint64 transferred, gint err,
					void *user_data);

struct transfer_data *transfer_register(DBusConnection *conn,
						const char *filename,
						const char *name,
						const char *type,
						struct transfer_params *params,
						void *user_data);

void transfer_unregister(struct transfer_data *transfer);

int transfer_get(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data);
int transfer_put(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data);
void transfer_abort(struct transfer_data *transfer);

int transfer_get_params(struct transfer_data *transfer,
					struct transfer_params *params);
const char *transfer_get_buffer(struct transfer_data *transfer, int *size);
void transfer_set_buffer(struct transfer_data *transfer, char *buffer);
void transfer_clear_buffer(struct transfer_data *transfer);

void transfer_set_name(struct transfer_data *transfer, const char *name);
const char *transfer_get_path(struct transfer_data *transfer);
gint64 transfer_get_size(struct transfer_data *transfer);
