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
	gint size;
};

struct transfer_callback;

struct transfer_data {
	struct session_data *session;
	struct transfer_params *params;
	struct transfer_callback *callback;
	char *path;		/* Transfer path */
	gchar *filename;	/* Transfer file location */
	char *name;		/* Transfer object name */
	char *type;		/* Transfer object type */
	int fd;
	GwObexXfer *xfer;
	char *buffer;
	size_t buffer_len;
	int filled;
	gint64 size;
	gint64 transferred;
	int err;
};

typedef void (*transfer_callback_t) (struct transfer_data *transfer,
					gint64 transferred, gint err,
					void *user_data);

struct transfer_data *transfer_register(struct session_data *session,
						const char *filename,
						const char *name,
						const char *type,
						struct transfer_params *params);

void transfer_unregister(struct transfer_data *transfer);

int transfer_get(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data);
int transfer_put(struct transfer_data *transfer, transfer_callback_t func,
			void *user_data);
void transfer_abort(struct transfer_data *transfer);
