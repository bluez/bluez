/*
 *
 *  OBEX Client
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

#include <bluetooth/bluetooth.h>

struct session_data {
	bdaddr_t src;
	bdaddr_t dst;
	char *target;
	char *agent;
};

typedef void (*session_callback) (struct session_data *session,
							void *user_data);

int session_create(const char *source,
			const char *destination, const char *target,
				session_callback callback, void *user_data);
int session_set_agent(struct session_data *session, const char *agent);
int session_send(struct session_data *session, const char *filename);
