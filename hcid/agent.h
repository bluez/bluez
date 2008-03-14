/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

struct agent;

typedef void (*agent_cb) (struct agent *agent, DBusError *err,
				void *user_data);

typedef void (*agent_passkey_cb) (struct agent *agent, DBusError *err,
					const char *passkey, void *user_data);

typedef void (*agent_remove_cb) (struct agent *agent, void *user_data);

struct agent *agent_create(const char *name, const char *path,
				const char *address,
				agent_remove_cb cb, void *remove_cb_data);

int agent_destroy(struct agent *agent, gboolean exited);

int agent_authorize(struct agent *agent, struct device *device,
			const char *uuid, agent_cb cb, void *user_data);

int agent_request_passkey(struct agent *agent, struct device *device,
				agent_passkey_cb cb, void *user_data);

int agent_confirm(struct agent *agent, struct device *device, const char *pin,
			agent_cb cb, void *user_data);

int agent_confirm_mode_change(struct agent *agent, const char *new_mode,
				agent_cb cb, void *user_data);

int agent_cancel(struct agent *agent);

gboolean agent_matches(struct agent *agent, const char *name, const char *path);

void agent_init(void);
void agent_exit(void);

