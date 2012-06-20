/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nokia Corporation
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
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

#include "adapter.h"
#include "manager.h"
#include "server.h"

struct btd_adapter_driver time_server_driver = {
	.name = "gatt-time-server",
	.probe = time_server_init,
	.remove = time_server_exit,
};

int time_manager_init(void)
{
	btd_register_adapter_driver(&time_server_driver);

	return 0;
}

void time_manager_exit(void)
{
	btd_unregister_adapter_driver(&time_server_driver);
}
