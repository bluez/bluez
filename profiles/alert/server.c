/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdbool.h>

#include "adapter.h"
#include "server.h"
#include "profile.h"

static int alert_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	return 0;
}

static void alert_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
}

static struct btd_profile alert_profile = {
	.name = "gatt-alert-server",
	.adapter_probe = alert_server_probe,
	.adapter_remove = alert_server_remove,
};

int alert_server_init(void)
{
	btd_profile_register(&alert_profile);

	return 0;
}

void alert_server_exit(void)
{
	btd_profile_unregister(&alert_profile);
}
