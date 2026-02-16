// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
 *
 */

bool gap_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client);
void gap_unregister_service(struct btp *btp);
bool gap_is_service_registered(void);

void gap_proxy_added(struct l_dbus_proxy *proxy, void *user_data);
void gap_property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data);
