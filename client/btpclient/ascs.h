// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Collabora Ltd.
 *
 */

bool ascs_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client);
void ascs_unregister_service(struct btp *btp);
bool ascs_is_service_registered(void);

bool ascs_setup(struct btp_adapter *adapter);

void ascs_proxy_added(struct l_dbus_proxy *proxy, void *user_data);
void ascs_property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data);

void ascs_ase_replied(struct btp_adapter *adapter, struct btp_ase *ase);
