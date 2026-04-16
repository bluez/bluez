// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Collabora Ltd.
 *
 */

bool bap_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client);
void bap_unregister_service(struct btp *btp);
bool bap_is_service_registered(void);
