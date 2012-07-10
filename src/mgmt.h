/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
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

int mgmt_setup(void);
void mgmt_cleanup(void);

int mgmt_set_powered(int index, gboolean powered);
int mgmt_set_discoverable(int index, gboolean discoverable, uint16_t timeout);
int mgmt_set_pairable(int index, gboolean pairable);
int mgmt_set_name(int index, const char *name);
int mgmt_set_dev_class(int index, uint8_t major, uint8_t minor);
int mgmt_set_fast_connectable(int index, gboolean enable);

int mgmt_start_discovery(int index);
int mgmt_stop_discovery(int index);

int mgmt_read_clock(int index, bdaddr_t *bdaddr, int which, int timeout,
					uint32_t *clock, uint16_t *accuracy);
int mgmt_read_bdaddr(int index, bdaddr_t *bdaddr);

int mgmt_block_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type);
int mgmt_unblock_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type);

int mgmt_get_conn_list(int index, GSList **conns);

int mgmt_disconnect(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type);

int mgmt_unpair_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type);

int mgmt_add_uuid(int index, uuid_t *uuid, uint8_t svc_hint);
int mgmt_remove_uuid(int index, uuid_t *uuid);

int mgmt_set_did(int index, uint16_t vendor, uint16_t product,
					uint16_t version, uint16_t source);

int mgmt_load_link_keys(int index, GSList *keys, gboolean debug_keys);
int mgmt_load_ltks(int index, GSList *keys);

int mgmt_set_io_capability(int index, uint8_t io_capability);

int mgmt_create_bonding(int index, bdaddr_t *bdaddr, uint8_t addr_type,
							uint8_t io_cap);
int mgmt_cancel_bonding(int index, bdaddr_t *bdaddr);

int mgmt_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin,
								size_t pin_len);
int mgmt_confirm_reply(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							gboolean success);
int mgmt_passkey_reply(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							uint32_t passkey);

int mgmt_read_local_oob_data(int index);

int mgmt_add_remote_oob_data(int index, bdaddr_t *bdaddr,
					uint8_t *hash, uint8_t *randomizer);
int mgmt_remove_remote_oob_data(int index, bdaddr_t *bdaddr);

int mgmt_confirm_name(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							gboolean name_known);
