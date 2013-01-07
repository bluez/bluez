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

int mgmt_create_bonding(int index, const bdaddr_t *bdaddr, uint8_t addr_type,
							uint8_t io_cap);
int mgmt_cancel_bonding(int index, const bdaddr_t *bdaddr, uint8_t addr_type);

int mgmt_pincode_reply(int index, const bdaddr_t *bdaddr, const char *pin,
								size_t pin_len);
int mgmt_confirm_reply(int index, const bdaddr_t *bdaddr, uint8_t bdaddr_type,
							gboolean success);
int mgmt_passkey_reply(int index, const bdaddr_t *bdaddr, uint8_t bdaddr_type,
							uint32_t passkey);
