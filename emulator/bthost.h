/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>

typedef void (*bthost_send_func) (const void *data, uint16_t len,
							void *user_data);

struct bthost;

struct bthost *bthost_create(void);
void bthost_destroy(struct bthost *bthost);

void bthost_set_send_handler(struct bthost *bthost, bthost_send_func handler,
							void *user_data);

void bthost_receive_h4(struct bthost *bthost, const void *data, uint16_t len);

void bthost_start(struct bthost *bthost);
void bthost_stop(struct bthost *bthost);
