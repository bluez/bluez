/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>

#include "display.h"
#include "packet.h"
#include "vendor.h"
#include "msft.h"

static void msft_cmd(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static void msft_rsp(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static const struct vendor_ocf vendor_ocf_entry = {
	0x000, "Extension", msft_cmd, 1, false, msft_rsp, 1, false
};

const struct vendor_ocf *msft_vendor_ocf(void)
{
	return &vendor_ocf_entry;
}

static void msft_evt(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static const struct vendor_evt vendor_evt_entry = {
	0x00, "Extension", msft_evt, 1, false
};

const struct vendor_evt *msft_vendor_evt(void)
{
	return &vendor_evt_entry;
}
