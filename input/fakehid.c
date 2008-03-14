/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>
#include <bluetooth/l2cap.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "logging.h"
#include "device.h"
#include "fakehid.h"

static struct fake_hid fake_hid_table[] = {
	{ },
};

static inline int fake_hid_match_device(uint16_t vendor, uint16_t product,
							struct fake_hid *fhid)
{
	return vendor == fhid->vendor && product == fhid->product;
}

struct fake_hid *get_fake_hid(uint16_t vendor, uint16_t product)
{
	int i;

	for (i = 0; fake_hid_table[i].vendor != 0; i++)
		if (fake_hid_match_device(vendor, product, &fake_hid_table[i]))
			return &fake_hid_table[i];

	return NULL;
}

int fake_hid_connadd(struct fake_input *fake, int intr_sk,
						struct fake_hid *fake_hid)
{
	if (fake_hid->setup_uinput(fake, fake_hid)) {
		error("Error setting up uinput");
		return ENOMEM;
	}

	fake->io = g_io_channel_unix_new(intr_sk);
	g_io_channel_set_close_on_unref(fake->io, TRUE);
	g_io_add_watch(fake->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) fake_hid->event, fake);

	return 0;
}
