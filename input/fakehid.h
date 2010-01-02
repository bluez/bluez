/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

struct fake_hid;
struct fake_input;

struct fake_hid {
	uint16_t vendor;
	uint16_t product;
	gboolean (*connect) (struct fake_input *fake_input, GError **err);
	int (*disconnect) (struct fake_input *fake_input);
	gboolean (*event) (GIOChannel *chan, GIOCondition cond, gpointer data);
	int (*setup_uinput) (struct fake_input *fake, struct fake_hid *fake_hid);
};

struct fake_hid *get_fake_hid(uint16_t vendor, uint16_t product);

int fake_hid_connadd(struct fake_input *fake, GIOChannel *intr_io,
						struct fake_hid *fake_hid);
