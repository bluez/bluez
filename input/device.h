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

#define L2CAP_PSM_HIDP_CTRL	0x11
#define L2CAP_PSM_HIDP_INTR	0x13

struct device;

struct fake_input {
	int		flags;
	GIOChannel	*io;
	int		uinput;		/* uinput socket */
	int		rfcomm;		/* RFCOMM socket */
	uint8_t		ch;		/* RFCOMM channel number */
	gboolean 	(*connect) (struct device *dev);
	int		(*disconnect) (struct device *dev);
	void		*priv;
};

int input_device_register(DBusConnection *conn, bdaddr_t *src, bdaddr_t *dst,
			struct hidp_connadd_req *hidp, const char **ppath);
int fake_input_register(DBusConnection *conn, bdaddr_t *src,
			bdaddr_t *dst, uint8_t ch, const char **ppath);
int input_device_unregister(DBusConnection *conn, const char *path);

gboolean input_device_is_registered(bdaddr_t *src, bdaddr_t *dst);

int input_device_set_channel(const bdaddr_t *src, const bdaddr_t *dst, int psm, int nsk);
int input_device_close_channels(const bdaddr_t *src, const bdaddr_t *dst);
int input_device_connadd(bdaddr_t *src, bdaddr_t *dst);
