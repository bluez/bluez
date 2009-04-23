/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "hcid.h"
#include "plugin.h"
#include "logging.h"


static int init_all_devices(int ctl)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	dl = g_try_malloc0(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
	if (!dl) {
		info("Can't allocate devlist buffer: %s (%d)",
							strerror(errno), errno);
		return errno;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void *) dl) < 0) {
		info("Can't get device list: %s (%d)",
							strerror(errno), errno);
		return errno;
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		gboolean devup;

		device_event(HCI_DEV_REG, dr->dev_id);

		devup = hci_test_bit(HCI_UP, &dr->dev_opt);
		if (devup)
			device_event(HCI_DEV_UP, dr->dev_id);
	}

	g_free(dl);
	return 0;
}

static gboolean io_stack_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	evt_si_device *sd;
	hci_event_hdr *eh;
	int type;
	size_t len;
	GIOError err;

	ptr = buf;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		error("Read from control socket failed: %s (%d)",
							strerror(errno), errno);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	if (eh->evt != EVT_STACK_INTERNAL)
		return TRUE;

	ptr += HCI_EVENT_HDR_SIZE;

	si = (evt_stack_internal *) ptr;
	switch (si->type) {
	case EVT_SI_DEVICE:
		sd = (void *) &si->data;
		device_event(sd->event, sd->dev_id);
		break;
	}

	return TRUE;
}

static int hciops_init(void)
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	GIOChannel *ctl_io;
	int sock;

	/* Create and bind HCI socket */
	sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sock < 0) {
		error("Can't open HCI socket: %s (%d)", strerror(errno),
								errno);
		return errno;
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt,
							sizeof(flt)) < 0) {
		error("Can't set filter: %s (%d)", strerror(errno), errno);
		return errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(sock, (struct sockaddr *) &addr,
							sizeof(addr)) < 0) {
		error("Can't bind HCI socket: %s (%d)",
							strerror(errno), errno);
		return errno;
	}

	ctl_io = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(ctl_io, TRUE);

	g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	g_io_channel_unref(ctl_io);

	/* Initialize already connected devices */
	return init_all_devices(sock);
}

static void hciops_exit(void)
{
}

BLUETOOTH_PLUGIN_DEFINE(hciops, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, hciops_init, hciops_exit)
