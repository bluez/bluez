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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "../src/adapter.h"
#include "../src/device.h"

#include "log.h"
#include "device.h"
#include "fakehid.h"
#include "uinput.h"

#define PS3_FLAGS_MASK 0xFFFFFF00

enum ps3remote_special_keys {
	PS3R_BIT_PS = 0,
	PS3R_BIT_ENTER = 3,
	PS3R_BIT_L2 = 8,
	PS3R_BIT_R2 = 9,
	PS3R_BIT_L1 = 10,
	PS3R_BIT_R1 = 11,
	PS3R_BIT_TRIANGLE = 12,
	PS3R_BIT_CIRCLE = 13,
	PS3R_BIT_CROSS = 14,
	PS3R_BIT_SQUARE = 15,
	PS3R_BIT_SELECT = 16,
	PS3R_BIT_L3 = 17,
	PS3R_BIT_R3 = 18,
	PS3R_BIT_START = 19,
	PS3R_BIT_UP = 20,
	PS3R_BIT_RIGHT = 21,
	PS3R_BIT_DOWN = 22,
	PS3R_BIT_LEFT = 23,
};

static unsigned int ps3remote_bits[] = {
	[PS3R_BIT_ENTER] = 0x0b,
	[PS3R_BIT_PS] = 0x43,
	[PS3R_BIT_SQUARE] = 0x5f,
	[PS3R_BIT_CROSS] = 0x5e,
	[PS3R_BIT_CIRCLE] = 0x5d,
	[PS3R_BIT_TRIANGLE] = 0x5c,
	[PS3R_BIT_R1] = 0x5b,
	[PS3R_BIT_L1] = 0x5a,
	[PS3R_BIT_R2] = 0x59,
	[PS3R_BIT_L2] = 0x58,
	[PS3R_BIT_LEFT] = 0x57,
	[PS3R_BIT_DOWN] = 0x56,
	[PS3R_BIT_RIGHT] = 0x55,
	[PS3R_BIT_UP] = 0x54,
	[PS3R_BIT_START] = 0x53,
	[PS3R_BIT_R3] = 0x52,
	[PS3R_BIT_L3] = 0x51,
	[PS3R_BIT_SELECT] = 0x50,
};

static unsigned int ps3remote_keymap[] = {
	[0x16] = KEY_EJECTCD,
	[0x64] = KEY_AUDIO,
	[0x65] = KEY_ANGLE,
	[0x63] = KEY_SUBTITLE,
	[0x0f] = KEY_CLEAR,
	[0x28] = KEY_TIME,
	[0x00] = KEY_1,
	[0x01] = KEY_2,
	[0x02] = KEY_3,
	[0x03] = KEY_4,
	[0x04] = KEY_5,
	[0x05] = KEY_6,
	[0x06] = KEY_7,
	[0x07] = KEY_8,
	[0x08] = KEY_9,
	[0x09] = KEY_0,
	[0x81] = KEY_RED,
	[0x82] = KEY_GREEN,
	[0x80] = KEY_BLUE,
	[0x83] = KEY_YELLOW,
	[0x70] = KEY_INFO,		/* display */
	[0x1a] = KEY_MENU,		/* top menu */
	[0x40] = KEY_CONTEXT_MENU,	/* pop up/menu */
	[0x0e] = KEY_ESC,		/* return */
	[0x5c] = KEY_OPTION,		/* options/triangle */
	[0x5d] = KEY_BACK,		/* back/circle */
	[0x5f] = KEY_SCREEN,		/* view/square */
	[0x5e] = BTN_0,			/* cross */
	[0x54] = KEY_UP,
	[0x56] = KEY_DOWN,
	[0x57] = KEY_LEFT,
	[0x55] = KEY_RIGHT,
	[0x0b] = KEY_ENTER,
	[0x5a] = BTN_TL,		/* L1 */
	[0x58] = BTN_TL2,		/* L2 */
	[0x51] = BTN_THUMBL,		/* L3 */
	[0x5b] = BTN_TR,		/* R1 */
	[0x59] = BTN_TR2,		/* R2 */
	[0x52] = BTN_THUMBR,		/* R3 */
	[0x43] = KEY_HOMEPAGE,		/* PS button */
	[0x50] = KEY_SELECT,
	[0x53] = BTN_START,
	[0x33] = KEY_REWIND,		/* scan back */
	[0x32] = KEY_PLAY,
	[0x34] = KEY_FORWARD,		/* scan forward */
	[0x30] = KEY_PREVIOUS,
	[0x38] = KEY_STOP,
	[0x31] = KEY_NEXT,
	[0x60] = KEY_FRAMEBACK,		/* slow/step back */
	[0x39] = KEY_PAUSE,
	[0x61] = KEY_FRAMEFORWARD,	/* slow/step forward */
	[0xff] = KEY_MAX,
};

static int ps3remote_decode(char *buff, int size, unsigned int *value)
{
	static unsigned int lastkey = 0;
	static unsigned int lastmask = 0;
	unsigned int i, mask;
	int retval;
	guint8 key;

	if (size < 12) {
		error("Got a shorter packet! (size %i)\n", size);
		return KEY_RESERVED;
	}

	mask = (buff[2] << 16) + (buff[3] << 8) + buff[4];
	key = buff[5];

	/* first, check flags */
	for (i = 0; i < 24; i++) {
		if ((lastmask & (1 << i)) == (mask & (1 << i)))
			continue;
		if (ps3remote_bits[i] == 0)
			goto error;
		retval = ps3remote_keymap[ps3remote_bits[i]];
		if (mask & (1 << i))
			/* key pressed */
			*value = 1;
		else
			/* key released */
			*value = 0;

		goto out;
	}

	*value = buff[11];
	if (buff[11] == 1) {
		retval = ps3remote_keymap[key];
	} else
		retval = lastkey;

	if (retval == KEY_RESERVED)
		goto error;
	if (retval == KEY_MAX)
		return retval;

	lastkey = retval;

out:
	fflush(stdout);

	lastmask = mask;

	return retval;

error:
	error("ps3remote: unrecognized sequence [%#x][%#x][%#x][%#x] [%#x],"
			"last: [%#x][%#x][%#x][%#x]",
			buff[2], buff[3], buff[4], buff[5], buff[11],
				lastmask >> 16, lastmask >> 8 & 0xff,
						lastmask & 0xff, lastkey);
	return -1;
}

static gboolean ps3remote_event(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct fake_input *fake = data;
	struct uinput_event event;
	unsigned int key, value = 0;
	ssize_t size;
	char buff[50];
	int fd;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		goto failed;
	}

	fd = g_io_channel_unix_get_fd(chan);

	memset(buff, 0, sizeof(buff));
	size = read(fd, buff, sizeof(buff));
	if (size < 0) {
		error("IO Channel read error");
		goto failed;
	}

	key = ps3remote_decode(buff, size, &value);
	if (key == KEY_RESERVED) {
		error("Got invalid key from decode");
		goto failed;
	} else if (key == KEY_MAX)
		return TRUE;

	memset(&event, 0, sizeof(event));
	gettimeofday(&event.time, NULL);
	event.type = EV_KEY;
	event.code = key;
	event.value = value;
	if (write(fake->uinput, &event, sizeof(event)) != sizeof(event)) {
		error("Error writing to uinput device");
		goto failed;
	}

	memset(&event, 0, sizeof(event));
	gettimeofday(&event.time, NULL);
	event.type = EV_SYN;
	event.code = SYN_REPORT;
	if (write(fake->uinput, &event, sizeof(event)) != sizeof(event)) {
		error("Error writing to uinput device");
		goto failed;
	}

	return TRUE;

failed:
	ioctl(fake->uinput, UI_DEV_DESTROY);
	close(fake->uinput);
	fake->uinput = -1;
	g_io_channel_unref(fake->io);

	return FALSE;
}

static int ps3remote_setup_uinput(struct fake_input *fake,
						struct fake_hid *fake_hid)
{
	struct uinput_dev dev;
	int i;

	fake->uinput = open("/dev/input/uinput", O_RDWR);
	if (fake->uinput < 0) {
		fake->uinput = open("/dev/uinput", O_RDWR);
		if (fake->uinput < 0) {
			fake->uinput = open("/dev/misc/uinput", O_RDWR);
			if (fake->uinput < 0) {
				error("Error opening uinput device file");
				return 1;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	snprintf(dev.name, sizeof(dev.name), "%s", "PS3 Remote Controller");
	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor = fake_hid->vendor;
	dev.id.product = fake_hid->product;

	if (write(fake->uinput, &dev, sizeof(dev)) != sizeof(dev)) {
		error("Error creating uinput device");
		goto err;
	}

	/* enabling key events */
	if (ioctl(fake->uinput, UI_SET_EVBIT, EV_KEY) < 0) {
		error("Error enabling uinput device key events");
		goto err;
	}

	/* enabling keys */
	for (i = 0; i < 256; i++)
		if (ps3remote_keymap[i] != KEY_RESERVED)
			if (ioctl(fake->uinput, UI_SET_KEYBIT,
						ps3remote_keymap[i]) < 0) {
				error("Error enabling uinput key %i",
							ps3remote_keymap[i]);
				goto err;
			}

	/* creating the device */
	if (ioctl(fake->uinput, UI_DEV_CREATE) < 0) {
		error("Error creating uinput device");
		goto err;
	}

	return 0;

err:
	close(fake->uinput);
	return 1;
}

static gboolean fake_hid_common_connect(struct fake_input *fake, GError **err)
{
	return TRUE;
}

static int fake_hid_common_disconnect(struct fake_input *fake)
{
	return 0;
}

static struct fake_hid fake_hid_table[] = {
	/* Sony PS3 remote device */
	{
		.vendor		= 0x054c,
		.product	= 0x0306,
		.connect	= fake_hid_common_connect,
		.disconnect	= fake_hid_common_disconnect,
		.event		= ps3remote_event,
		.setup_uinput	= ps3remote_setup_uinput,
		.devices	= NULL,
	},

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

struct fake_input *fake_hid_connadd(struct fake_input *fake,
						GIOChannel *intr_io,
						struct fake_hid *fake_hid)
{
	GList *l;
	struct fake_input *old = NULL;

	/* Look for an already setup device */
	for (l = fake_hid->devices; l != NULL; l = l->next) {
		old = l->data;
		if (old->idev == fake->idev) {
			g_free(fake);
			fake = old;
			fake_hid->connect(fake, NULL);
			break;
		}
		old = NULL;
	}

	/* New device? Add it to the list of known devices,
	 * and create the uinput necessary */
	if (old == NULL) {
		if (fake_hid->setup_uinput(fake, fake_hid)) {
			error("Error setting up uinput");
			g_free(fake);
			return NULL;
		}
		fake_hid->devices = g_list_append(fake_hid->devices, fake);
	}

	fake->io = g_io_channel_ref(intr_io);
	g_io_channel_set_close_on_unref(fake->io, TRUE);
	g_io_add_watch(fake->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) fake_hid->event, fake);

	return fake;
}
