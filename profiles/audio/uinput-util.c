// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <linux/uinput.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"

#include "uinput-util.h"


static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct input_event event;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	return write(fd, &event, sizeof(event));
}

void uinput_send_key(int fd, uint16_t key, int pressed)
{
	if (fd < 0)
		return;

	send_event(fd, EV_KEY, key, pressed);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

int uinput_create(struct btd_adapter *adapter, struct btd_device *device,
					const char *name, const char *suffix,
					const struct uinput_key_map *key_map)
{
	struct uinput_user_dev dev;
	int fd, err, i;
	char src[18];

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = -errno;
				error("Can't open input device: %s (%d)",
							strerror(-err), -err);
				return err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));

	if (name) {
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);
		dev.name[UINPUT_MAX_NAME_SIZE - 1] = '\0';
	}

	if (suffix) {
		int len, slen;

		len = strlen(dev.name);
		slen = strlen(suffix);

		/* If name + suffix don't fit, truncate the name, then add the
		 * suffix.
		 */
		if (len + slen < UINPUT_MAX_NAME_SIZE - 1) {
			strcpy(dev.name + len, suffix);
		} else {
			if (slen >= UINPUT_MAX_NAME_SIZE)
				slen = UINPUT_MAX_NAME_SIZE - 1;
			len = UINPUT_MAX_NAME_SIZE - slen - 1;
			strncpy(dev.name + len, suffix, slen);
			dev.name[UINPUT_MAX_NAME_SIZE - 1] = '\0';
		}
	}

	if (device) {
		dev.id.bustype = BUS_BLUETOOTH;
		dev.id.vendor  = btd_device_get_vendor(device);
		dev.id.product = btd_device_get_product(device);
		dev.id.version = btd_device_get_version(device);
	} else {
		dev.id.bustype = BUS_VIRTUAL;
		dev.id.vendor  = 0;
		dev.id.product = 0;
		dev.id.version = 0;
	}

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = -errno;
		error("Can't write device information: %s (%d)",
						strerror(-err), -err);
		close(fd);
		return err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	ba2strlc(btd_adapter_get_address(adapter), src);
	ioctl(fd, UI_SET_PHYS, src);

	for (i = 0; key_map[i].name != NULL; i++)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = -errno;
		error("Can't create uinput device: %s (%d)",
						strerror(-err), -err);
		close(fd);
		return err;
	}

	send_event(fd, EV_REP, REP_DELAY, 300);

	return fd;
}
