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
#include <stdio.h>
#include <stdarg.h>
#include <linux/uinput.h>

#include "bluetooth/bluetooth.h"

#include "src/shared/util.h"
#include "src/shared/uinput-util.h"


#define DBG(uinput, fmt, arg...) \
	uinput_debug(uinput->debug_func, uinput->debug_data, "%s:%s() " fmt, \
						__FILE__, __func__, ## arg)

struct bt_uinput {
	int fd;
	bt_uinput_debug_func_t debug_func;
	void *debug_data;
};

static void uinput_debug(bt_uinput_debug_func_t debug_func, void *debug_data,
							const char *format, ...)
{
	va_list ap;

	if (!debug_func || !format)
		return;

	va_start(ap, format);
	util_debug_va(debug_func, debug_data, format, ap);
	va_end(ap);
}

static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct input_event event;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	return write(fd, &event, sizeof(event));
}

void bt_uinput_send_key(struct bt_uinput *uinput, uint16_t key, bool pressed)
{
	if (!uinput)
		return;

	DBG(uinput, "%d", key);

	send_event(uinput->fd, EV_KEY, key, pressed ? 1 : 0);
	send_event(uinput->fd, EV_SYN, SYN_REPORT, 0);
}

struct bt_uinput *bt_uinput_new(const char *name, const char *suffix,
					const bdaddr_t *addr,
					const struct input_id *dev_id,
					const struct bt_uinput_key_map *key_map,
					bt_uinput_debug_func_t debug,
					void *user_data)
{
	struct bt_uinput *uinput;
	struct uinput_user_dev dev;
	int fd, err, i;
	char src[18];

	uinput = new0(struct bt_uinput, 1);
	uinput->debug_func = debug;
	uinput->debug_data = user_data;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = errno;
				DBG(uinput, "Can't open input device: %s (%d)",
							strerror(err), err);
				free(uinput);
				errno = err;
				return NULL;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));

	if (name)
		snprintf(dev.name, UINPUT_MAX_NAME_SIZE, "%s", name);

	if (suffix) {
		int len, slen;

		len = strlen(dev.name);
		slen = strlen(suffix);

		/* If name + suffix don't fit, truncate the name, then add the
		 * suffix.
		 */
		if (slen >= UINPUT_MAX_NAME_SIZE)
			slen = UINPUT_MAX_NAME_SIZE - 1;
		if (len > UINPUT_MAX_NAME_SIZE - slen - 1)
			len = UINPUT_MAX_NAME_SIZE - slen - 1;

		snprintf(dev.name + len, UINPUT_MAX_NAME_SIZE - len,
								"%s", suffix);
	}

	if (dev_id) {
		dev.id.bustype = dev_id->bustype;
		dev.id.vendor = dev_id->vendor;
		dev.id.product = dev_id->product;
		dev.id.version = dev_id->version;
	} else {
		dev.id.bustype = BUS_VIRTUAL;
	}

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = errno;
		DBG(uinput, "Can't write device information: %s (%d)",
							strerror(err), err);
		close(fd);
		free(uinput);
		errno = err;
		return NULL;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	ba2strlc(addr, src);
	ioctl(fd, UI_SET_PHYS, src);

	for (i = 0; key_map[i].name != NULL; i++)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = errno;
		DBG(uinput, "Can't create uinput device: %s (%d)",
							strerror(err), err);
		close(fd);
		free(uinput);
		errno = err;
		return NULL;
	}

	send_event(fd, EV_REP, REP_DELAY, 300);

	DBG(uinput, "%p", uinput);

	uinput->fd = fd;
	return uinput;
}

void bt_uinput_destroy(struct bt_uinput *uinput)
{
	if (!uinput)
		return;

	DBG(uinput, "%p", uinput);

	ioctl(uinput->fd, UI_DEV_DESTROY);
	close(uinput->fd);
	free(uinput);
}
