/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen
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
#include "src/shared/uinput.h"


#define DBG(uinput, fmt, arg...) \
	uinput_debug(uinput->debug_func, uinput->debug_data, "%s:%s() " fmt, \
						__FILE__, __func__, ## arg)

struct bt_uinput {
	struct input_id dev_id;
	char name[UINPUT_MAX_NAME_SIZE];
	bdaddr_t addr;
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

static int uinput_emit(struct bt_uinput *uinput, uint16_t type, uint16_t code,
								int32_t val)
{
	struct input_event ie;

	memset(&ie, 0, sizeof(ie));

	ie.type = type;
	ie.code = code;
	ie.value = val;

	return write(uinput->fd, &ie, sizeof(ie));
}

void bt_uinput_send_key(struct bt_uinput *uinput, uint16_t key, bool pressed)
{
	if (!uinput)
		return;

	DBG(uinput, "%d", key);

	uinput_emit(uinput, EV_KEY, key, pressed ? 1 : 0);
	uinput_emit(uinput, EV_SYN, SYN_REPORT, 0);
}

struct bt_uinput *bt_uinput_new(const char *name, const char *suffix,
				const bdaddr_t *addr,
				const struct input_id *dev_id)
{
	struct bt_uinput *uinput;
	const size_t name_max = sizeof(uinput->name);

	uinput = new0(struct bt_uinput, 1);
	uinput->fd = -1;

	if (name)
		snprintf(uinput->name, name_max, "%s", name);

	if (suffix) {
		size_t name_len = strlen(uinput->name);
		size_t suffix_len = strlen(suffix);
		size_t pos = name_len;

		if (suffix_len > name_max - 1)
			suffix_len = name_max - 1;
		if (pos + suffix_len > name_max - 1)
			pos = name_max - 1 - suffix_len;

		snprintf(uinput->name + pos, name_max - pos, "%s", suffix);
	}

	if (addr)
		bacpy(&uinput->addr, addr);

	if (dev_id) {
		uinput->dev_id.bustype = dev_id->bustype;
		uinput->dev_id.product = dev_id->product;
		uinput->dev_id.vendor = dev_id->vendor;
		uinput->dev_id.version = dev_id->version;
	} else {
		uinput->dev_id.bustype = BUS_BLUETOOTH;
	}

	return uinput;
}

void bt_uinput_set_debug(struct bt_uinput *uinput,
					bt_uinput_debug_func_t debug_func,
					void *user_data)
{
	if (!uinput)
		return;

	uinput->debug_func = debug_func;
	uinput->debug_data = user_data;
}

int bt_uinput_create(struct bt_uinput *uinput,
					const struct bt_uinput_key_map *key_map)
{
	int fd = -1;
	struct uinput_user_dev dev;
	size_t i;
	int err;
	char addr[18];

	if (!uinput || uinput->fd >= 0)
		return -EINVAL;

	fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/dev/misc/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		err = -errno;
		DBG(uinput, "Failed to open /dev/uinput: %s", strerror(-err));
		goto fail;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);
	for (i = 0; key_map[i].name; ++i)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	ba2strlc(&uinput->addr, addr);
	ioctl(fd, UI_SET_PHYS, addr);

	memset(&dev, 0, sizeof(dev));
	dev.id = uinput->dev_id;
	snprintf(dev.name, sizeof(dev.name), "%s", uinput->name);

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = -errno;
		DBG(uinput, "Failed to write setup: %s", strerror(-err));
		goto fail;
	}

	if (ioctl(fd, UI_DEV_CREATE) < 0) {
		err = -errno;
		DBG(uinput, "Failed to create device: %s", strerror(-err));
		goto fail;
	}

	DBG(uinput, "%p", uinput);

	uinput->fd = fd;
	return 0;

fail:
	if (fd >= 0)
		close(fd);
	return err;
}

void bt_uinput_destroy(struct bt_uinput *uinput)
{
	if (!uinput)
		return;

	DBG(uinput, "%p", uinput);

	if (uinput->fd >= 0) {
		ioctl(uinput->fd, UI_DEV_DESTROY);
		close(uinput->fd);
	}

	free(uinput);
}
