/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include <stdint.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "lib/uuid.h"

#include "gdbus/gdbus.h"

#include "btio/btio.h"
#include "src/adapter.h"
#include "src/btd.h"
#include "src/dbus-common.h"
#include "src/device.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"

#include "telephony.h"

struct hfp_device {
	struct telephony	*telephony;
	uint16_t		version;
	GIOChannel		*io;
};

static void device_destroy(struct hfp_device *dev)
{
	DBG("%s", telephony_get_path(dev->telephony));

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	telephony_unregister_interface(dev->telephony);
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct hfp_device *dev = user_data;
	struct btd_service *service = telephony_get_service(dev->telephony);

	DBG("");

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	g_io_channel_set_close_on_unref(chan, FALSE);

	btd_service_connecting_complete(service, 0);

	return;

failed:
	g_io_channel_shutdown(chan, TRUE, NULL);
	device_destroy(dev);
}

struct telephony_callbacks hfp_callbacks = {
};

static int hfp_connect(struct btd_service *service)
{
	struct hfp_device *dev;
	struct btd_profile *p;
	const sdp_record_t *rec;
	sdp_list_t *list, *protos;
	sdp_profile_desc_t *desc;
	int channel;
	bdaddr_t src, dst;
	GError *err = NULL;

	DBG("");

	dev = btd_service_get_user_data(service);

	p = btd_service_get_profile(service);
	rec = btd_device_get_record(telephony_get_device(dev->telephony),
					p->remote_uuid);
	if (!rec)
		return -EIO;

	if (sdp_get_profile_descs(rec, &list) == 0) {
		desc = list->data;
		dev->version = desc->version;
	}
	sdp_list_free(list, free);

	if (sdp_get_access_protos(rec, &protos) < 0) {
		error("unable to get access protocols from record");
		return -EIO;
	}

	channel = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (channel <= 0) {
		error("unable to get RFCOMM channel from record");
		return -EIO;
	}

	src = telephony_get_src(dev->telephony);
	dst = telephony_get_dst(dev->telephony);
	dev->io = bt_io_connect(connect_cb, dev,
		NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR, &src,
		BT_IO_OPT_DEST_BDADDR, &dst,
		BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
		BT_IO_OPT_CHANNEL, channel,
		BT_IO_OPT_INVALID);
	if (dev->io == NULL) {
		error("unable to start connection");
		return -EIO;
	}

	return telephony_register_interface(dev->telephony);
}

static int hfp_disconnect(struct btd_service *service)
{
	DBG("");

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int hfp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct hfp_device *dev;

	DBG("%s", path);

	dev = g_new0(struct hfp_device, 1);
	if (!dev)
		return -EINVAL;

	dev->telephony = telephony_new(service, dev, &hfp_callbacks);
	btd_service_set_user_data(service, dev);

	return 0;
}

static void hfp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct hfp_device *dev;

	DBG("%s", path);

	dev = btd_service_get_user_data(service);

	telephony_free(dev->telephony);
	g_free(dev);
}

static struct btd_profile hfp_hf_profile = {
	.name		= "hfp",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,

	.remote_uuid	= HFP_AG_UUID,
	.device_probe	= hfp_probe,
	.device_remove	= hfp_remove,

	.auto_connect	= true,
	.connect	= hfp_connect,
	.disconnect	= hfp_disconnect,

	.experimental	= true,
};

static int hfp_init(void)
{
	btd_profile_register(&hfp_hf_profile);

	return 0;
}

static void hfp_exit(void)
{
	btd_profile_unregister(&hfp_hf_profile);
}

BLUETOOTH_PLUGIN_DEFINE(hfp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
		hfp_init, hfp_exit)
