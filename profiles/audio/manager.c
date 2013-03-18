/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <btio/btio.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "glib-helper.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "../src/profile.h"

#include "log.h"
#include "device.h"
#include "error.h"
#include "avdtp.h"
#include "media.h"
#include "a2dp.h"
#include "sink.h"
#include "source.h"
#include "avrcp.h"
#include "control.h"
#include "manager.h"
#include "sdpd.h"

static GKeyFile *config = NULL;
static GSList *devices = NULL;

static struct audio_device *get_audio_dev(struct btd_device *device)
{
	return manager_get_audio_device(device, TRUE);
}

static struct audio_device *manager_find_device(struct btd_device *device)
{
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;

		if (dev->btd_dev == device)
			return dev;
	}

	return NULL;
}

static void audio_remove(struct btd_profile *p, struct btd_device *device)
{
	struct audio_device *dev;

	dev = manager_find_device(device);
	if (dev == NULL)
		return;

	devices = g_slist_remove(devices, dev);
	audio_device_unregister(dev);
}

static int a2dp_source_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	struct audio_device *audio_dev;

	audio_dev = get_audio_dev(device);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	audio_dev->source = source_init(audio_dev);

	return 0;
}

static int a2dp_sink_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	struct audio_device *audio_dev;

	audio_dev = get_audio_dev(device);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	audio_dev->sink = sink_init(audio_dev);

	return 0;
}

static int avrcp_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	struct audio_device *audio_dev;

	audio_dev = get_audio_dev(device);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	if (audio_dev->control)
		control_update(audio_dev->control, uuids);
	else
		audio_dev->control = control_init(audio_dev, uuids);

	if (audio_dev->sink && sink_is_active(audio_dev))
		avrcp_connect(audio_dev);

	return 0;
}

static int a2dp_source_connect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return source_connect(audio_dev);
}

static int a2dp_source_disconnect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return source_disconnect(audio_dev, FALSE);
}

static int a2dp_sink_connect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return sink_connect(audio_dev);
}

static int a2dp_sink_disconnect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return sink_disconnect(audio_dev, FALSE);
}

static int avrcp_target_connect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return control_connect(audio_dev);
}

static int avrcp_target_disconnect(struct btd_device *dev,
						struct btd_profile *profile)
{
	const char *path = device_get_path(dev);
	struct audio_device *audio_dev;

	DBG("path %s", path);

	audio_dev = get_audio_dev(dev);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	return control_disconnect(audio_dev);
}

static int a2dp_source_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	return a2dp_source_register(adapter, config);
}

static void a2dp_source_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	a2dp_source_unregister(adapter);
}

static int a2dp_sink_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	return a2dp_sink_register(adapter, config);
}

static void a2dp_sink_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	a2dp_sink_unregister(adapter);
}

static int avrcp_target_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	return avrcp_target_register(adapter, config);
}

static int avrcp_remote_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	return avrcp_remote_register(adapter, config);
}

static void avrcp_target_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	avrcp_target_unregister(adapter);
}

static void avrcp_remote_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	avrcp_remote_unregister(adapter);
}

static int media_server_probe(struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	return media_register(adapter);
}

static void media_server_remove(struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	media_unregister(adapter);
}

static struct btd_profile a2dp_source_profile = {
	.name		= "audio-source",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,

	.remote_uuid	= A2DP_SOURCE_UUID,
	.device_probe	= a2dp_source_probe,
	.device_remove	= audio_remove,

	.auto_connect	= true,
	.connect	= a2dp_source_connect,
	.disconnect	= a2dp_source_disconnect,

	.adapter_probe	= a2dp_sink_server_probe,
	.adapter_remove	= a2dp_sink_server_remove,
};

static struct btd_profile a2dp_sink_profile = {
	.name		= "audio-sink",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,

	.remote_uuid	= A2DP_SINK_UUID,
	.device_probe	= a2dp_sink_probe,
	.device_remove	= audio_remove,

	.auto_connect	= true,
	.connect	= a2dp_sink_connect,
	.disconnect	= a2dp_sink_disconnect,

	.adapter_probe	= a2dp_source_server_probe,
	.adapter_remove	= a2dp_source_server_remove,
};

static struct btd_profile avrcp_target_profile = {
	.name		= "audio-avrcp-target",

	.remote_uuid	= AVRCP_TARGET_UUID,
	.device_probe	= avrcp_probe,
	.device_remove	= audio_remove,

	.auto_connect	= true,
	.connect	= avrcp_target_connect,
	.disconnect	= avrcp_target_disconnect,

	.adapter_probe	= avrcp_target_server_probe,
	.adapter_remove = avrcp_target_server_remove,
};

static struct btd_profile avrcp_remote_profile = {
	.name		= "audio-avrcp-control",

	.remote_uuid	= AVRCP_REMOTE_UUID,
	.device_probe	= avrcp_probe,
	.device_remove	= audio_remove,

	.adapter_probe	= avrcp_remote_server_probe,
	.adapter_remove = avrcp_remote_server_remove,
};

static struct btd_adapter_driver media_driver = {
	.name	= "media",
	.probe	= media_server_probe,
	.remove	= media_server_remove,
};

void audio_sink_connected(struct btd_device *dev, int err)
{
	device_profile_connected(dev, &a2dp_sink_profile, err);
}

void audio_sink_disconnected(struct btd_device *dev, int err)
{
	device_profile_disconnected(dev, &a2dp_sink_profile, err);
}

void audio_source_connected(struct btd_device *dev, int err)
{
	device_profile_connected(dev, &a2dp_source_profile, err);
}

void audio_source_disconnected(struct btd_device *dev, int err)
{
	device_profile_disconnected(dev, &a2dp_source_profile, err);
}

void audio_target_connected(struct btd_device *dev, int err)
{
	device_profile_connected(dev, &avrcp_target_profile, err);
}

void audio_target_disconnected(struct btd_device *dev, int err)
{
	device_profile_disconnected(dev, &avrcp_target_profile, err);
}

void audio_controller_connected(struct btd_device *dev, int err)
{
	device_profile_connected(dev, &avrcp_remote_profile, err);
}

void audio_controller_disconnected(struct btd_device *dev, int err)
{
	device_profile_disconnected(dev, &avrcp_remote_profile, err);
}

int audio_manager_init(GKeyFile *conf)
{
	if (conf)
		config = conf;

	btd_profile_register(&a2dp_source_profile);
	btd_profile_register(&a2dp_sink_profile);
	btd_profile_register(&avrcp_remote_profile);
	btd_profile_register(&avrcp_target_profile);

	btd_register_adapter_driver(&media_driver);

	return 0;
}

void audio_manager_exit(void)
{
	if (config) {
		g_key_file_free(config);
		config = NULL;
	}

	btd_profile_unregister(&a2dp_source_profile);
	btd_profile_unregister(&a2dp_sink_profile);
	btd_profile_unregister(&avrcp_remote_profile);
	btd_profile_unregister(&avrcp_target_profile);

	btd_unregister_adapter_driver(&media_driver);
}

struct audio_device *manager_get_audio_device(struct btd_device *device,
							gboolean create)
{
	struct audio_device *dev;

	dev = manager_find_device(device);
	if (dev)
		return dev;

	if (!create)
		return NULL;

	dev = audio_device_register(device);
	if (!dev)
		return NULL;

	devices = g_slist_append(devices, dev);

	return dev;
}

static void set_fast_connectable(struct btd_adapter *adapter,
							gpointer user_data)
{
	gboolean enable = GPOINTER_TO_UINT(user_data);

	if (btd_adapter_set_fast_connectable(adapter, enable))
		error("Changing fast connectable for hci%d failed",
					btd_adapter_get_index(adapter));
}

void manager_set_fast_connectable(gboolean enable)
{
	adapter_foreach(set_fast_connectable, GUINT_TO_POINTER(enable));
}
