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
#include <bluetooth/uuid.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "glib-helper.h"
#include "btio.h"
#include "../src/adapter.h"
#include "../src/manager.h"
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

struct audio_adapter {
	struct btd_adapter *btd_adapter;
	gboolean powered;
	uint32_t hsp_ag_record_id;
	uint32_t hfp_ag_record_id;
	uint32_t hfp_hs_record_id;
	GIOChannel *hsp_ag_server;
	GIOChannel *hfp_ag_server;
	GIOChannel *hfp_hs_server;
	gint ref;
};

static gboolean auto_connect = TRUE;
static int max_connected_headsets = 1;
static GKeyFile *config = NULL;
static GSList *adapters = NULL;
static GSList *devices = NULL;

static struct enabled_interfaces enabled = {
	.sink		= TRUE,
	.source		= FALSE,
	.control	= TRUE,
};

static struct audio_adapter *find_adapter(GSList *list,
					struct btd_adapter *btd_adapter)
{
	for (; list; list = list->next) {
		struct audio_adapter *adapter = list->data;

		if (adapter->btd_adapter == btd_adapter)
			return adapter;
	}

	return NULL;
}

static struct audio_device *get_audio_dev(struct btd_device *device)
{
	struct btd_adapter *adapter = device_get_adapter(device);

	return manager_get_device(adapter_get_address(adapter),
					device_get_address(device), TRUE);
}

static void audio_remove(struct btd_profile *p, struct btd_device *device)
{
	struct audio_device *dev;
	const char *path;

	path = device_get_path(device);

	dev = manager_find_device(path, NULL, NULL, NULL, FALSE);
	if (dev == NULL)
		return;

	devices = g_slist_remove(devices, dev);
	audio_device_unregister(dev);
}

static int a2dp_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	struct audio_device *audio_dev;

	audio_dev = get_audio_dev(device);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	if (g_slist_find_custom(uuids, A2DP_SINK_UUID, bt_uuid_strcmp) &&
						audio_dev->sink == NULL)
		audio_dev->sink = sink_init(audio_dev);

	if (g_slist_find_custom(uuids, A2DP_SOURCE_UUID, bt_uuid_strcmp) &&
						audio_dev->source == NULL)
		audio_dev->source = source_init(audio_dev);

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

static struct audio_adapter *audio_adapter_ref(struct audio_adapter *adp)
{
	adp->ref++;

	DBG("%p: ref=%d", adp, adp->ref);

	return adp;
}

static void audio_adapter_unref(struct audio_adapter *adp)
{
	adp->ref--;

	DBG("%p: ref=%d", adp, adp->ref);

	if (adp->ref > 0)
		return;

	adapters = g_slist_remove(adapters, adp);
	btd_adapter_unref(adp->btd_adapter);
	g_free(adp);
}

static struct audio_adapter *audio_adapter_create(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = g_new0(struct audio_adapter, 1);
	adp->btd_adapter = btd_adapter_ref(adapter);

	return audio_adapter_ref(adp);
}

static struct audio_adapter *audio_adapter_get(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = find_adapter(adapters, adapter);
	if (!adp) {
		adp = audio_adapter_create(adapter);
		adapters = g_slist_append(adapters, adp);
	} else
		audio_adapter_ref(adp);

	return adp;
}

static int a2dp_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	err = a2dp_register(adapter_get_address(adapter), config);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void a2dp_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	a2dp_unregister(adapter_get_address(adapter));
	audio_adapter_unref(adp);
}

static int avrcp_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	err = avrcp_register(adapter_get_address(adapter), config);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void avrcp_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	avrcp_unregister(adapter_get_address(adapter));
	audio_adapter_unref(adp);
}

static int media_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	err = media_register(path, adapter_get_address(adapter));
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void media_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	media_unregister(path);
	audio_adapter_unref(adp);
}

static struct btd_profile a2dp_profile = {
	.name		= "audio-a2dp",

	.remote_uuids	= BTD_UUIDS(A2DP_SOURCE_UUID, A2DP_SINK_UUID,
							ADVANCED_AUDIO_UUID),
	.device_probe	= a2dp_probe,
	.device_remove	= audio_remove,

	.adapter_probe	= a2dp_server_probe,
	.adapter_remove = a2dp_server_remove,
};

static struct btd_profile avrcp_profile = {
	.name		= "audio-avrcp",

	.remote_uuids	= BTD_UUIDS(AVRCP_TARGET_UUID, AVRCP_REMOTE_UUID),
	.device_probe	= avrcp_probe,
	.device_remove	= audio_remove,

	.adapter_probe	= avrcp_server_probe,
	.adapter_remove = avrcp_server_remove,
};

static struct btd_adapter_driver media_driver = {
	.name	= "media",
	.probe	= media_server_probe,
	.remove	= media_server_remove,
};

int audio_manager_init(GKeyFile *conf)
{
	char **list;
	int i;
	gboolean b;
	GError *err = NULL;

	if (!conf)
		goto proceed;

	config = conf;

	list = g_key_file_get_string_list(config, "General", "Enable",
						NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "Sink"))
			enabled.sink = TRUE;
		else if (g_str_equal(list[i], "Source"))
			enabled.source = TRUE;
		else if (g_str_equal(list[i], "Control"))
			enabled.control = TRUE;
	}
	g_strfreev(list);

	list = g_key_file_get_string_list(config, "General", "Disable",
						NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "Sink"))
			enabled.sink = FALSE;
		else if (g_str_equal(list[i], "Source"))
			enabled.source = FALSE;
		else if (g_str_equal(list[i], "Control"))
			enabled.control = FALSE;
	}
	g_strfreev(list);

	b = g_key_file_get_boolean(config, "General", "AutoConnect", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		auto_connect = b;

	err = NULL;
	i = g_key_file_get_integer(config, "Headset", "MaxConnected",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		max_connected_headsets = i;

proceed:
	if (enabled.source || enabled.sink)
		btd_profile_register(&a2dp_profile);

	if (enabled.control)
		btd_profile_register(&avrcp_profile);

	btd_register_adapter_driver(&media_driver);

	return 0;
}

void audio_manager_exit(void)
{
	if (config) {
		g_key_file_free(config);
		config = NULL;
	}

	if (enabled.source || enabled.sink)
		btd_profile_unregister(&a2dp_profile);

	if (enabled.control)
		btd_profile_unregister(&avrcp_profile);

	btd_unregister_adapter_driver(&media_driver);
}

GSList *manager_find_devices(const char *path,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					const char *interface,
					gboolean connected)
{
	GSList *result = NULL;
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;

		if ((path && (strcmp(path, "")) &&
				strcmp(device_get_path(dev->btd_dev), path)))
			continue;

		if ((src && bacmp(src, BDADDR_ANY)) && bacmp(&dev->src, src))
			continue;

		if ((dst && bacmp(dst, BDADDR_ANY)) && bacmp(&dev->dst, dst))
			continue;

		if (interface && !strcmp(AUDIO_SINK_INTERFACE, interface)
				&& !dev->sink)
			continue;

		if (interface && !strcmp(AUDIO_SOURCE_INTERFACE, interface)
				&& !dev->source)
			continue;

		if (interface && !strcmp(AUDIO_CONTROL_INTERFACE, interface)
				&& !dev->control)
			continue;

		if (connected && !audio_device_is_active(dev, interface))
			continue;

		result = g_slist_append(result, dev);
	}

	return result;
}

struct audio_device *manager_find_device(const char *path,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					const char *interface,
					gboolean connected)
{
	struct audio_device *result;
	GSList *l;

	l = manager_find_devices(path, src, dst, interface, connected);
	if (l == NULL)
		return NULL;

	result = l->data;
	g_slist_free(l);
	return result;
}

struct audio_device *manager_get_device(const bdaddr_t *src,
					const bdaddr_t *dst,
					gboolean create)
{
	struct audio_device *dev;
	struct btd_adapter *adapter;
	struct btd_device *device;
	char addr[18];

	dev = manager_find_device(NULL, src, dst, NULL, FALSE);
	if (dev)
		return dev;

	if (!create)
		return NULL;

	ba2str(src, addr);

	adapter = manager_find_adapter(src);
	if (!adapter) {
		error("Unable to get a btd_adapter object for %s",
				addr);
		return NULL;
	}

	ba2str(dst, addr);

	device = adapter_get_device(adapter, addr);
	if (!device) {
		error("Unable to get btd_device object for %s", addr);
		return NULL;
	}

	dev = audio_device_register(device, src, dst);
	if (!dev)
		return NULL;

	devices = g_slist_append(devices, dev);

	return dev;
}

void manager_set_fast_connectable(gboolean enable)
{
	GSList *l;

	for (l = adapters; l != NULL; l = l->next) {
		struct audio_adapter *adapter = l->data;

		if (btd_adapter_set_fast_connectable(adapter->btd_adapter,
								enable))
			error("Changing fast connectable for hci%d failed",
				adapter_get_dev_id(adapter->btd_adapter));
	}
}
