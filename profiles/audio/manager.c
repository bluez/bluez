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
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"

#include "log.h"
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

static int a2dp_source_probe(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);

	DBG("path %s", device_get_path(dev));

	source_init(service);

	return 0;
}

static void a2dp_source_remove(struct btd_service *service)
{
	source_unregister(service);
}

static int a2dp_sink_probe(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);

	DBG("path %s", device_get_path(dev));

	return sink_init(service);
}

static void a2dp_sink_remove(struct btd_service *service)
{
	sink_unregister(service);
}

static int avrcp_target_probe(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);

	DBG("path %s", device_get_path(dev));

	return control_init_target(service);
}

static void avrcp_target_remove(struct btd_service *service)
{
	control_unregister(service);
}

static int avrcp_remote_probe(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);

	DBG("path %s", device_get_path(dev));

	return control_init_remote(service);
}

static void avrcp_remote_remove(struct btd_service *service)
{
	control_unregister(service);
}

static int a2dp_source_connect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return source_connect(service);
}

static int a2dp_source_disconnect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return source_disconnect(service, FALSE);
}

static int a2dp_sink_connect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return sink_connect(service);
}

static int a2dp_sink_disconnect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return sink_disconnect(service, FALSE);
}

static int avrcp_control_connect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return control_connect(service);
}

static int avrcp_control_disconnect(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	const char *path = device_get_path(dev);

	DBG("path %s", path);

	return control_disconnect(service);
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
	.device_remove	= a2dp_source_remove,

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
	.device_remove	= a2dp_sink_remove,

	.auto_connect	= true,
	.connect	= a2dp_sink_connect,
	.disconnect	= a2dp_sink_disconnect,

	.adapter_probe	= a2dp_source_server_probe,
	.adapter_remove	= a2dp_source_server_remove,
};

static struct btd_profile avrcp_target_profile = {
	.name		= "audio-avrcp-target",

	.remote_uuid	= AVRCP_TARGET_UUID,
	.device_probe	= avrcp_target_probe,
	.device_remove	= avrcp_target_remove,

	.connect	= avrcp_control_connect,
	.disconnect	= avrcp_control_disconnect,

	.adapter_probe	= avrcp_target_server_probe,
	.adapter_remove = avrcp_target_server_remove,
};

static struct btd_profile avrcp_remote_profile = {
	.name		= "audio-avrcp-control",

	.remote_uuid	= AVRCP_REMOTE_UUID,
	.device_probe	= avrcp_remote_probe,
	.device_remove	= avrcp_remote_remove,

	.connect	= avrcp_control_connect,
	.disconnect	= avrcp_control_disconnect,

	.adapter_probe	= avrcp_remote_server_probe,
	.adapter_remove = avrcp_remote_server_remove,
};

static struct btd_adapter_driver media_driver = {
	.name	= "media",
	.probe	= media_server_probe,
	.remove	= media_server_remove,
};

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
