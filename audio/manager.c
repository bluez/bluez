/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "glib-helper.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "../src/driver.h"

#include "dbus-service.h"
#include "logging.h"
#include "textfile.h"
#include "ipc.h"
#include "device.h"
#include "error.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "gateway.h"
#include "sink.h"
#include "control.h"
#include "manager.h"
#include "sdpd.h"

typedef enum {
	HEADSET	= 1 << 0,
	GATEWAY	= 1 << 1,
	SINK	= 1 << 2,
	SOURCE	= 1 << 3,
	CONTROL	= 1 << 4,
	TARGET	= 1 << 5,
	INVALID	= 1 << 6
} audio_service_type;

typedef enum {
		GENERIC_AUDIO = 0,
		ADVANCED_AUDIO,
		AV_REMOTE,
		GET_RECORDS
} audio_sdp_state_t;

struct audio_sdp_data {
	struct audio_device *device;

	DBusMessage *msg;	/* Method call or NULL */

	GSList *records;	/* sdp_record_t * */

	audio_sdp_state_t state;

	create_dev_cb_t cb;
	void *cb_data;
};

static DBusConnection *connection = NULL;

static GSList *devices = NULL;

static uint32_t hsp_ag_record_id = 0;
static uint32_t hfp_ag_record_id = 0;

static uint32_t hsp_hs_record_id = 0;

static GIOChannel *hsp_ag_server = NULL;
static GIOChannel *hfp_ag_server = NULL;

static GIOChannel *hsp_hs_server = NULL;

static struct enabled_interfaces enabled = {
	.headset	= TRUE,
	.gateway	= FALSE,
	.sink		= TRUE,
	.source		= FALSE,
	.control	= TRUE,
};

static uint16_t get_service_uuid(const sdp_record_t *record)
{
	sdp_list_t *classes;
	uuid_t uuid;
	uint16_t uuid16 = 0;

	if (sdp_get_service_classes(record, &classes) < 0) {
		error("Unable to get service classes from record");
		return 0;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));

	if (!sdp_uuid128_to_uuid(&uuid)) {
		error("Not a 16 bit UUID");
		sdp_list_free(classes, free);
		return 0;
	}

	if (uuid.type == SDP_UUID32) {
		if (uuid.value.uuid32 > 0xFFFF) {
			error("Not a 16 bit UUID");
			goto done;
		}
		uuid16 = (uint16_t) uuid.value.uuid32;
	} else
		uuid16 = uuid.value.uuid16;

done:
	sdp_list_free(classes, free);

	return uuid16;
}

gboolean server_is_enabled(uint16_t svc)
{
	gboolean ret;

	switch (svc) {
	case HEADSET_SVCLASS_ID:
		ret = (hsp_ag_server != NULL);
		break;
	case HEADSET_AGW_SVCLASS_ID:
		ret = (hsp_hs_server != NULL);
		break;
	case HANDSFREE_SVCLASS_ID:
		ret = (hfp_ag_server != NULL);
		break;
	case HANDSFREE_AGW_SVCLASS_ID:
		ret = FALSE;
		break;
	case AUDIO_SINK_SVCLASS_ID:
		return enabled.sink;
	case AV_REMOTE_TARGET_SVCLASS_ID:
	case AV_REMOTE_SVCLASS_ID:
		return enabled.control;
	default:
		ret = FALSE;
		break;
	}

	return ret;
}

static void handle_record(sdp_record_t *record, struct audio_device *device)
{
	uint16_t uuid16;

	uuid16 = get_service_uuid(record);

	if (!server_is_enabled(uuid16))
		return;

	switch (uuid16) {
	case HEADSET_SVCLASS_ID:
		debug("Found Headset record");
		if (device->headset)
			headset_update(device, record, uuid16);
		else
			device->headset = headset_init(device,
							record, uuid16);
		break;
	case HEADSET_AGW_SVCLASS_ID:
		debug("Found Headset AG record");
		break;
	case HANDSFREE_SVCLASS_ID:
		debug("Found Hansfree record");
		if (device->headset)
			headset_update(device, record, uuid16);
		else
			device->headset = headset_init(device,
							record, uuid16);
		break;
	case HANDSFREE_AGW_SVCLASS_ID:
		debug("Found Handsfree AG record");
		break;
	case AUDIO_SINK_SVCLASS_ID:
		debug("Found Audio Sink");
		if (device->sink == NULL)
			device->sink = sink_init(device);
		break;
	case AUDIO_SOURCE_SVCLASS_ID:
		debug("Found Audio Source");
		break;
	case AV_REMOTE_SVCLASS_ID:
		debug("Found AV Remote");
		if (device->control == NULL)
			device->control = control_init(device);
		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	case AV_REMOTE_TARGET_SVCLASS_ID:
		debug("Found AV Target");
		if (device->control == NULL)
			device->control = control_init(device);
		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	default:
		debug("Unrecognized UUID: 0x%04X", uuid16);
		break;
	}
}

static sdp_record_t *hsp_ag_record(uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_list_t *aproto, *proto[2];
	sdp_data_t *channel;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Headset Audio Gateway", 0, 0);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *hsp_hs_record(uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_list_t *aproto, *proto[2];
	sdp_data_t *channel;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Headset", 0, 0);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *hfp_ag_record(uint8_t ch, uint32_t feat)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *channel, *features;
	uint8_t netid = 0x01;
	uint16_t sdpfeat;
	sdp_data_t *network = sdp_data_alloc(SDP_UINT8, &netid);

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0105;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdpfeat = (uint16_t) feat & 0xF;
	features = sdp_data_alloc(SDP_UINT16, &sdpfeat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(record, SDP_ATTR_EXTERNAL_NETWORK, network);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct audio_device *device = user_data;
	const char *uuid;

	if (get_hfp_active(device))
		uuid = HFP_AG_UUID;
	else
		uuid = HSP_AG_UUID;

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		if (dbus_error_has_name(derr, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			service_cancel_auth(&device->src, &device->dst);
		}

		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
	} else {
		char hs_address[18];

		headset_set_authorized(device);

		ba2str(&device->dst, hs_address);

		debug("Accepted headset connection from %s for %s",
						hs_address, device->path);
		headset_set_state(device, HEADSET_STATE_CONNECTED);
	}
}

static void ag_io_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer data)
{
	const char *uuid;
	struct audio_device *device;
	gboolean hfp_active;

	if (err < 0) {
		error("accept: %s (%d)", strerror(-err), -err);
		return;
	}

	if (chan == hsp_ag_server) {
		hfp_active = FALSE;
		uuid = HSP_AG_UUID;
	} else {
		hfp_active = TRUE;
		uuid = HFP_AG_UUID;
	}

	device = manager_find_device(dst, NULL, FALSE);
	if (!device)
		goto drop;

	if (headset_get_state(device) > HEADSET_STATE_DISCONNECTED) {
		debug("Refusing new connection since one already exists");
		goto drop;
	}

	set_hfp_active(device, hfp_active);

	if (headset_connect_rfcomm(device, chan) < 0) {
		error("Allocating new GIOChannel failed!");
		goto drop;
	}

	err = service_req_auth(&device->src, &device->dst, uuid, auth_cb,
				device);
	if (err < 0) {
		debug("Authorization denied: %s", strerror(-err));
		headset_close_rfcomm(device);
		return;
	}

	headset_set_state(device, HEADSET_STATE_CONNECT_IN_PROGRESS);

	return;

drop:
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	return;
}

static void hs_io_cb(GIOChannel *chan, int err, const bdaddr_t *src,
		const bdaddr_t *dst, void *data)
{
	/*Stub*/
	return;
}

static int headset_server_init(DBusConnection *conn, GKeyFile *config)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;
	sdp_record_t *record;
	gboolean hfp = TRUE, master = TRUE;
	GError *err = NULL;
	uint32_t features, flags;

	if (!enabled.headset)
		return 0;

	if (config) {
		gboolean tmp;

		tmp = g_key_file_get_boolean(config, "General", "Master",
						&err);
		if (err) {
			debug("audio.conf: %s", err->message);
			g_error_free(err);
			err = NULL;
		} else
			master = tmp;

		tmp = g_key_file_get_boolean(config, "Headset", "HFP",
						&err);
		if (err) {
			debug("audio.conf: %s", err->message);
			g_error_free(err);
			err = NULL;
		} else
			hfp = tmp;
	}

	flags = RFCOMM_LM_SECURE;

	if (master)
		flags |= RFCOMM_LM_MASTER;

	hsp_ag_server = bt_rfcomm_listen(BDADDR_ANY, chan, flags, ag_io_cb,
				NULL);
	if (!hsp_ag_server)
		return -1;

	record = hsp_ag_record(chan);
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register HS AG service record");
		sdp_record_free(record);
		g_io_channel_unref(hsp_ag_server);
		hsp_ag_server = NULL;
		return -1;
	}
	hsp_ag_record_id = record->handle;

	features = headset_config_init(config);

	if (!hfp)
		return 0;

	chan = DEFAULT_HF_AG_CHANNEL;

	hfp_ag_server = bt_rfcomm_listen(BDADDR_ANY, chan, flags, ag_io_cb,
				NULL);
	if (!hfp_ag_server)
		return -1;

	record = hfp_ag_record(chan, features);
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register HF AG service record");
		sdp_record_free(record);
		g_io_channel_unref(hfp_ag_server);
		hfp_ag_server = NULL;
		return -1;
	}
	hfp_ag_record_id = record->handle;

	return 0;
}

static int gateway_server_init(DBusConnection *conn, GKeyFile *config)
{
	uint8_t chan = DEFAULT_HSP_HS_CHANNEL;
	sdp_record_t *record;
	gboolean master = TRUE;
	GError *err = NULL;
	uint32_t flags;

	if (!enabled.gateway)
		return 0;

	if (config) {
		gboolean tmp;

		tmp = g_key_file_get_boolean(config, "General", "Master",
						&err);
		if (err) {
			debug("audio.conf: %s", err->message);
			g_error_free(err);
			err = NULL;
		} else
			master = tmp;
	}

	flags = RFCOMM_LM_SECURE;

	if (master)
		flags |= RFCOMM_LM_MASTER;

	hsp_hs_server = bt_rfcomm_listen(BDADDR_ANY, chan, flags, hs_io_cb,
				NULL);
	if (!hsp_hs_server)
		return -1;

	record = hsp_hs_record(chan);
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register HSP HS service record");
		sdp_record_free(record);
		g_io_channel_unref(hsp_hs_server);
		hsp_hs_server = NULL;
		return -1;
	}

	hsp_hs_record_id = record->handle;

	return 0;
}

static void server_exit(void)
{
	if (hsp_ag_record_id) {
		remove_record_from_server(hsp_ag_record_id);
		hsp_ag_record_id = 0;
	}

	if (hsp_ag_server) {
		g_io_channel_unref(hsp_ag_server);
		hsp_ag_server = NULL;
	}

	if (hsp_hs_record_id) {
		remove_record_from_server(hsp_hs_record_id);
		hsp_hs_record_id = 0;
	}

	if (hsp_hs_server) {
		g_io_channel_unref(hsp_hs_server);
		hsp_hs_server = NULL;
	}

	if (hfp_ag_record_id) {
		remove_record_from_server(hfp_ag_record_id);
		hfp_ag_record_id = 0;
	}

	if (hfp_ag_server) {
		g_io_channel_unref(hfp_ag_server);
		hfp_ag_server = NULL;
	}
}

static int audio_probe(struct btd_device_driver *driver,
			struct btd_device *device, GSList *records)
{
	struct adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	const char *source, *destination;
	bdaddr_t src, dst;
	struct audio_device *dev;

	source = adapter_get_address(adapter);
	destination = device_get_address(device);

	str2ba(source, &src);
	str2ba(destination, &dst);

	dev = manager_find_device(&dst, NULL, FALSE);
	if (!dev) {
		dev = device_register(connection, path, &src, &dst);
		if (!dev)
			return -EINVAL;
		devices = g_slist_append(devices, dev);
	}

	g_slist_foreach(records, (GFunc) handle_record, dev);

	return 0;
}

static void audio_remove(struct btd_device_driver *driver,
			struct btd_device *device)
{
	struct audio_device *dev;
	const char *destination = device_get_address(device);
	bdaddr_t dst;

	str2ba(destination, &dst);

	dev = manager_find_device(&dst, NULL, FALSE);
	if (!dev)
		return;

	devices = g_slist_remove(devices, dev);

	device_unregister(dev);
}

static struct btd_device_driver audio_driver = {
	.name	= "audio",
	.uuids	= BTD_UUIDS(HSP_HS_UUID, HFP_HS_UUID, HSP_AG_UUID, HFP_AG_UUID,
			ADVANCED_AUDIO_UUID, A2DP_SOURCE_UUID, A2DP_SINK_UUID,
			AVRCP_TARGET_UUID, AVRCP_REMOTE_UUID),
	.probe	= audio_probe,
	.remove	= audio_remove,
};

int audio_manager_init(DBusConnection *conn, GKeyFile *config)
{
	char **list;
	int i;

	connection = dbus_connection_ref(conn);

	if (!config)
		goto proceed;

	list = g_key_file_get_string_list(config, "General", "Enable",
						NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "Headset"))
			enabled.headset = TRUE;
		else if (g_str_equal(list[i], "Gateway"))
			enabled.gateway = TRUE;
		else if (g_str_equal(list[i], "Sink"))
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
		if (g_str_equal(list[i], "Headset"))
			enabled.headset = FALSE;
		else if (g_str_equal(list[i], "Gateway"))
			enabled.gateway = FALSE;
		else if (g_str_equal(list[i], "Sink"))
			enabled.sink = FALSE;
		else if (g_str_equal(list[i], "Source"))
			enabled.source = FALSE;
		else if (g_str_equal(list[i], "Control"))
			enabled.control = FALSE;
	}
	g_strfreev(list);

proceed:
	if (enabled.headset) {
		if (headset_server_init(conn, config) < 0)
			goto failed;
	}

	if (enabled.gateway) {
		if (gateway_server_init(conn, config) < 0)
			goto failed;
	}

	if (enabled.source || enabled.sink) {
		if (a2dp_init(conn, config) < 0)
			goto failed;
	}

	if (enabled.control && avrcp_init(conn, config) < 0)
		goto failed;

	btd_register_device_driver(&audio_driver);

	return 0;
failed:
	audio_manager_exit();
	return -1;
}

void audio_manager_exit(void)
{
	server_exit();

	dbus_connection_unref(connection);

	btd_unregister_device_driver(&audio_driver);

	connection = NULL;
}

struct audio_device *manager_get_connected_device(void)
{
	GSList *l;

	for (l = devices; l != NULL; l = g_slist_next(l)) {
		struct audio_device *device = l->data;

		if ((device->sink || device->source) &&
				avdtp_is_connected(&device->src, &device->dst))
			return device;

		if (device->headset && headset_is_active(device))
			return device;
	}

	return NULL;
}

struct audio_device *manager_find_device(const bdaddr_t *bda, const char *interface,
					gboolean connected)
{
	GSList *l;

	if (!bacmp(bda, BDADDR_ANY) && !interface && !connected)
		return devices->data;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;

		if (bacmp(bda, BDADDR_ANY) && bacmp(&dev->dst, bda))
			continue;

		if (interface && !strcmp(AUDIO_HEADSET_INTERFACE, interface)
				&& !dev->headset)
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

		if (connected && !device_is_connected(dev, interface))
			continue;

		return dev;
	}

	return NULL;
}
