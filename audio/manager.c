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
#include "btio.h"
#include "../src/manager.h"
#include "../src/adapter.h"
#include "../src/device.h"

#include "log.h"
#include "textfile.h"
#include "ipc.h"
#include "device.h"
#include "error.h"
#include "avdtp.h"
#include "a2dp.h"
#include "headset.h"
#include "gateway.h"
#include "sink.h"
#include "source.h"
#include "control.h"
#include "manager.h"
#include "sdpd.h"
#include "telephony.h"

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

struct audio_adapter {
	struct btd_adapter *btd_adapter;
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
static DBusConnection *connection = NULL;
static GKeyFile *config = NULL;
static GSList *adapters = NULL;
static GSList *devices = NULL;

static struct enabled_interfaces enabled = {
	.hfp		= TRUE,
	.headset	= TRUE,
	.gateway	= FALSE,
	.sink		= TRUE,
	.source		= FALSE,
	.control	= TRUE,
};

static struct audio_adapter *find_adapter(GSList *list,
					struct btd_adapter *btd_adapter)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct audio_adapter *adapter = l->data;

		if (adapter->btd_adapter == btd_adapter)
			return adapter;
	}

	return NULL;
}

gboolean server_is_enabled(bdaddr_t *src, uint16_t svc)
{
	switch (svc) {
	case HEADSET_SVCLASS_ID:
		return enabled.headset;
	case HEADSET_AGW_SVCLASS_ID:
		return FALSE;
	case HANDSFREE_SVCLASS_ID:
		return enabled.headset && enabled.hfp;
	case HANDSFREE_AGW_SVCLASS_ID:
		return enabled.gateway;
	case AUDIO_SINK_SVCLASS_ID:
		return enabled.sink;
	case AUDIO_SOURCE_SVCLASS_ID:
		return enabled.source;
	case AV_REMOTE_TARGET_SVCLASS_ID:
	case AV_REMOTE_SVCLASS_ID:
		return enabled.control;
	default:
		return FALSE;
	}
}

static void handle_uuid(const char *uuidstr, struct audio_device *device)
{
	uuid_t uuid;
	uint16_t uuid16;

	if (bt_string2uuid(&uuid, uuidstr) < 0) {
		error("%s not detected as an UUID-128", uuidstr);
		return;
	}

	if (!sdp_uuid128_to_uuid(&uuid) && uuid.type != SDP_UUID16) {
		error("Could not convert %s to a UUID-16", uuidstr);
		return;
	}

	uuid16 = uuid.value.uuid16;

	if (!server_is_enabled(&device->src, uuid16)) {
		DBG("server not enabled for %s (0x%04x)", uuidstr, uuid16);
		return;
	}

	switch (uuid16) {
	case HEADSET_SVCLASS_ID:
		DBG("Found Headset record");
		if (device->headset)
			headset_update(device, uuid16, uuidstr);
		else
			device->headset = headset_init(device, uuid16,
							uuidstr);
		break;
	case HEADSET_AGW_SVCLASS_ID:
		DBG("Found Headset AG record");
		break;
	case HANDSFREE_SVCLASS_ID:
		DBG("Found Handsfree record");
		if (device->headset)
			headset_update(device, uuid16, uuidstr);
		else
			device->headset = headset_init(device, uuid16,
								uuidstr);
		break;
	case HANDSFREE_AGW_SVCLASS_ID:
		DBG("Found Handsfree AG record");
		if (enabled.gateway && (device->gateway == NULL))
			device->gateway = gateway_init(device);
		break;
	case AUDIO_SINK_SVCLASS_ID:
		DBG("Found Audio Sink");
		if (device->sink == NULL)
			device->sink = sink_init(device);
		break;
	case AUDIO_SOURCE_SVCLASS_ID:
		DBG("Found Audio Source");
		if (device->source == NULL)
			device->source = source_init(device);
		break;
	case AV_REMOTE_SVCLASS_ID:
	case AV_REMOTE_TARGET_SVCLASS_ID:
		DBG("Found AV %s", uuid16 == AV_REMOTE_SVCLASS_ID ?
							"Remote" : "Target");
		if (device->control)
			control_update(device, uuid16);
		else
			device->control = control_init(device, uuid16);
		if (device->sink && sink_is_active(device))
			avrcp_connect(device);
		break;
	default:
		DBG("Unrecognized UUID: 0x%04X", uuid16);
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
	profile.version = 0x0102;
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

static sdp_record_t *hfp_hs_record(uint8_t ch)
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

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_SVCLASS_ID);
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

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free", 0, 0);

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
	sdp_data_t *network;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	network = sdp_data_alloc(SDP_UINT8, &netid);
	if (!network) {
		sdp_record_free(record);
		return NULL;
	}

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

static void headset_auth_cb(DBusError *derr, void *user_data)
{
	struct audio_device *device = user_data;
	GError *err = NULL;
	GIOChannel *io;

	if (device->hs_preauth_id) {
		g_source_remove(device->hs_preauth_id);
		device->hs_preauth_id = 0;
	}

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}

	io = headset_get_rfcomm(device);

	if (!bt_io_accept(io, headset_connect_cb, device, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}
}

static gboolean hs_preauth_cb(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct audio_device *device = user_data;

	DBG("Headset disconnected during authorization");

	audio_device_cancel_authorization(device, headset_auth_cb, device);

	headset_set_state(device, HEADSET_STATE_DISCONNECTED);

	device->hs_preauth_id = 0;

	return FALSE;
}

static void ag_confirm(GIOChannel *chan, gpointer data)
{
	const char *server_uuid, *remote_uuid;
	struct audio_device *device;
	gboolean hfp_active;
	bdaddr_t src, dst;
	int perr;
	GError *err = NULL;
	uint8_t ch;

	bt_io_get(chan, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_CHANNEL, &ch,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	if (ch == DEFAULT_HS_AG_CHANNEL) {
		hfp_active = FALSE;
		server_uuid = HSP_AG_UUID;
		remote_uuid = HSP_HS_UUID;
	} else {
		hfp_active = TRUE;
		server_uuid = HFP_AG_UUID;
		remote_uuid = HFP_HS_UUID;
	}

	device = manager_get_device(&src, &dst, TRUE);
	if (!device)
		goto drop;

	if (!manager_allow_headset_connection(device)) {
		DBG("Refusing headset: too many existing connections");
		goto drop;
	}

	if (!device->headset) {
		btd_device_add_uuid(device->btd_dev, remote_uuid);
		if (!device->headset)
			goto drop;
	}

	if (headset_get_state(device) > HEADSET_STATE_DISCONNECTED) {
		DBG("Refusing new connection since one already exists");
		goto drop;
	}

	set_hfp_active(device, hfp_active);

	if (headset_connect_rfcomm(device, chan) < 0) {
		error("headset_connect_rfcomm failed");
		goto drop;
	}

	headset_set_state(device, HEADSET_STATE_CONNECTING);

	perr = audio_device_request_authorization(device, server_uuid,
						headset_auth_cb, device);
	if (perr < 0) {
		DBG("Authorization denied: %s", strerror(-perr));
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);
		return;
	}

	device->hs_preauth_id = g_io_add_watch(chan,
					G_IO_NVAL | G_IO_HUP | G_IO_ERR,
					hs_preauth_cb, device);

	device->auto_connect = auto_connect;

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

static void gateway_auth_cb(DBusError *derr, void *user_data)
{
	struct audio_device *device = user_data;

	if (derr && dbus_error_is_set(derr))
		error("Access denied: %s", derr->message);
	else {
		char ag_address[18];

		ba2str(&device->dst, ag_address);
		DBG("Accepted AG connection from %s for %s",
			ag_address, device->path);

		gateway_start_service(device);
	}
}

static void hf_io_cb(GIOChannel *chan, gpointer data)
{
	bdaddr_t src, dst;
	GError *err = NULL;
	uint8_t ch;
	const char *server_uuid, *remote_uuid;
	uint16_t svclass;
	struct audio_device *device;
	int perr;

	bt_io_get(chan, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_CHANNEL, &ch,
			BT_IO_OPT_INVALID);

	if (err) {
		error("%s", err->message);
		g_error_free(err);
		return;
	}

	server_uuid = HFP_AG_UUID;
	remote_uuid = HFP_HS_UUID;
	svclass = HANDSFREE_AGW_SVCLASS_ID;

	device = manager_get_device(&src, &dst, TRUE);
	if (!device)
		goto drop;

	if (!device->gateway) {
		btd_device_add_uuid(device->btd_dev, remote_uuid);
		if (!device->gateway)
			goto drop;
	}

	if (gateway_is_connected(device)) {
		DBG("Refusing new connection since one already exists");
		goto drop;
	}

	if (gateway_connect_rfcomm(device, chan) < 0) {
		error("Allocating new GIOChannel failed!");
		goto drop;
	}

	perr = audio_device_request_authorization(device, server_uuid,
						gateway_auth_cb, device);
	if (perr < 0) {
		DBG("Authorization denied!");
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
	g_io_channel_unref(chan);
}

static int headset_server_init(struct audio_adapter *adapter)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;
	sdp_record_t *record;
	gboolean master = TRUE;
	GError *err = NULL;
	uint32_t features;
	GIOChannel *io;
	bdaddr_t src;

	if (config) {
		gboolean tmp;

		tmp = g_key_file_get_boolean(config, "General", "Master",
						&err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_clear_error(&err);
		} else
			master = tmp;
	}

	adapter_get_address(adapter->btd_adapter, &src);

	io =  bt_io_listen(BT_IO_RFCOMM, NULL, ag_confirm, adapter, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io)
		goto failed;

	adapter->hsp_ag_server = io;

	record = hsp_ag_record(chan);
	if (!record) {
		error("Unable to allocate new service record");
		goto failed;
	}

	if (add_record_to_server(&src, record) < 0) {
		error("Unable to register HS AG service record");
		sdp_record_free(record);
		goto failed;
	}
	adapter->hsp_ag_record_id = record->handle;

	features = headset_config_init(config);

	if (!enabled.hfp)
		return 0;

	chan = DEFAULT_HF_AG_CHANNEL;

	io = bt_io_listen(BT_IO_RFCOMM, NULL, ag_confirm, adapter, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io)
		goto failed;

	adapter->hfp_ag_server = io;

	record = hfp_ag_record(chan, features);
	if (!record) {
		error("Unable to allocate new service record");
		goto failed;
	}

	if (add_record_to_server(&src, record) < 0) {
		error("Unable to register HF AG service record");
		sdp_record_free(record);
		goto failed;
	}
	adapter->hfp_ag_record_id = record->handle;

	return 0;

failed:
	error("%s", err->message);
	g_error_free(err);
	if (adapter->hsp_ag_server) {
		g_io_channel_shutdown(adapter->hsp_ag_server, TRUE, NULL);
		g_io_channel_unref(adapter->hsp_ag_server);
		adapter->hsp_ag_server = NULL;
	}

	if (adapter->hfp_ag_server) {
		g_io_channel_shutdown(adapter->hfp_ag_server, TRUE, NULL);
		g_io_channel_unref(adapter->hfp_ag_server);
		adapter->hfp_ag_server = NULL;
	}

	return -1;
}

static int gateway_server_init(struct audio_adapter *adapter)
{
	uint8_t chan = DEFAULT_HFP_HS_CHANNEL;
	sdp_record_t *record;
	gboolean master = TRUE;
	GError *err = NULL;
	GIOChannel *io;
	bdaddr_t src;

	if (config) {
		gboolean tmp;

		tmp = g_key_file_get_boolean(config, "General", "Master",
						&err);
		if (err) {
			DBG("audio.conf: %s", err->message);
			g_clear_error(&err);
		} else
			master = tmp;
	}

	adapter_get_address(adapter->btd_adapter, &src);

	io = bt_io_listen(BT_IO_RFCOMM, NULL, hf_io_cb, adapter, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return -1;
	}

	adapter->hfp_hs_server = io;
	record = hfp_hs_record(chan);
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(&src, record) < 0) {
		error("Unable to register HFP HS service record");
		sdp_record_free(record);
		g_io_channel_unref(adapter->hfp_hs_server);
		adapter->hfp_hs_server = NULL;
		return -1;
	}

	adapter->hfp_hs_record_id = record->handle;

	return 0;
}

static int audio_probe(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	bdaddr_t src, dst;
	struct audio_device *audio_dev;

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst);

	audio_dev = manager_get_device(&src, &dst, TRUE);
	if (!audio_dev) {
		DBG("unable to get a device object");
		return -1;
	}

	g_slist_foreach(uuids, (GFunc) handle_uuid, audio_dev);

	return 0;
}

static void audio_remove(struct btd_device *device)
{
	struct audio_device *dev;
	const char *path;

	path = device_get_path(device);

	dev = manager_find_device(path, NULL, NULL, NULL, FALSE);
	if (!dev)
		return;

	devices = g_slist_remove(devices, dev);

	audio_device_unregister(dev);

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
		if (!adp)
			return NULL;
		adapters = g_slist_append(adapters, adp);
	} else
		audio_adapter_ref(adp);

	return adp;
}

static int headset_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	err = headset_server_init(adp);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void headset_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	if (adp->hsp_ag_record_id) {
		remove_record_from_server(adp->hsp_ag_record_id);
		adp->hsp_ag_record_id = 0;
	}

	if (adp->hsp_ag_server) {
		g_io_channel_shutdown(adp->hsp_ag_server, TRUE, NULL);
		g_io_channel_unref(adp->hsp_ag_server);
		adp->hsp_ag_server = NULL;
	}

	if (adp->hfp_ag_record_id) {
		remove_record_from_server(adp->hfp_ag_record_id);
		adp->hfp_ag_record_id = 0;
	}

	if (adp->hfp_ag_server) {
		g_io_channel_shutdown(adp->hfp_ag_server, TRUE, NULL);
		g_io_channel_unref(adp->hfp_ag_server);
		adp->hfp_ag_server = NULL;
	}

	audio_adapter_unref(adp);
}

static int gateway_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	return gateway_server_init(adp);
}

static void gateway_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	if (adp->hfp_hs_record_id) {
		remove_record_from_server(adp->hfp_hs_record_id);
		adp->hfp_hs_record_id = 0;
	}

	if (adp->hfp_hs_server) {
		g_io_channel_unref(adp->hfp_hs_server);
		adp->hfp_hs_server = NULL;
	}

	audio_adapter_unref(adp);
}

static int a2dp_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;
	int err;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	adapter_get_address(adapter, &src);

	err = a2dp_register(connection, &src, config);
	if (err < 0)
		audio_adapter_unref(adp);

	return err;
}

static void a2dp_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	adapter_get_address(adapter, &src);
	a2dp_unregister(&src);
	audio_adapter_unref(adp);
}

static int avrcp_server_probe(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adp = audio_adapter_get(adapter);
	if (!adp)
		return -EINVAL;

	adapter_get_address(adapter, &src);

	return avrcp_register(connection, &src, config);
}

static void avrcp_server_remove(struct btd_adapter *adapter)
{
	struct audio_adapter *adp;
	const gchar *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adp = find_adapter(adapters, adapter);
	if (!adp)
		return;

	adapter_get_address(adapter, &src);
	avrcp_unregister(&src);
	audio_adapter_unref(adp);
}

static struct btd_device_driver audio_driver = {
	.name	= "audio",
	.uuids	= BTD_UUIDS(HSP_HS_UUID, HFP_HS_UUID, HSP_AG_UUID, HFP_AG_UUID,
			ADVANCED_AUDIO_UUID, A2DP_SOURCE_UUID, A2DP_SINK_UUID,
			AVRCP_TARGET_UUID, AVRCP_REMOTE_UUID),
	.probe	= audio_probe,
	.remove	= audio_remove,
};

static struct btd_adapter_driver headset_server_driver = {
	.name	= "audio-headset",
	.probe	= headset_server_probe,
	.remove	= headset_server_remove,
};

static struct btd_adapter_driver gateway_server_driver = {
	.name	= "audio-gateway",
	.probe	= gateway_server_probe,
	.remove	= gateway_server_remove,
};

static struct btd_adapter_driver a2dp_server_driver = {
	.name	= "audio-a2dp",
	.probe	= a2dp_server_probe,
	.remove	= a2dp_server_remove,
};

static struct btd_adapter_driver avrcp_server_driver = {
	.name	= "audio-control",
	.probe	= avrcp_server_probe,
	.remove	= avrcp_server_remove,
};

int audio_manager_init(DBusConnection *conn, GKeyFile *conf,
							gboolean *enable_sco)
{
	char **list;
	int i;
	gboolean b;
	GError *err = NULL;

	connection = dbus_connection_ref(conn);

	if (!conf)
		goto proceed;

	config = conf;

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

	b = g_key_file_get_boolean(config, "General", "AutoConnect", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		auto_connect = b;

	b = g_key_file_get_boolean(config, "Headset", "HFP",
					&err);
	if (err)
		g_clear_error(&err);
	else
		enabled.hfp = b;

	err = NULL;
	i = g_key_file_get_integer(config, "Headset", "MaxConnected",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else
		max_connected_headsets = i;

proceed:
	if (enabled.headset) {
		telephony_init();
		btd_register_adapter_driver(&headset_server_driver);
	}

	if (enabled.gateway)
		btd_register_adapter_driver(&gateway_server_driver);

	if (enabled.source || enabled.sink)
		btd_register_adapter_driver(&a2dp_server_driver);

	if (enabled.control)
		btd_register_adapter_driver(&avrcp_server_driver);

	btd_register_device_driver(&audio_driver);

	*enable_sco = (enabled.gateway || enabled.headset);

	return 0;
}

void audio_manager_exit(void)
{
	/* Bail out early if we haven't been initialized */
	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
	connection = NULL;

	if (config) {
		g_key_file_free(config);
		config = NULL;
	}

	if (enabled.headset) {
		btd_unregister_adapter_driver(&headset_server_driver);
		telephony_exit();
	}

	if (enabled.gateway)
		btd_unregister_adapter_driver(&gateway_server_driver);

	if (enabled.source || enabled.sink)
		btd_unregister_adapter_driver(&a2dp_server_driver);

	if (enabled.control)
		btd_unregister_adapter_driver(&avrcp_server_driver);

	btd_unregister_device_driver(&audio_driver);
}

struct audio_device *manager_find_device(const char *path,
					const bdaddr_t *src,
					const bdaddr_t *dst,
					const char *interface,
					gboolean connected)
{
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;

		if ((path && (strcmp(path, "")) && strcmp(dev->path, path)))
			continue;

		if ((src && bacmp(src, BDADDR_ANY)) && bacmp(&dev->src, src))
			continue;

		if ((dst && bacmp(dst, BDADDR_ANY)) && bacmp(&dev->dst, dst))
			continue;

		if (interface && !strcmp(AUDIO_HEADSET_INTERFACE, interface)
				&& !dev->headset)
			continue;

		if (interface && !strcmp(AUDIO_GATEWAY_INTERFACE, interface)
				&& !dev->gateway)
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

		return dev;
	}

	return NULL;
}

struct audio_device *manager_get_device(const bdaddr_t *src,
					const bdaddr_t *dst,
					gboolean create)
{
	struct audio_device *dev;
	struct btd_adapter *adapter;
	struct btd_device *device;
	char addr[18];
	const char *path;

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

	device = adapter_get_device(connection, adapter, addr);
	if (!device) {
		error("Unable to get btd_device object for %s", addr);
		return NULL;
	}

	path = device_get_path(device);

	dev = audio_device_register(connection, device, path, src, dst);
	if (!dev)
		return NULL;

	devices = g_slist_append(devices, dev);

	return dev;
}

gboolean manager_allow_headset_connection(struct audio_device *device)
{
	GSList *l;
	int connected = 0;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *dev = l->data;
		struct headset *hs = dev->headset;

		if (dev == device)
			continue;

		if (bacmp(&dev->src, &device->src))
			continue;

		if (!hs)
			continue;

		if (headset_get_state(dev) > HEADSET_STATE_DISCONNECTED)
			connected++;

		if (connected >= max_connected_headsets)
			return FALSE;
	}

	return TRUE;
}
