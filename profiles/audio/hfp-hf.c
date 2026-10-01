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

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "bluetooth/uuid.h"

#include "gdbus/gdbus.h"

#include "btio/btio.h"
#include "src/adapter.h"
#include "src/btd.h"
#include "src/dbus-common.h"
#include "src/device.h"
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/hfp.h"
#include "src/shared/queue.h"

#include "hfp-hf.h"
#include "media.h"
#include "telephony.h"

#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

#define HFP_HF_VERSION		0x0109
#define HFP_HF_DEFAULT_CHANNEL	7

#define HFP_HF_SDP_ECNR					0x0001
#define HFP_HF_SDP_3WAY					0x0002
#define HFP_HF_SDP_CLIP					0x0004
#define HFP_HF_SDP_VOICE_RECOGNITION			0x0008
#define HFP_HF_SDP_REMOTE_VOLUME_CONTROL		0x0010
#define HFP_HF_SDP_WIDE_BAND_SPEECH			0x0020
#define HFP_HF_SDP_ENHANCED_VOICE_RECOGNITION_STATUS	0x0040
#define HFP_HF_SDP_VOICE_RECOGNITION_TEXT		0x0080
#define HFP_HF_SDP_SUPER_WIDE_BAND_SPEECH		0x0100

#define HFP_HF_SDP_FEATURES	(HFP_HF_SDP_ECNR | HFP_HF_SDP_3WAY |\
				HFP_HF_SDP_CLIP |\
				HFP_HF_SDP_REMOTE_VOLUME_CONTROL)

#define URI	"tel"
#define URI_PREFIX	URI ":"

struct hfp_device {
	struct telephony	*telephony;
	uint16_t		version;
	GIOChannel		*io;
	GIOChannel		*sco_io;
	uint16_t		imtu;
	uint16_t		omtu;
	struct hfp_hf		*hf;
	struct queue		*calls;
	uint8_t			codec;
	unsigned int		resume_id;
	hfp_hf_sco_closed_cb	sco_closed_cb;
	void			*sco_closed_data;
};

struct hfp_server {
	struct btd_adapter	*adapter;
	GIOChannel		*io;
	GIOChannel		*sco_io;
	uint32_t		record_id;
	GSList			*endpoints;
};

static GSList *servers;

static void hfp_hf_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static char *make_endpoint_path(struct telephony *telephony, uint8_t codec)
{
	char *path;
	int err;

	err = asprintf(&path, "%s/sep%u", telephony_get_path(telephony),
								codec);
	if (err < 0) {
		error("Could not allocate path for remote %s",
			device_get_path(telephony_get_device(telephony)));
		return NULL;
	}

	return path;
}

static struct hfp_server *find_server(GSList *list, struct btd_adapter *a)
{
	for (; list; list = list->next) {
		struct hfp_server *server = list->data;

		if (server->adapter == a)
			return server;
	}

	return NULL;
}

static void unregister_endpoint(gpointer data, gpointer user_data)
{
	struct media_endpoint *ep = data;
	struct telephony *telephony = user_data;
	char *path;

	path = make_endpoint_path(telephony, media_endpoint_get_codec(ep));
	if (path) {
		g_dbus_unregister_interface(btd_get_dbus_connection(),
				path, MEDIA_ENDPOINT_INTERFACE);
		free(path);
	}
}

static enum call_state hfp_call_status_to_call_state(
						enum hfp_call_status status)
{
	switch (status) {
	case CALL_STATUS_ACTIVE: return CALL_STATE_ACTIVE; break;
	case CALL_STATUS_HELD: return CALL_STATE_HELD; break;
	case CALL_STATUS_DIALING: return CALL_STATE_DIALING; break;
	case CALL_STATUS_ALERTING: return CALL_STATE_ALERTING; break;
	case CALL_STATUS_INCOMING: return CALL_STATE_INCOMING; break;
	case CALL_STATUS_WAITING: return CALL_STATE_WAITING; break;
	case CALL_STATUS_RESPONSE_AND_HOLD:
		return CALL_STATE_RESPONSE_AND_HOLD; break;
	default:
		DBG("Unknown hfp_call_status: %u", status);
	}

	return CALL_STATE_DISCONNECTED;
}

static bool call_id_cmp(const void *data, const void *match_data)
{
	struct call *call = (struct call *) data;
	uint16_t id = GPOINTER_TO_UINT(match_data);

	return call->idx == id;
}

static void device_destroy(struct hfp_device *dev)
{
	struct hfp_server *server;

	DBG("%s", telephony_get_path(dev->telephony));

	telephony_set_state(dev->telephony, DISCONNECTING);

	if (dev->hf) {
		hfp_hf_unref(dev->hf);
		dev->hf = NULL;
	}

	if (dev->sco_io) {
		g_io_channel_unref(dev->sco_io);
		dev->sco_io = NULL;
	}

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	server = find_server(servers,
		device_get_adapter(telephony_get_device(dev->telephony)));
	if (server)
		g_slist_foreach(server->endpoints, unregister_endpoint,
					dev->telephony);

	telephony_unregister_interface(dev->telephony);
}

static void hfp_hf_update_indicator(enum hfp_indicator indicator, uint32_t val,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	switch (indicator) {
	case HFP_INDICATOR_SERVICE:
		telephony_set_network_service(dev->telephony, val);
		break;
	case HFP_INDICATOR_CALL:
		break;
	case HFP_INDICATOR_CALLSETUP:
		break;
	case HFP_INDICATOR_CALLHELD:
		break;
	case HFP_INDICATOR_SIGNAL:
		telephony_set_signal(dev->telephony, val);
		break;
	case HFP_INDICATOR_ROAM:
		telephony_set_roaming(dev->telephony, val);
		break;
	case HFP_INDICATOR_BATTCHG:
		telephony_set_battchg(dev->telephony, val);
		break;
	case HFP_INDICATOR_LAST:
	default:
		DBG("Unknown signal indicator: %u", indicator);
	}
}

static void hfp_hf_update_inband_ring(bool enabled, void *user_data)
{
	struct hfp_device *dev = user_data;

	telephony_set_inband_ringtone(dev->telephony, enabled);
}

static void hfp_hf_update_operator(const char *operator_name, void *user_data)
{
	struct hfp_device *dev = user_data;

	telephony_set_operator_name(dev->telephony, operator_name);
}

static void hfp_hf_call_added(uint id, enum hfp_call_status status,
							void *user_data)
{
	struct hfp_device *dev = user_data;
	struct call *call;
	const char *number;
	bool mpty;

	call = telephony_new_call(dev->telephony, id,
					hfp_call_status_to_call_state(status),
					NULL);
	if ((number = hfp_hf_call_get_number(dev->hf, id)) != NULL)
		call->line_id = g_strdup(number);
	if (hfp_hf_call_get_multiparty(dev->hf, id, &mpty))
		call->multiparty = mpty;
	if (telephony_call_register_interface(call)) {
		telephony_free_call(call);
		return;
	}

	queue_push_tail(dev->calls, call);
}

static void hfp_hf_call_removed(uint id, void *user_data)
{
	struct hfp_device *dev = user_data;
	struct call *call;

	call = queue_find(dev->calls, call_id_cmp, GUINT_TO_POINTER(id));
	if (!call) {
		DBG("Unknown call id: %u", id);
		return;
	}

	telephony_call_set_state(call, CALL_STATE_DISCONNECTED);
	queue_remove(dev->calls, call);
	telephony_call_unregister_interface(call);
}

static void hfp_hf_session_ready_cb(enum hfp_result res, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	if (res != HFP_RESULT_OK) {
		error("Session setup error: %d, dropping connection", res);
		hfp_hf_disconnect(dev->hf);
		return;
	}

	telephony_set_state(dev->telephony, CONNECTED);
}

static void hfp_hf_call_status_updated(uint id, enum hfp_call_status status,
							void *user_data)
{
	struct hfp_device *dev = user_data;
	struct call *call;

	call = queue_find(dev->calls, call_id_cmp, GUINT_TO_POINTER(id));
	if (!call) {
		DBG("Unknown call id: %u", id);
		return;
	}

	telephony_call_set_state(call, hfp_call_status_to_call_state(status));
}

static void hfp_hf_call_line_id_updated(uint id, const char *number,
							unsigned int type,
							void *user_data)
{
	struct hfp_device *dev = user_data;
	struct call *call;

	call = queue_find(dev->calls, call_id_cmp, GUINT_TO_POINTER(id));
	if (!call) {
		DBG("Unknown call id: %u", id);
		return;
	}

	telephony_call_set_line_id(call, number);
}

static struct hfp_hf_callbacks hf_session_callbacks = {
	.session_ready = hfp_hf_session_ready_cb,
	.update_indicator = hfp_hf_update_indicator,
	.update_operator = hfp_hf_update_operator,
	.update_inband_ring = hfp_hf_update_inband_ring,
	.call_added = hfp_hf_call_added,
	.call_removed = hfp_hf_call_removed,
	.call_status_updated = hfp_hf_call_status_updated,
	.call_line_id_updated = hfp_hf_call_line_id_updated,
};

static void hfp_disconnect_watch(void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	queue_destroy(dev->calls, NULL);
	dev->calls = NULL;

	device_destroy(user_data);
}

static gboolean get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	const char *uuid;

	uuid = HFP_HS_UUID;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct hfp_device *dev = data;
	const char *path;

	path = device_get_path(telephony_get_device(dev->telephony));

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static const GDBusMethodTable hfp_hf_ep_methods[] = {
	{ },
};

static const GDBusPropertyTable hfp_hf_ep_properties[] = {
	{ "UUID", "s", get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void register_endpoint(gpointer data, gpointer user_data)
{
	struct media_endpoint *ep = data;
	struct hfp_device *dev = user_data;
	char *path = NULL;

	path = make_endpoint_path(dev->telephony,
					media_endpoint_get_codec(ep));
	if (path) {
		if (g_dbus_register_interface(btd_get_dbus_connection(),
					path, MEDIA_ENDPOINT_INTERFACE,
					hfp_hf_ep_methods, NULL,
					hfp_hf_ep_properties,
					dev, NULL) == FALSE) {
			error("Could not register remote ep %s", path);
		}
		free(path);
	}
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct hfp_device *dev = user_data;
	struct btd_service *service = telephony_get_service(dev->telephony);
	struct hfp_server *server;

	DBG("");

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	dev->hf = hfp_hf_new(g_io_channel_unix_get_fd(chan));
	if (!dev->hf) {
		error("Could not create hfp io");
		goto failed;
	}

	hfp_hf_set_debug(dev->hf, hfp_hf_debug, NULL, NULL);
	g_io_channel_set_close_on_unref(chan, FALSE);

	hfp_hf_set_close_on_unref(dev->hf, true);
	hfp_hf_set_disconnect_handler(dev->hf, hfp_disconnect_watch,
					dev, NULL);
	hfp_hf_session_register(dev->hf, &hf_session_callbacks, dev);

	dev->calls = queue_new();

	if (!hfp_hf_session(dev->hf)) {
		error("Could not start SLC creation");
		hfp_hf_disconnect(dev->hf);
		goto failed;
	}

	telephony_set_state(dev->telephony, SESSION_CONNECTING);
	btd_service_connecting_complete(service, 0);

	server = find_server(servers,
		device_get_adapter(telephony_get_device(dev->telephony)));
	g_slist_foreach(server->endpoints, register_endpoint, dev);

	return;

failed:
	g_io_channel_shutdown(chan, TRUE, NULL);
	device_destroy(dev);
}

static void cmd_complete(enum hfp_result res, enum hfp_error cme_err,
							void *user_data)
{
	DBusMessage *msg = user_data;

	if (res != HFP_RESULT_OK) {
		DBusMessage *reply;
		const char *name = dbus_message_get_member(msg);

		error("Command %s error: %d", name, res);
		reply = g_dbus_create_error(msg, ERROR_INTERFACE
					".Failed",
					"Command %s failed: %d", name, res);
		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(msg);
		return;
	}

	g_dbus_send_reply(btd_get_dbus_connection(), msg, DBUS_TYPE_INVALID);
	dbus_message_unref(msg);
}

static DBusMessage *dial(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	const char *number;
	bool ret;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
		return btd_error_invalid_args(msg);
	}

	if (strncmp(number, URI_PREFIX, strlen(URI_PREFIX)) != 0)
		return btd_error_invalid_args(msg);

	ret = hfp_hf_dial(dev->hf, number + strlen(URI_PREFIX), cmd_complete,
					dbus_message_ref(msg));
	if (!ret)
		return btd_error_failed(msg, "Dial command failed");

	return NULL;
}

static DBusMessage *hangup_all(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	bool ret;

	ret = hfp_hf_hangup_all(dev->hf, cmd_complete,
					dbus_message_ref(msg));
	if (!ret)
		return btd_error_failed(msg, "Hang up all command failed");

	return NULL;
}

static DBusMessage *send_tones(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	const char *tones;
	bool ret;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &tones,
					DBUS_TYPE_INVALID)) {
		return btd_error_invalid_args(msg);
	}

	ret = hfp_hf_send_tones(dev->hf, tones, cmd_complete,
					dbus_message_ref(msg));
	if (!ret)
		return btd_error_failed(msg, "Send tones command failed");

	return NULL;
}

static DBusMessage *call_answer(DBusConnection *conn, DBusMessage *msg,
				void *call_data)
{
	struct call *call = call_data;
	struct hfp_device *dev = telephony_get_profile_data(call->device);
	bool ret;

	ret = hfp_hf_call_answer(dev->hf, call->idx, cmd_complete,
					dbus_message_ref(msg));
	if (!ret)
		return btd_error_failed(msg, "Answer call command failed");

	return NULL;
}

static DBusMessage *call_hangup(DBusConnection *conn, DBusMessage *msg,
				void *call_data)
{
	struct call *call = call_data;
	struct hfp_device *dev = telephony_get_profile_data(call->device);
	bool ret;

	ret = hfp_hf_call_hangup(dev->hf, call->idx, cmd_complete,
					dbus_message_ref(msg));
	if (!ret)
		return btd_error_failed(msg, "Hangup call command failed");

	return NULL;
}

struct telephony_callbacks hfp_callbacks = {
	.dial = dial,
	.hangup_all = hangup_all,
	.send_tones = send_tones,
	.call_answer = call_answer,
	.call_hangup = call_hangup,
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
	struct hfp_device *dev;

	DBG("");

	dev = btd_service_get_user_data(service);

	if (dev->hf)
		hfp_hf_disconnect(dev->hf);

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
	/* Use CVSD codec by default */
	dev->codec = 1;
	btd_service_set_user_data(service, dev);
	telephony_add_uri_scheme(dev->telephony, URI);

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

static sdp_record_t *hfp_record(void)
{
	sdp_record_t *record;
	uuid_t root_uuid, hfphf, genericaudio, l2cap, rfcomm;
	sdp_list_t *root, *svclass_id, *aproto, *proto[2], *apseq, *pfseq;
	sdp_data_t *channel, *features;
	uint8_t hf_channel = HFP_HF_DEFAULT_CHANNEL;
	sdp_profile_desc_t profile;
	uint16_t feat = HFP_HF_SDP_FEATURES;

	record = sdp_record_alloc();
	if (!record) {
		error("Unable to allocate new service record");
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&hfphf, HANDSFREE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &hfphf);
	sdp_uuid16_create(&genericaudio, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &genericaudio);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &hf_channel);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = HFP_HF_VERSION;
	pfseq = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_set_info_attr(record, "Hands-Free unit", NULL, NULL);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(svclass_id, NULL);
	sdp_list_free(root, NULL);

	return record;
}

static void server_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	uint8_t channel;
	bdaddr_t src, dst;
	char address[18];
	GError *gerr = NULL;
	struct btd_device *device;
	struct btd_service *service;
	struct hfp_device *dev;
	const sdp_record_t *rec;
	sdp_list_t *list;
	sdp_profile_desc_t *desc;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s on Channel %d", address, channel);

	device = btd_adapter_find_device(adapter_find(&src), &dst,
							BDADDR_BREDR);
	if (!device)
		return;

	service = btd_device_get_service(device, HFP_AG_UUID);
	if (!service)
		return;

	dev = btd_service_get_user_data(service);

	rec = btd_device_get_record(telephony_get_device(dev->telephony),
					HFP_AG_UUID);
	if (!rec)
		return;

	if (sdp_get_profile_descs(rec, &list) == 0) {
		desc = list->data;
		dev->version = desc->version;
	}
	sdp_list_free(list, free);

	telephony_register_interface(dev->telephony);

	connect_cb(chan, err, dev);
}

static GIOChannel *server_socket(struct btd_adapter *adapter)
{
	GIOChannel *io;
	GError *err = NULL;

	io = bt_io_listen(server_connect_cb, NULL, NULL, NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR,
		btd_adapter_get_address(adapter),
		BT_IO_OPT_CHANNEL, HFP_HF_DEFAULT_CHANNEL,
		BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
		BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return io;
}

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	struct hfp_device *dev = data;

	if (cond & G_IO_NVAL)
		return FALSE;

	DBG("sco connection released");
	g_io_channel_shutdown(dev->sco_io, TRUE, NULL);
	g_io_channel_unref(dev->sco_io);
	dev->sco_io = NULL;

	/* The remote end hung up the SCO connection instead of us
	 * releasing it locally, e.g. via Suspend/Release on the media
	 * transport. Notify the transport so it can update its state
	 * and release/suspend accordingly.
	 */
	if (dev->sco_closed_cb)
		dev->sco_closed_cb(dev, dev->sco_closed_data);

	return FALSE;
}

struct connect_data {
	struct hfp_device *dev;
	void (*cb)(int status, void *data);
	void *cb_user_data;
};

static void sco_connect_complete(struct connect_data *connect_data, int status)
{
	if (!connect_data || !connect_data->cb)
		goto done;

	connect_data->cb(status, connect_data->cb_user_data);

done:
	g_free(connect_data);
}

static void sco_connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct connect_data *connect_data = user_data;
	bdaddr_t src, dst;
	char addr[18];
	uint16_t handle;
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct btd_service *service;
	struct hfp_device *dev;
	struct hfp_server *server;
	struct media_endpoint *endpoint = NULL;
	GSList *l;
	char *path = NULL;
	uint16_t imtu, omtu;

	if (err) {
		error("Connecting failed: %s\n", err->message);
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	if (!bt_io_get(io, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, addr,
			BT_IO_OPT_HANDLE, &handle,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_OMTU, &omtu,
			BT_IO_OPT_INVALID)) {
		error("Unable to get destination address: %s\n", err->message);
		g_clear_error(&err);
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	DBG("Successfully connected to %s. handle=%u imtu=%u omtu=%u",
						addr, handle, imtu, omtu);

	adapter = adapter_find(&src);
	if (!adapter) {
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	device = btd_adapter_find_device(adapter, &dst, BDADDR_BREDR);
	if (!device) {
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	service = btd_device_get_service(device, HFP_AG_UUID);
	if (!service) {
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	dev = btd_service_get_user_data(service);

	server = find_server(servers, adapter);
	if (server == NULL) {
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	for (l = server->endpoints; l; l = l->next) {
		if (media_endpoint_get_codec(l->data) == dev->codec) {
			endpoint = l->data;
			break;
		}
	}
	if (endpoint == NULL) {
		sco_connect_complete(connect_data, -EIO);
		return;
	}

	path = make_endpoint_path(dev->telephony, dev->codec);
	if (path == NULL) {
		error("Could not allocate path for remote %s",
			device_get_path(telephony_get_device(dev->telephony)));
		sco_connect_complete(connect_data, -ENOMEM);
		return;
	}

	if (!hfp_hf_set_configuration(endpoint, path, NULL, dev, NULL)) {
		free(path);
		sco_connect_complete(connect_data, -EIO);
		return;
	}
	free(path);

	dev->imtu = imtu;
	dev->omtu = omtu;
	dev->sco_io = g_io_channel_ref(io);

	g_io_add_watch(io, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) sco_io_cb, dev);

	sco_connect_complete(connect_data, 0);
}

bool hfp_hf_sco_listen(struct btd_adapter *adapter, void *endpoint)
{
	struct hfp_server *server;
	GError *err = NULL;

	DBG("path %s, codec %u", adapter_get_path(adapter),
					media_endpoint_get_codec(endpoint));

	server = find_server(servers, adapter);
	if (server == NULL)
		return false;

	server->endpoints = g_slist_append(server->endpoints, endpoint);

	if (server->sco_io)
		return true;

	server->sco_io = bt_io_listen(sco_connect_cb, NULL, NULL, NULL,
				&err,
				BT_IO_OPT_SOURCE_BDADDR,
				btd_adapter_get_address(server->adapter),
				BT_IO_OPT_INVALID);
	if (server->sco_io) {
		DBG("SCO server started");
		return true;
	}

	server->endpoints = g_slist_remove(server->endpoints, endpoint);
	error("%s", err->message);
	g_error_free(err);

	return false;
}

void hfp_hf_sco_remove(struct btd_adapter *adapter, void *endpoint)
{
	struct hfp_server *server;

	DBG("path %s, codec %u", adapter_get_path(adapter),
					media_endpoint_get_codec(endpoint));

	server = find_server(servers, adapter);
	if (server == NULL) {
		error("No server for %s codec %u", adapter_get_path(adapter),
					media_endpoint_get_codec(endpoint));
		return;
	}

	server->endpoints = g_slist_remove(server->endpoints, endpoint);

	if (server->sco_io && g_slist_length(server->endpoints) == 0) {
		g_io_channel_shutdown(server->sco_io, TRUE, NULL);
		g_io_channel_unref(server->sco_io);
		server->sco_io = NULL;
		DBG("SCO server stopped");
	}
}

struct btd_device *hfp_hf_get_device(struct hfp_device *dev)
{
	return telephony_get_device(dev->telephony);
}

int hfp_hf_device_get_fd(struct hfp_device *dev)
{
	if (!dev->sco_io)
		return -1;

	return g_io_channel_unix_get_fd(dev->sco_io);
}

uint16_t hfp_hf_device_get_imtu(struct hfp_device *dev)
{
	return dev->imtu;
}

uint16_t hfp_hf_device_get_omtu(struct hfp_device *dev)
{
	return dev->omtu;
}

static gboolean sco_start_cb(gpointer data)
{
	struct connect_data *connect_data = data;

	if (connect_data && connect_data->cb) {
		connect_data->cb(0, connect_data->cb_user_data);
		g_free(connect_data);
	}

	return FALSE;
}

unsigned int hfp_hf_sco_start(struct hfp_device *dev, void *cb, void *user_data)
{
	bdaddr_t src, dst;
	struct connect_data *connect_data;
	GError *err = NULL;
	GIOChannel *io;

	DBG("codec %u", dev->codec);

	connect_data = g_new0(struct connect_data, 1);
	connect_data->dev = dev;
	connect_data->cb = cb;
	connect_data->cb_user_data = user_data;

	src = telephony_get_src(dev->telephony);
	dst = telephony_get_dst(dev->telephony);
	if (!dev->sco_io) {
		io = bt_io_connect(sco_connect_cb, connect_data, NULL, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
			BT_IO_OPT_INVALID);
		if (!io) {
			error("%s", err->message);
			g_error_free(err);
			g_free(connect_data);
			return 0;
		}
	} else {
		g_idle_add(sco_start_cb, connect_data);
	}

	return (++dev->resume_id);
}

unsigned int hfp_hf_sco_stop(struct hfp_device *dev)
{
	if (!dev->sco_io)
		return 0;

	DBG("codec %u", dev->codec);

	g_io_channel_shutdown(dev->sco_io, TRUE, NULL);
	g_io_channel_unref(dev->sco_io);
	dev->sco_io = NULL;

	return dev->resume_id;
}

void hfp_hf_set_sco_closed_cb(struct hfp_device *dev,
				hfp_hf_sco_closed_cb cb, void *user_data)
{
	dev->sco_closed_cb = cb;
	dev->sco_closed_data = user_data;
}

static int hfp_adapter_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct hfp_server *server;
	sdp_record_t *record;

	DBG("path %s", adapter_get_path(adapter));

	server = find_server(servers, adapter);
	if (server != NULL)
		goto done;

	server = g_new0(struct hfp_server, 1);

	server->io = server_socket(adapter);
	if (!server->io) {
		g_free(server);
		return -1;
	}

done:
	record = hfp_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (adapter_service_add(adapter, record) < 0) {
		error("Unable to register HFP HF service record");
		sdp_record_free(record);
		g_free(server);
		return -1;
	}
	server->record_id = record->handle;

	server->adapter = btd_adapter_ref(adapter);

	servers = g_slist_append(servers, server);

	return 0;
}

static void hfp_adapter_remove(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct hfp_server *server;

	DBG("path %s", adapter_get_path(adapter));

	server = find_server(servers, adapter);
	if (!server)
		return;

	if (server->sco_io) {
		g_io_channel_shutdown(server->sco_io, TRUE, NULL);
		g_io_channel_unref(server->sco_io);
	}

	if (server->io) {
		g_io_channel_shutdown(server->io, TRUE, NULL);
		g_io_channel_unref(server->io);
	}

	if (server->record_id != 0) {
		adapter_service_remove(adapter, server->record_id);
		server->record_id = 0;
	}

	servers = g_slist_remove(servers, server);

	btd_adapter_unref(server->adapter);
	g_free(server);
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

	.adapter_probe  = hfp_adapter_probe,
	.adapter_remove = hfp_adapter_remove,

	.experimental	= true,
};

static int hfp_init(void)
{
	return btd_profile_register(&hfp_hf_profile);
}

static void hfp_exit(void)
{
	btd_profile_unregister(&hfp_hf_profile);
}

BLUETOOTH_PLUGIN_DEFINE(hfp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
		hfp_init, hfp_exit)
