/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/sdp-client.h"
#include "src/uuid-helper.h"
#include "src/shared/hfp.h"
#include "btio/btio.h"
#include "handsfree.h"
#include "bluetooth.h"
#include "src/log.h"
#include "hal-msg.h"
#include "ipc.h"
#include "utils.h"

#define HFP_AG_CHANNEL 13
#define HFP_AG_FEATURES 0

static struct {
	bdaddr_t bdaddr;
	uint8_t state;
	GIOChannel *io;
	guint watch;
	struct hfp_gw *gw;
} device;

static bdaddr_t adapter_addr;
static uint32_t record_id = 0;

static GIOChannel *server = NULL;

static void device_set_state(uint8_t state)
{
	struct hal_ev_handsfree_conn_state ev;
	char address[18];

	if (device.state == state)
		return;

	device.state = state;

	ba2str(&device.bdaddr, address);
	DBG("device %s state %u", address, state);

	bdaddr2android(&device.bdaddr, ev.bdaddr);
	ev.state = state;

	ipc_send_notif(HAL_SERVICE_ID_HANDSFREE, HAL_EV_HANDSFREE_CONN_STATE,
							sizeof(ev), &ev);
}

static void device_init(const bdaddr_t *bdaddr)
{
	bacpy(&device.bdaddr, bdaddr);

	device_set_state(HAL_EV_HANDSFREE_CONNECTION_STATE_CONNECTING);
}

static void device_cleanup(void)
{
	if (device.gw) {
		hfp_gw_unref(device.gw);
		device.gw = NULL;
	}

	if (device.watch) {
		g_source_remove(device.watch);
		device.watch = 0;
	}

	if (device.io) {
		g_io_channel_unref(device.io);
		device.io = NULL;
	}

	device_set_state(HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTED);

	memset(&device, 0, sizeof(device));
}

static gboolean watch_cb(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	DBG("");

	device.watch = 0;

	device_cleanup();

	return FALSE;
}

static void at_command_handler(const char *command, void *user_data)
{
	hfp_gw_send_result(device.gw, HFP_RESULT_ERROR);

	g_io_channel_shutdown(device.io, TRUE, NULL);
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	DBG("");

	if (err) {
		error("handsfree: connect failed (%s)", err->message);
		goto failed;
	}

	g_io_channel_set_close_on_unref(chan, TRUE);

	device.gw = hfp_gw_new(g_io_channel_unix_get_fd(chan));
	if (!device.gw)
		goto failed;

	hfp_gw_set_close_on_unref(device.gw, true);
	hfp_gw_set_command_handler(device.gw, at_command_handler, NULL, NULL);

	device.watch = g_io_add_watch(chan,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					watch_cb, NULL);
	if (device.watch == 0)
		goto failed;

	device.io = g_io_channel_ref(chan);

	device_set_state(HAL_EV_HANDSFREE_CONNECTION_STATE_CONNECTED);

	return;

failed:
	g_io_channel_shutdown(chan, TRUE, NULL);
	device_cleanup();
}

static void confirm_cb(GIOChannel *chan, gpointer data)
{
	char address[18];
	bdaddr_t bdaddr;
	GError *err = NULL;

	bt_io_get(chan, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_DEST_BDADDR, &bdaddr,
			BT_IO_OPT_INVALID);
	if (err) {
		error("handsfree: confirm failed (%s)", err->message);
		g_error_free(err);
		goto drop;
	}

	DBG("incoming connect from %s", address);

	if (device.state != HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTED) {
		info("handsfree: refusing connection from %s", address);
		goto drop;
	}

	device_init(&bdaddr);

	if (!bt_io_accept(chan, connect_cb, NULL, NULL, NULL)) {
		error("handsfree: failed to accept connection");
		device_cleanup();
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

static void sdp_search_cb(sdp_list_t *recs, int err, gpointer data)
{
	sdp_list_t *protos, *classes;
	GError *gerr = NULL;
	GIOChannel *io;
	uuid_t uuid;
	int channel;

	DBG("");

	if (err < 0) {
		error("handsfree: unable to get SDP record: %s", strerror(-err));
		goto fail;
	}

	if (!recs || !recs->data) {
		error("handsfree: no SDP records found");
		goto fail;
	}

	if (sdp_get_service_classes(recs->data, &classes) < 0) {
		error("handsfree: unable to get service classes from record");
		goto fail;
	}

	if (sdp_get_access_protos(recs->data, &protos) < 0) {
		error("handsfree: unable to get access protocols from record");
		sdp_list_free(classes, free);
		goto fail;
	}

	/* TODO read remote version? */

	memcpy(&uuid, classes->data, sizeof(uuid));
	sdp_list_free(classes, free);

	if (!sdp_uuid128_to_uuid(&uuid) || uuid.type != SDP_UUID16 ||
			uuid.value.uuid16 != HANDSFREE_SVCLASS_ID) {
		sdp_list_free(protos, NULL);
		error("handsfree: invalid service record or not HFP");
		goto fail;
	}

	channel = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (channel <= 0) {
		error("handsfree: unable to get RFCOMM channel from record");
		goto fail;
	}

	io = bt_io_connect(connect_cb, NULL, NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_DEST_BDADDR, &device.bdaddr,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_CHANNEL, channel,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("handsfree: unable to connect: %s", gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	g_io_channel_unref(io);
	return;

fail:
	device_cleanup();
}

static void handle_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_handsfree_connect *cmd = buf;
	char addr[18];
	uint8_t status;
	uuid_t uuid;
	bdaddr_t bdaddr;

	DBG("");

	if (device.state != HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTED) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2bdaddr(&cmd->bdaddr, &bdaddr);

	ba2str(&bdaddr, addr);
	DBG("connecting to %s", addr);

	device_init(&bdaddr);

	sdp_uuid16_create(&uuid, HANDSFREE_SVCLASS_ID);
	if (bt_search_service(&adapter_addr, &device.bdaddr, &uuid,
					sdp_search_cb, NULL, NULL, 0) < 0) {
		error("handsfree: SDP search failed");
		device_cleanup();
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CONNECT,
									status);
}

static void handle_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_handsfree_disconnect *cmd = buf;
	bdaddr_t bdaddr;
	uint8_t status;

	DBG("");

	android2bdaddr(cmd->bdaddr, &bdaddr);

	if (device.state == HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTED ||
			bacmp(&device.bdaddr, &bdaddr)) {
		status = HAL_STATUS_FAILED;
		goto failed;

	}

	if (device.state == HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTING) {
		status = HAL_STATUS_SUCCESS;
		goto failed;
	}

	if (device.io) {
		device_set_state(HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTING);
		g_io_channel_shutdown(device.io, TRUE, NULL);
	} else {
		device_cleanup();
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_DISCONNECT,
									status);
}

static void handle_connect_audio(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CONNECT_AUDIO,
							HAL_STATUS_FAILED);
}

static void handle_disconnect_audio(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
			HAL_OP_HANDSFREE_DISCONNECT_AUDIO, HAL_STATUS_FAILED);
}

static void handle_start_vr(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_START_VR,
							HAL_STATUS_FAILED);
}

static void handle_stop_vr(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_STOP_VR,
							HAL_STATUS_FAILED);
}

static void handle_volume_control(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_VOLUME_CONTROL,
							HAL_STATUS_FAILED);
}

static void handle_device_status_notif(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_DEVICE_STATUS_NOTIF,
					HAL_STATUS_FAILED);
}

static void handle_cops(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_COPS_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_cind(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CIND_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_formatted_at_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_FORMATTED_AT_RESPONSE,
					HAL_STATUS_FAILED);
}

static void handle_at_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_AT_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_clcc_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CLCC_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_phone_state_change(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_PHONE_STATE_CHANGE,
					HAL_STATUS_FAILED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_HANDSFREE_CONNECT */
	{ handle_connect, false, sizeof(struct hal_cmd_handsfree_connect)},
	/* HAL_OP_HANDSFREE_DISCONNECT */
	{handle_disconnect, false, sizeof(struct hal_cmd_handsfree_disconnect)},
	/*HAL_OP_HANDSFREE_CONNECT_AUDIO*/
	{handle_connect_audio, false,
			sizeof(struct hal_cmd_handsfree_connect_audio)},
	/*HAL_OP_HANDSFREE_DISCONNECT_AUDIO*/
	{handle_disconnect_audio, false,
			sizeof(struct hal_cmd_handsfree_disconnect_audio)},
	/* define HAL_OP_HANDSFREE_START_VR */
	{handle_start_vr, false, 0 },
	/* define HAL_OP_HANDSFREE_STOP_VR */
	{handle_stop_vr, false, 0 },
	/* HAL_OP_HANDSFREE_VOLUME_CONTROL */
	{handle_volume_control, false,
			sizeof(struct hal_cmd_handsfree_volume_control)},
	/* HAL_OP_HANDSFREE_DEVICE_STATUS_NOTIF */
	{handle_device_status_notif, false,
			sizeof(struct hal_cmd_handsfree_device_status_notif)},
	/* HAL_OP_HANDSFREE_COPS_RESPONSE */
	{handle_cops, true, sizeof(struct hal_cmd_handsfree_cops_response)},
	/* HAL_OP_HANDSFREE_CIND_RESPONSE */
	{ handle_cind, false, sizeof(struct hal_cmd_handsfree_cind_response)},
	/* HAL_OP_HANDSFREE_FORMATTED_AT_RESPONSE */
	{handle_formatted_at_resp, true,
			sizeof(struct hal_cmd_handsfree_formatted_at_response)},
	/* HAL_OP_HANDSFREE_AT_RESPONSE */
	{handle_at_resp, false, sizeof(struct hal_cmd_handsfree_at_response)},
	/* HAL_OP_HANDSFREE_CLCC_RESPONSE */
	{handle_clcc_resp, true,
			sizeof(struct hal_cmd_handsfree_clcc_response)},
	/* HAL_OP_HANDSFREE_PHONE_STATE_CHANGE */
	{handle_phone_state_change, true,
			sizeof(struct hal_cmd_handsfree_phone_state_change)},
};

static sdp_record_t *handsfree_ag_record(void)
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
	uint8_t ch = HFP_AG_CHANNEL;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	network = sdp_data_alloc(SDP_UINT8, &netid);
	if (!network) {
		sdp_record_free(record);
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0106;
	pfseq = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdpfeat = HFP_AG_FEATURES;
	features = sdp_data_alloc(SDP_UINT16, &sdpfeat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free Audio Gateway", NULL, NULL);

	sdp_attr_add(record, SDP_ATTR_EXTERNAL_NETWORK, network);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

bool bt_handsfree_register(const bdaddr_t *addr)
{
	sdp_record_t *rec;
	GError *err = NULL;

	DBG("");

	bacpy(&adapter_addr, addr);

	server =  bt_io_listen( NULL, confirm_cb, NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_CHANNEL, HFP_AG_CHANNEL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_INVALID);
	if (!server) {
		error("Failed to listen on Handsfree rfcomm: %s", err->message);
		g_error_free(err);
		return false;
	}

	rec = handsfree_ag_record();
	if (!rec) {
		error("Failed to allocate Handsfree record");
		goto failed;
	}

	if (bt_adapter_add_record(rec, 0) < 0) {
		error("Failed to register Handsfree record");
		sdp_record_free(rec);
		goto failed;
	}
	record_id = rec->handle;

	ipc_register(HAL_SERVICE_ID_HANDSFREE, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;

failed:
	g_io_channel_shutdown(server, TRUE, NULL);
	g_io_channel_unref(server);
	server = NULL;

	return false;
}

void bt_handsfree_unregister(void)
{
	DBG("");

	ipc_unregister(HAL_SERVICE_ID_HANDSFREE);

	if (server) {
		g_io_channel_shutdown(server, TRUE, NULL);
		g_io_channel_unref(server);
		server = NULL;
	}

	bt_adapter_remove_record(record_id);
	record_id = 0;
}
