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

#include <stdbool.h>
#include <errno.h>
#include <glib.h>

#include "btio/btio.h"
#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/log.h"
#include "avctp.h"
#include "avrcp-lib.h"
#include "hal-msg.h"
#include "ipc-common.h"
#include "ipc.h"
#include "bluetooth.h"
#include "avrcp.h"

#define L2CAP_PSM_AVCTP 0x17

#define AVRCP_FEATURE_CATEGORY_1	0x0001
#define AVRCP_FEATURE_CATEGORY_2	0x0002
#define AVRCP_FEATURE_CATEGORY_3	0x0004
#define AVRCP_FEATURE_CATEGORY_4	0x0008

static bdaddr_t adapter_addr;
static uint32_t record_id = 0;
static GSList *devices = NULL;
static GIOChannel *server = NULL;
static struct ipc *hal_ipc = NULL;

struct avrcp_request {
	struct avrcp_device *dev;
	uint8_t pdu_id;
	uint8_t transaction;
};

struct avrcp_device {
	bdaddr_t	dst;
	struct avrcp	*session;
	GIOChannel	*io;
	GQueue		*queue;
};

static struct avrcp_request *pop_request(uint8_t pdu_id)
{
	GSList *l;

	for (l = devices; l; l = g_slist_next(l)) {
		struct avrcp_device *dev = l->data;
		GList *reqs = g_queue_peek_head_link(dev->queue);
		int i;

		for (i = 0; reqs; reqs = g_list_next(reqs), i++) {
			struct avrcp_request *req = reqs->data;

			if (req->pdu_id == pdu_id) {
				g_queue_pop_nth(dev->queue, i);
				return req;
			}
		}
	}

	return NULL;
}

static void handle_get_play_status(const void *buf, uint16_t len)
{
	const struct hal_cmd_avrcp_get_play_status *cmd = buf;
	uint8_t status;
	struct avrcp_request *req;
	int ret;

	DBG("");

	req = pop_request(AVRCP_GET_PLAY_STATUS);
	if (!req) {
		status = HAL_STATUS_FAILED;
		goto done;
	}

	ret = avrcp_get_play_status_rsp(req->dev->session, req->transaction,
					cmd->position, cmd->duration,
					cmd->status);
	if (ret < 0) {
		status = HAL_STATUS_FAILED;
		g_free(req);
		goto done;
	}

	status = HAL_STATUS_SUCCESS;
	g_free(req);

done:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
				HAL_OP_AVRCP_GET_PLAY_STATUS, status);
}

static void handle_list_player_attrs(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_LIST_PLAYER_ATTRS, HAL_STATUS_FAILED);
}

static void handle_list_player_values(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_LIST_PLAYER_VALUES, HAL_STATUS_FAILED);
}

static void handle_get_player_attrs(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_GET_PLAYER_ATTRS, HAL_STATUS_FAILED);
}

static void handle_get_player_attrs_text(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_GET_PLAYER_ATTRS_TEXT, HAL_STATUS_FAILED);
}

static void handle_get_player_values_text(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_GET_PLAYER_VALUES_TEXT, HAL_STATUS_FAILED);
}

static void handle_get_element_attrs_text(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_GET_ELEMENT_ATTRS_TEXT, HAL_STATUS_FAILED);
}

static void handle_set_player_attrs_value(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_SET_PLAYER_ATTRS_VALUE, HAL_STATUS_FAILED);
}

static void handle_register_notification(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_OP_AVRCP_REGISTER_NOTIFICATION, HAL_STATUS_FAILED);
}

static void handle_set_volume(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_AVRCP, HAL_OP_AVRCP_SET_VOLUME,
							HAL_STATUS_FAILED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_AVRCP_GET_PLAY_STATUS */
	{ handle_get_play_status, false,
			sizeof(struct hal_cmd_avrcp_get_play_status) },
	/* HAL_OP_AVRCP_LIST_PLAYER_ATTRS */
	{ handle_list_player_attrs, true,
			sizeof(struct hal_cmd_avrcp_list_player_attrs) },
	/* HAL_OP_AVRCP_LIST_PLAYER_VALUES */
	{ handle_list_player_values, true,
			sizeof(struct hal_cmd_avrcp_list_player_values) },
	/* HAL_OP_AVRCP_GET_PLAYER_ATTRS */
	{ handle_get_player_attrs, true,
			sizeof(struct hal_cmd_avrcp_get_player_attrs) },
	/* HAL_OP_AVRCP_GET_PLAYER_ATTRS_TEXT */
	{ handle_get_player_attrs_text, true,
			sizeof(struct hal_cmd_avrcp_get_player_attrs_text) },
	/* HAL_OP_AVRCP_GET_PLAYER_VALUES_TEXT */
	{ handle_get_player_values_text, true,
			sizeof(struct hal_cmd_avrcp_get_player_values_text) },
	/* HAL_OP_AVRCP_GET_ELEMENT_ATTRS_TEXT */
	{ handle_get_element_attrs_text, true,
			sizeof(struct hal_cmd_avrcp_get_element_attrs_text) },
	/* HAL_OP_AVRCP_SET_PLAYER_ATTRS_VALUE */
	{ handle_set_player_attrs_value, true,
			sizeof(struct hal_cmd_avrcp_set_player_attrs_value) },
	/* HAL_OP_AVRCP_REGISTER_NOTIFICATION */
	{ handle_register_notification, true,
			sizeof(struct hal_cmd_avrcp_register_notification) },
	/* HAL_OP_AVRCP_SET_VOLUME */
	{ handle_set_volume, false, sizeof(struct hal_cmd_avrcp_set_volume) },
};

static sdp_record_t *avrcp_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto_control, *proto_control[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = L2CAP_PSM_AVCTP;
	uint16_t avrcp_ver = 0x0100, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
					AVRCP_FEATURE_CATEGORY_2 |
					AVRCP_FEATURE_CATEGORY_3 |
					AVRCP_FEATURE_CATEGORY_4);

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto_control[0] = sdp_list_append(NULL, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto_control[0] = sdp_list_append(proto_control[0], psm);
	apseq = sdp_list_append(NULL, proto_control[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto_control[1] = sdp_list_append(NULL, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto_control[1] = sdp_list_append(proto_control[1], version);
	apseq = sdp_list_append(apseq, proto_control[1]);

	aproto_control = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto_control);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", NULL, NULL);

	sdp_data_free(psm);
	sdp_data_free(version);
	sdp_list_free(proto_control[0], NULL);
	sdp_list_free(proto_control[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto_control, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static void avrcp_device_free(void *data)
{
	struct avrcp_device *dev = data;

	g_queue_foreach(dev->queue, (GFunc) g_free, NULL);
	g_queue_free(dev->queue);

	if (dev->session)
		avrcp_shutdown(dev->session);

	if (dev->io) {
		g_io_channel_shutdown(dev->io, FALSE, NULL);
		g_io_channel_unref(dev->io);
	}

	g_free(dev);
}

static void avrcp_device_remove(struct avrcp_device *dev)
{
	devices = g_slist_remove(devices, dev);
	avrcp_device_free(dev);
}

static struct avrcp_device *avrcp_device_new(const bdaddr_t *dst)
{
	struct avrcp_device *dev;

	dev = g_new0(struct avrcp_device, 1);
	bacpy(&dev->dst, dst);
	devices = g_slist_prepend(devices, dev);

	return dev;
}

static int device_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct avrcp_device *dev = s;
	const bdaddr_t *dst = user_data;

	return bacmp(&dev->dst, dst);
}

static struct avrcp_device *avrcp_device_find(const bdaddr_t *dst)
{
	GSList *l;

	l = g_slist_find_custom(devices, dst, device_cmp);
	if (!l)
		return NULL;

	return l->data;
}

static void disconnect_cb(void *data)
{
	struct avrcp_device *dev = data;

	DBG("");

	dev->session = NULL;

	avrcp_device_remove(dev);
}

static bool handle_fast_forward(struct avrcp *session, bool pressed,
							void *user_data)
{
	struct hal_ev_avrcp_passthrough_cmd ev;

	DBG("pressed %s", pressed ? "true" : "false");

	ev.id = AVC_FAST_FORWARD;
	ev.state = pressed;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_EV_AVRCP_PASSTHROUGH_CMD, sizeof(ev), &ev);

	return true;
}

static bool handle_rewind(struct avrcp *session, bool pressed,
							void *user_data)
{
	struct hal_ev_avrcp_passthrough_cmd ev;

	DBG("pressed %s", pressed ? "true" : "false");

	ev.id = AVC_REWIND;
	ev.state = pressed;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_AVRCP,
			HAL_EV_AVRCP_PASSTHROUGH_CMD, sizeof(ev), &ev);

	return true;
}

static const struct avrcp_passthrough_handler passthrough_handlers[] = {
		{ AVC_FAST_FORWARD, handle_fast_forward },
		{ AVC_REWIND, handle_rewind },
		{ },
};

static ssize_t handle_get_capabilities_cmd(struct avrcp *session,
						uint8_t transaction,
						uint16_t params_len,
						uint8_t *params,
						void *user_data)
{
	DBG("");

	if (params_len != 1)
		return -EINVAL;

	switch (params[0]) {
	case CAP_COMPANY_ID:
		params[params_len++] = 1;
		hton24(&params[params_len], IEEEID_BTSIG);
		return params_len + 3;
	case CAP_EVENTS_SUPPORTED:
		/* Android do not provide this info via HAL so the list most
		 * be hardcoded according to what RegisterNotification can
		 * actually handle */
		params[params_len++] = 3;
		params[params_len++] = AVRCP_EVENT_STATUS_CHANGED;
		params[params_len++] = AVRCP_EVENT_TRACK_CHANGED;
		params[params_len++] = AVRCP_EVENT_PLAYBACK_POS_CHANGED;
		return params_len;
	}

	return -EINVAL;
}

static void push_request(struct avrcp_device *dev, uint8_t pdu_id,
							uint8_t transaction)
{
	struct avrcp_request *req;

	req = g_new0(struct avrcp_request, 1);
	req->dev = dev;
	req->pdu_id = pdu_id;
	req->transaction = transaction;

	g_queue_push_tail(dev->queue, req);
}

static ssize_t handle_get_play_status_cmd(struct avrcp *session,
						uint8_t transaction,
						uint16_t params_len,
						uint8_t *params,
						void *user_data)
{
	struct avrcp_device *dev = user_data;

	DBG("");

	if (params_len != 0)
		return -EINVAL;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_AVRCP,
					HAL_EV_AVRCP_GET_PLAY_STATUS, 0, NULL);

	push_request(dev, AVRCP_GET_PLAY_STATUS, transaction);

	return -EAGAIN;
}

static const struct avrcp_control_handler control_handlers[] = {
		{ AVRCP_GET_CAPABILITIES,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					handle_get_capabilities_cmd },
		{ AVRCP_GET_PLAY_STATUS,
					AVC_CTYPE_STATUS, AVC_CTYPE_STABLE,
					handle_get_play_status_cmd },
		{ },
};

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct avrcp_device *dev;
	bdaddr_t src, dst;
	char address[18];
	uint16_t imtu, omtu;
	GError *gerr = NULL;
	int fd;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_OMTU, &omtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);

	dev = avrcp_device_find(&dst);
	if (dev) {
		if (dev->session) {
			error("Unexpected connection");
			return;
		}
	} else {
		DBG("Incoming connection from %s", address);
		dev = avrcp_device_new(&dst);
	}

	fd = g_io_channel_unix_get_fd(chan);

	dev->session = avrcp_new(fd, imtu, omtu, 0x0100);
	if (!dev->session) {
		avrcp_device_free(dev);
		return;
	}

	avrcp_set_destroy_cb(dev->session, disconnect_cb, dev);
	avrcp_set_passthrough_handlers(dev->session, passthrough_handlers,
									dev);
	avrcp_set_control_handlers(dev->session, control_handlers, dev);

	dev->queue = g_queue_new();

	/* FIXME: get the real name of the device */
	avrcp_init_uinput(dev->session, "bluetooth", address);

	g_io_channel_set_close_on_unref(chan, FALSE);

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	DBG("%s connected", address);
}

bool bt_avrcp_register(struct ipc *ipc, const bdaddr_t *addr, uint8_t mode)
{
	GError *err = NULL;
	sdp_record_t *rec;

	DBG("");

	bacpy(&adapter_addr, addr);

	server = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_PSM, L2CAP_PSM_AVCTP,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_INVALID);
	if (!server) {
		error("Failed to listen on AVDTP channel: %s", err->message);
		g_error_free(err);
		return false;
	}

	rec = avrcp_record();
	if (!rec) {
		error("Failed to allocate AVRCP record");
		goto fail;
	}

	if (bt_adapter_add_record(rec, 0) < 0) {
		error("Failed to register AVRCP record");
		sdp_record_free(rec);
		goto fail;
	}
	record_id = rec->handle;

	hal_ipc = ipc;

	ipc_register(hal_ipc, HAL_SERVICE_ID_AVRCP, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
fail:
	g_io_channel_shutdown(server, TRUE, NULL);
	g_io_channel_unref(server);
	server = NULL;

	return false;
}

void bt_avrcp_unregister(void)
{
	DBG("");

	g_slist_free_full(devices, avrcp_device_free);
	devices = NULL;

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_AVRCP);
	hal_ipc = NULL;

	bt_adapter_remove_record(record_id);
	record_id = 0;

	if (server) {
		g_io_channel_shutdown(server, TRUE, NULL);
		g_io_channel_unref(server);
		server = NULL;
	}
}

static bool avrcp_device_connect(struct avrcp_device *dev, BtIOConnect cb)
{
	GError *err = NULL;

	dev->io = bt_io_connect(cb, dev, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_AVCTP,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		return false;
	}

	return true;
}

void bt_avrcp_connect(const bdaddr_t *dst)
{
	struct avrcp_device *dev;
	char addr[18];

	DBG("");

	if (avrcp_device_find(dst))
		return;

	dev = avrcp_device_new(dst);
	if (!avrcp_device_connect(dev, connect_cb)) {
		avrcp_device_free(dev);
		return;
	}

	ba2str(&dev->dst, addr);
	DBG("connecting to %s", addr);
}

void bt_avrcp_disconnect(const bdaddr_t *dst)
{
	struct avrcp_device *dev;

	DBG("");

	dev = avrcp_device_find(dst);
	if (!dev)
		return;

	if (dev->session) {
		avrcp_shutdown(dev->session);
		return;
	}

	avrcp_device_remove(dev);
}
