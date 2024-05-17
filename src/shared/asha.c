// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  Asymptotic Inc.
 *
 *  Author: Arun Raghavan <arun@asymptotic.io>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "lib/bluetooth.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-db.h"
#include "src/log.h"

#include "asha.h"

/* We use strings instead of uint128_t to maintain readability */
#define ASHA_CHRC_READ_ONLY_PROPERTIES_UUID "6333651e-c481-4a3e-9169-7c902aad37bb"
#define ASHA_CHRC_AUDIO_CONTROL_POINT_UUID "f0d4de7e-4a88-476c-9d9f-1937b0996cc0"
#define ASHA_CHRC_AUDIO_STATUS_UUID "38663f1a-e711-4cac-b641-326b56404837"
#define ASHA_CHRC_VOLUME_UUID "00e4ca9e-ab14-41e4-8823-f9e70c7e91df"
#define ASHA_CHRC_LE_PSM_OUT_UUID "2d410339-82b6-42aa-b34e-e2e01df8cc1a"

/* 2 byte SDU length, 1 byte sequence number, and then 20ms of G.722 */
#define ASHA_MIN_MTU 163
#define ASHA_CONNECTION_MTU 512			/* The default of 672 does not
						 * work */

struct bt_asha_device *bt_asha_device_new(void)
{
	struct bt_asha_device *asha;

	asha = new0(struct bt_asha_device, 1);

	return asha;
}

void bt_asha_device_reset(struct bt_asha_device *asha)
{
	if (asha->status_notify_id) {
		bt_gatt_client_unregister_notify(asha->client,
						asha->status_notify_id);
	}

	gatt_db_unref(asha->db);
	asha->db = NULL;

	bt_gatt_client_unref(asha->client);
	asha->client = NULL;

	asha->psm = 0;
}

void bt_asha_state_reset(struct bt_asha_device *asha)
{
	close(asha->fd);
	asha->fd = -1;

	asha->state = ASHA_STOPPED;
	asha->resume_id = 0;

	asha->cb = NULL;
	asha->cb_user_data = NULL;
}

void bt_asha_device_free(struct bt_asha_device *asha)
{
	gatt_db_unref(asha->db);
	bt_gatt_client_unref(asha->client);
	free(asha);
}

uint16_t bt_asha_device_get_render_delay(struct bt_asha_device *asha)
{
	return asha->render_delay;
}

enum bt_asha_state_t bt_asha_device_get_state(struct bt_asha_device *asha)
{
	return asha->state;
}

int bt_asha_device_get_fd(struct bt_asha_device *asha)
{
	return asha->fd;
}

uint16_t bt_asha_device_get_omtu(struct bt_asha_device *asha)
{
	return asha->omtu;
}
uint16_t bt_asha_device_get_imtu(struct bt_asha_device *asha)
{
	return asha->imtu;
}

static int asha_connect_socket(struct bt_asha_device *asha)
{
	int fd = 0, err;
	struct sockaddr_l2 addr = { 0, };
	struct l2cap_options opts;
	socklen_t len;

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (fd < 0) {
		error("Could not open L2CAP CoC socket: %s", strerror(errno));
		goto error;
	}

	addr.l2_family = AF_BLUETOOTH;
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

	/*
	 * We need to bind before connect to work around getting the wrong addr
	 * type on older(?) kernels
	 */
	err = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		error("Could not bind L2CAP CoC socket: %s", strerror(errno));
		goto error;
	}

	addr.l2_psm = asha->psm;
	bacpy(&addr.l2_bdaddr, device_get_address(asha->device));

	opts.mode = BT_MODE_LE_FLOWCTL;
	opts.omtu = opts.imtu = ASHA_MIN_MTU;

	err = setsockopt(fd, SOL_BLUETOOTH, BT_MODE, &opts.mode,
							sizeof(opts.mode));
	if (err < 0) {
		error("Could not set L2CAP CoC socket flow control mode: %s",
				strerror(errno));
		/* Let this be non-fatal? */
	}

	opts.imtu = ASHA_CONNECTION_MTU;
	err = setsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU, &opts.imtu,
							sizeof(opts.imtu));
	if (err < 0) {
		error("Could not set L2CAP CoC socket receive MTU: %s",
				strerror(errno));
		/* Let this be non-fatal? */
	}

	err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		error("Could not connect L2CAP CoC socket: %s",
							strerror(errno));
		goto error;
	}

	err = getsockopt(fd, SOL_BLUETOOTH, BT_SNDMTU, &opts.omtu, &len);
	if (err < 0) {
		error("Could not get L2CAP CoC socket receive MTU: %s",
				strerror(errno));
		/* Let this be non-fatal? */
	}

	err = getsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU, &opts.imtu, &len);
	if (err < 0) {
		error("Could not get L2CAP CoC socket receive MTU: %s",
				strerror(errno));
		/* Let this be non-fatal? */
	}

	asha->fd = fd;
	asha->imtu = opts.imtu;
	asha->omtu = opts.omtu;

	DBG("L2CAP CoC socket is open");
	return 0;

error:
	if (fd)
		close(fd);
	return -1;
}

static void asha_acp_sent(bool success, uint8_t err, void *user_data)
{
	struct bt_asha_device *asha = user_data;

	if (success) {
		DBG("AudioControlPoint command successfully sent");
	} else {
		error("Failed to send AudioControlPoint command: %d", err);

		if (asha->cb)
			asha->cb(-1, asha->cb_user_data);

		bt_asha_state_reset(asha);
	}
}

static int asha_send_acp(struct bt_asha_device *asha, uint8_t *cmd,
		unsigned int len, bt_asha_cb_t cb, void *user_data)
{
	if (!bt_gatt_client_write_value(asha->client, asha->acp_handle, cmd,
				len, asha_acp_sent, asha, NULL)) {
		error("Error writing ACP start");
		return -1;
	}

	asha->cb = cb;
	asha->cb_user_data = user_data;

	return 0;
}

unsigned int bt_asha_device_start(struct bt_asha_device *asha, bt_asha_cb_t cb,
		void *user_data)
{
	uint8_t acp_start_cmd[] = {
		0x01,		/* START */
		0x01,		/* G.722, 16 kHz */
		0,		/* Unknown media type */
		asha->volume,	/* Volume */
		0,		/* Other disconnected */
	};
	int ret;

	if (asha->state != ASHA_STOPPED) {
		error("ASHA device start failed. Bad state %d", asha->state);
		return 0;
	}

	ret = asha_connect_socket(asha);
	if (ret < 0)
		return 0;

	ret = asha_send_acp(asha, acp_start_cmd, sizeof(acp_start_cmd), cb,
			user_data);
	if (ret < 0)
		return 0;

	asha->state = ASHA_STARTING;

	return (++asha->resume_id);
}

unsigned int bt_asha_device_stop(struct bt_asha_device *asha, bt_asha_cb_t cb,
		void *user_data)
{
	uint8_t acp_stop_cmd[] = {
		0x02, /* STOP */
	};
	int ret;

	if (asha->state != ASHA_STARTED)
		return 0;

	asha->state = ASHA_STOPPING;

	ret = asha_send_acp(asha, acp_stop_cmd, sizeof(acp_stop_cmd), cb,
			user_data);
	if (ret < 0)
		return 0;

	return asha->resume_id;
}

int8_t bt_asha_device_get_volume(struct bt_asha_device *asha)
{
	return asha->volume;
}

bool bt_asha_device_set_volume(struct bt_asha_device *asha, int8_t volume)
{
	if (!bt_gatt_client_write_without_response(asha->client,
						asha->volume_handle, false,
						(const uint8_t *)&volume, 1)) {
		error("Error writing volume");
		return false;
	}

	asha->volume = volume;
	return true;
}

static bool uuid_cmp(const char *uuid1, const bt_uuid_t *uuid2)
{
	bt_uuid_t lhs;

	bt_string_to_uuid(&lhs, uuid1);

	return bt_uuid_cmp(&lhs, uuid2) == 0;
}

static void read_psm(bool success,
			uint8_t att_ecode,
			const uint8_t *value,
			uint16_t length,
			void *user_data)
{
	struct bt_asha_device *asha = user_data;

	if (!success) {
		DBG("Reading PSM failed with ATT error: %u", att_ecode);
		return;
	}

	if (length != 2) {
		DBG("Reading PSM failed: unexpected length %u", length);
		return;
	}

	asha->psm = get_le16(value);

	DBG("Got PSM: %u", asha->psm);
}

static void read_rops(bool success,
			uint8_t att_ecode,
			const uint8_t *value,
			uint16_t length,
			void *user_data)
{
	struct bt_asha_device *asha = user_data;

	if (!success) {
		DBG("Reading ROPs failed with ATT error: %u", att_ecode);
		return;
	}

	if (length != 17) {
		DBG("Reading ROPs failed: unexpected length %u", length);
		return;
	}

	if (value[0] != 0x01) {
		DBG("Unexpected ASHA version: %u", value[0]);
		return;
	}

	/* Device Capabilities */
	asha->right_side = (value[1] & 0x1) != 0;
	asha->binaural = (value[1] & 0x2) != 0;
	asha->csis_supported = (value[1] & 0x4) != 0;
	/* HiSyncId: 2 byte company id, 6 byte ID shared by left and right */
	memcpy(asha->hisyncid, &value[2], 8);
	/* FeatureMap */
	asha->coc_streaming_supported = (value[10] & 0x1) != 0;
	/* RenderDelay */
	asha->render_delay = get_le16(&value[11]);
	/* byte 13 & 14 are reserved */
	/* Codec IDs */
	asha->codec_ids = get_le16(&value[15]);

	DBG("Got ROPS: side %u, binaural %u, csis: %u, delay %u, codecs: %u",
			asha->right_side, asha->binaural, asha->csis_supported,
			asha->render_delay, asha->codec_ids);
}

static void audio_status_register(uint16_t att_ecode, void *user_data)
{
	if (att_ecode)
		DBG("AudioStatusPoint register failed 0x%04x", att_ecode);
	else
		DBG("AudioStatusPoint register succeeded");
}

static void audio_status_notify(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct bt_asha_device *asha = user_data;
	uint8_t status = *value;
	/* Back these up to survive the reset paths */
	bt_asha_cb_t cb = asha->cb;
	bt_asha_cb_t cb_user_data = asha->cb_user_data;

	if (asha->state == ASHA_STARTING) {
		if (status == 0) {
			asha->state = ASHA_STARTED;
			DBG("ASHA start complete");
		} else {
			bt_asha_state_reset(asha);
			DBG("ASHA start failed");
		}
	} else if (asha->state == ASHA_STOPPING) {
		/* We reset our state, regardless */
		bt_asha_state_reset(asha);
		DBG("ASHA stop %s", status == 0 ? "complete" : "failed");
	}

	if (cb) {
		cb(status, cb_user_data);
		asha->cb = NULL;
		asha->cb_user_data = NULL;
	}
}

static void handle_characteristic(struct gatt_db_attribute *attr,
								void *user_data)
{
	struct bt_asha_device *asha = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle, NULL,
								NULL, &uuid)) {
		error("Failed to obtain characteristic data");
		return;
	}

	if (uuid_cmp(ASHA_CHRC_LE_PSM_OUT_UUID, &uuid)) {
		if (!bt_gatt_client_read_value(asha->client, value_handle,
					read_psm, asha, NULL))
			DBG("Failed to send request to read PSM");
	} else if (uuid_cmp(ASHA_CHRC_READ_ONLY_PROPERTIES_UUID, &uuid)) {
		if (!bt_gatt_client_read_value(asha->client, value_handle,
					read_rops, asha, NULL))
			DBG("Failed to send request for readonly properties");
	} else if (uuid_cmp(ASHA_CHRC_AUDIO_CONTROL_POINT_UUID, &uuid)) {
		/* Store this for later writes */
		asha->acp_handle = value_handle;
	} else if (uuid_cmp(ASHA_CHRC_VOLUME_UUID, &uuid)) {
		/* Store this for later writes */
		asha->volume_handle = value_handle;
	} else if (uuid_cmp(ASHA_CHRC_AUDIO_STATUS_UUID, &uuid)) {
		asha->status_notify_id =
			bt_gatt_client_register_notify(asha->client,
				value_handle, audio_status_register,
				audio_status_notify, asha, NULL);
		if (!asha->status_notify_id)
			DBG("Failed to send request to notify AudioStatus");
	} else {
		char uuid_str[MAX_LEN_UUID_STR];

		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		DBG("Unsupported characteristic: %s", uuid_str);
	}
}

static void foreach_asha_service(struct gatt_db_attribute *attr,
							void *user_data)
{
	struct bt_asha_device *asha = user_data;

	DBG("Found ASHA GATT service");

	asha->attr = attr;
	gatt_db_service_foreach_char(asha->attr, handle_characteristic, asha);
}

bool bt_asha_device_probe(struct bt_asha_device *asha)
{
	struct btd_device *device = asha->device;
	struct gatt_db *db = btd_device_get_gatt_db(device);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	bt_uuid_t asha_uuid;

	asha->db = gatt_db_ref(db);
	asha->client = bt_gatt_client_clone(client);

	bt_uuid16_create(&asha_uuid, ASHA_SERVICE);
	gatt_db_foreach_service(db, &asha_uuid, foreach_asha_service, asha);

	if (!asha->attr) {
		error("ASHA attribute not found");
		bt_asha_device_reset(asha);
		return false;
	}

	return true;
}
