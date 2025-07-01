// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <string.h>			// memcpy()
#include <sys/types.h>			// struct timeval [required by prov.h]

#include <ell/dbus.h>
//#include <ell/log.h>
//#include <ell/timeout.h>
#include <ell/util.h>			// l_new(), l_free()

#include "mesh/gatt-service.h"
#include "mesh/net.h"			// mesh_net_prov_caps, required by prov.h
#include "mesh/prov.h"			// mesh_prov_open_func_t,
					// mesh_prov_close_func_t,
					// mesh_prov_receive_func_t
#include "mesh/provision.h"		// PB_GATT
#include "mesh/pb-gatt.h"

#define MESH_GATT_PROV_SVC_UUID "0x1827"
#define MESH_GATT_PROV_CHRC_DATA_IN  "0x2ADB"
#define MESH_GATT_PROV_CHRC_DATA_OUT "0x2ADC"
#define MAX_PROXY_PROV_PDU_LEN 66  /* MshPRT_v1.1, section 7.1.3.1 / 7.1.3.2 */

struct pb_gatt_session {
	mesh_prov_open_func_t open_cb;
	mesh_prov_close_func_t close_cb;
	mesh_prov_receive_func_t rx_cb;
	mesh_prov_ack_func_t ack_cb;
//	struct l_timeout *tx_timeout;
	uint8_t uuid[16];
	uint16_t oob_info;

	struct gatt_service *gatt_service;
	void *user_data;

	pb_gatt_destroy_cb destroy_cb;
	void *destroy_data;
};

static struct pb_gatt_session *pb_session = NULL;

static void pb_gatt_tx(void *user_data, const void *data, uint16_t len)
{
	struct pb_gatt_session *session = user_data;

	gatt_service_tx(session->gatt_service, PROXY_MSG_TYPE_PROV_PDU, data, len);
}

static void gatt_notify_acquired_cb(void *user_data)
{
	struct pb_gatt_session *session = user_data;

	/*
	 * MshPRT_v1.1, section 5.2.2: The link is opened on a PB-GATT
	 * bearer when the PB-GATT Client enables notifications.
	 */
	session->open_cb(session->user_data, pb_gatt_tx, session, PB_GATT);
}

static void gatt_notify_stopped_cb(void *user_data)
{
	struct pb_gatt_session *session = user_data;

	session->close_cb(session->user_data, PROV_ERR_UNEXPECTED_ERR);
}

static void gatt_rx_cb(void *user_data, enum proxy_msg_type msg_type,
						const void *data, uint16_t len)
{
	struct pb_gatt_session *session = user_data;

	if (msg_type == PROXY_MSG_TYPE_PROV_PDU)
		session->rx_cb(session->user_data, data + 1, len - 1);
}

static bool gatt_tx_cmplt_cb(void *user_data)
{
	struct pb_gatt_session *session = user_data;

	session->ack_cb(session->user_data, 0 /* don't care */);
	return false;
}

static bool gatt_fill_adv_service_data_cb(void *user_data,
					struct l_dbus_message_builder *builder)
{
	struct pb_gatt_session *session = user_data;
	uint8_t oob_info[2];
	int i;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < sizeof(session->uuid); i++)
		l_dbus_message_builder_append_basic(builder, 'y',
							&(session->uuid[i]));
	l_put_be16(session->oob_info, oob_info);
	for (i = 0; i < sizeof(oob_info); i++)
		l_dbus_message_builder_append_basic(builder, 'y',
							&(oob_info[i]));
	l_dbus_message_builder_leave_array(builder);

	return true;
}

bool pb_gatt_reg(mesh_prov_open_func_t open_cb, mesh_prov_close_func_t close_cb,
		mesh_prov_receive_func_t rx_cb, mesh_prov_ack_func_t ack_cb,
		const uint8_t *uuid, uint16_t oob_info, void *user_data)
{
	pb_session = l_new(struct pb_gatt_session, 1);

	pb_session->open_cb = open_cb;
	pb_session->close_cb = close_cb;
	pb_session->rx_cb = rx_cb;
	pb_session->ack_cb = ack_cb;

	memcpy(pb_session->uuid, uuid, 16);
	pb_session->user_data = user_data;

	pb_session->gatt_service = gatt_service_create(MESH_GATT_PROV_SVC_UUID,
						MESH_GATT_PROV_CHRC_DATA_IN,
						MESH_GATT_PROV_CHRC_DATA_OUT,
						MAX_PROXY_PROV_PDU_LEN,
						gatt_notify_acquired_cb,
						gatt_notify_stopped_cb,
						gatt_rx_cb, gatt_tx_cmplt_cb,
						gatt_fill_adv_service_data_cb,
						pb_session);
	if (!pb_session->gatt_service) {
		l_free(pb_session);
		pb_session = NULL;
		return false;
	}

	return true;
}

static void gatt_destroy_finished(void *user_data)
{
	pb_gatt_destroy_cb destroy_cb;
	void *destroy_data;

	if (!pb_session || pb_session != user_data)
		return;

	destroy_cb = pb_session->destroy_cb;
	destroy_data = pb_session->destroy_data;

	l_free(pb_session);
	pb_session = NULL;

	if (destroy_cb)
		destroy_cb(destroy_data);
}

void pb_gatt_unreg(void *user_data, pb_gatt_destroy_cb destroy_cb,
							void *destroy_data)
{
	if (!pb_session || pb_session->user_data != user_data)
		return;

	pb_session->destroy_cb = destroy_cb;
	pb_session->destroy_data = destroy_data;
	gatt_service_destroy(pb_session->gatt_service, gatt_destroy_finished,
								pb_session);
}
