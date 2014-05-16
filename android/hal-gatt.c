/*
 * Copyright (C) 2014 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "ipc-common.h"
#include "hal-ipc.h"
#include "hal-utils.h"

static const btgatt_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

static void gatt_id_from_hal(btgatt_gatt_id_t *to,
						struct hal_gatt_gatt_id *from)
{
	memcpy(&to->uuid, from->uuid, sizeof(to->uuid));
	to->inst_id = from->inst_id;
}

static void gatt_id_to_hal(struct hal_gatt_gatt_id *to, btgatt_gatt_id_t *from)
{
	memcpy(to->uuid, &from->uuid, sizeof(from->uuid));
	to->inst_id = from->inst_id;
}

static void srvc_id_from_hal(btgatt_srvc_id_t *to,
						struct hal_gatt_srvc_id *from)
{
	memcpy(&to->id.uuid, from->uuid, sizeof(to->id.uuid));
	to->id.inst_id = from->inst_id;
	to->is_primary = from->is_primary;
}

static void srvc_id_to_hal(struct hal_gatt_srvc_id *to, btgatt_srvc_id_t *from)
{
	memcpy(to->uuid, &from->id.uuid, sizeof(from->id.uuid));
	to->inst_id = from->id.inst_id;
	to->is_primary = from->is_primary;
}

/* Client Event Handlers */

static void handle_register_client(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_register_client *ev = buf;

	if (cbs->client->register_client_cb)
		cbs->client->register_client_cb(ev->status, ev->client_if,
						(bt_uuid_t *) ev->app_uuid);
}

static void handle_scan_result(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_scan_result *ev = buf;
	uint8_t ad[62];

	if (len != sizeof(*ev) + ev->len ) {
		error("gatt: invalid scan result event, aborting");
		exit(EXIT_FAILURE);
	}

	/* Java assumes that passed data has 62 bytes */
	memset(ad, 0, sizeof(ad));
	memcpy(ad, ev->adv_data, ev->len > sizeof(ad) ? sizeof(ad) : ev->len);

	if (cbs->client->scan_result_cb)
		cbs->client->scan_result_cb((bt_bdaddr_t *) ev->bda, ev->rssi,
									ad);
}

static void handle_connect(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_connect *ev = buf;

	if (cbs->client->open_cb)
		cbs->client->open_cb(ev->conn_id, ev->status, ev->client_if,
						(bt_bdaddr_t *) ev->bda);
}

static void handle_disconnect(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_disconnect *ev = buf;

	if (cbs->client->close_cb)
		cbs->client->close_cb(ev->conn_id, ev->status, ev->client_if,
						(bt_bdaddr_t *) ev->bda);
}

static void handle_search_complete(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_search_complete *ev = buf;

	if (cbs->client->search_complete_cb)
		cbs->client->search_complete_cb(ev->conn_id, ev->status);
}

static void handle_search_result(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_search_result *ev = buf;
	btgatt_srvc_id_t srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);

	if (cbs->client->search_result_cb)
		cbs->client->search_result_cb(ev->conn_id, &srvc_id);
}

static void handle_get_characteristic(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_get_characteristic *ev = buf;
	btgatt_gatt_id_t char_id;
	btgatt_srvc_id_t srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);
	gatt_id_from_hal(&char_id, &ev->char_id);

	if (cbs->client->get_characteristic_cb)
		cbs->client->get_characteristic_cb(ev->conn_id, ev->status,
							&srvc_id, &char_id,
							ev->char_prop);
}

static void handle_get_descriptor(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_get_descriptor *ev = buf;
	btgatt_gatt_id_t descr_id;
	btgatt_gatt_id_t char_id;
	btgatt_srvc_id_t srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);
	gatt_id_from_hal(&char_id, &ev->char_id);
	gatt_id_from_hal(&descr_id, &ev->descr_id);

	if (cbs->client->get_descriptor_cb)
		cbs->client->get_descriptor_cb(ev->conn_id, ev->status,
						&srvc_id, &char_id, &descr_id);
}

static void handle_get_included_service(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_get_inc_service *ev = buf;
	btgatt_srvc_id_t srvc_id;
	btgatt_srvc_id_t incl_srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);
	srvc_id_from_hal(&incl_srvc_id, &ev->incl_srvc_id);

	if (cbs->client->get_included_service_cb)
		cbs->client->get_included_service_cb(ev->conn_id, ev->status,
								&srvc_id,
								&incl_srvc_id);
}

static void handle_register_for_notification(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_reg_for_notif *ev = buf;
	btgatt_gatt_id_t char_id;
	btgatt_srvc_id_t srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);
	gatt_id_from_hal(&char_id, &ev->char_id);

	if (cbs->client->register_for_notification_cb)
		cbs->client->register_for_notification_cb(ev->conn_id,
								ev->registered,
								ev->status,
								&srvc_id,
								&char_id);
}

static void handle_notify(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_notify *ev = buf;
	btgatt_notify_params_t params;

	if (len != sizeof(*ev) + ev->len ) {
		error("gatt: invalid notify event, aborting");
		exit(EXIT_FAILURE);
	}

	memset(&params, 0, sizeof(params));
	memcpy(params.value, ev->value, ev->len);
	memcpy(&params.bda, ev->bda, sizeof(params.bda));

	srvc_id_from_hal(&params.srvc_id, &ev->srvc_id);
	gatt_id_from_hal(&params.char_id, &ev->char_id);

	params.len = ev->len;
	params.is_notify = ev->is_notify;

	if (cbs->client->notify_cb)
		cbs->client->notify_cb(ev->conn_id, &params);
}

static void handle_read_characteristic(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_read_characteristic *ev = buf;
	btgatt_read_params_t params;

	if (len != sizeof(*ev) + ev->data.len ) {
		error("gatt: invalid read characteristic event, aborting");
		exit(EXIT_FAILURE);
	}

	memset(&params, 0, sizeof(params));

	srvc_id_from_hal(&params.srvc_id, &ev->data.srvc_id);
	gatt_id_from_hal(&params.char_id, &ev->data.char_id);
	gatt_id_from_hal(&params.descr_id, &ev->data.descr_id);

	memcpy(&params.value.value, ev->data.value, ev->data.len);

	params.value_type = ev->data.value_type;
	params.value.len = ev->data.len;
	params.status = ev->data.status;

	if (cbs->client->read_characteristic_cb)
		cbs->client->read_characteristic_cb(ev->conn_id, ev->status,
								&params);
}

static void handle_write_characteristic(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_write_characteristic *ev = buf;
	btgatt_write_params_t params;

	memset(&params, 0, sizeof(params));

	srvc_id_from_hal(&params.srvc_id, &ev->data.srvc_id);
	gatt_id_from_hal(&params.char_id, &ev->data.char_id);
	gatt_id_from_hal(&params.descr_id, &ev->data.descr_id);

	params.status = ev->data.status;

	if (cbs->client->write_characteristic_cb)
		cbs->client->write_characteristic_cb(ev->conn_id, ev->status,
								&params);
}

static void handle_read_descriptor(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_read_descriptor *ev = buf;
	btgatt_read_params_t params;

	if (len != sizeof(*ev) + ev->data.len ) {
		error("gatt: invalid read descriptor event, aborting");
		exit(EXIT_FAILURE);
	}

	memset(&params, 0, sizeof(params));

	srvc_id_from_hal(&params.srvc_id, &ev->data.srvc_id);
	gatt_id_from_hal(&params.char_id, &ev->data.char_id);
	gatt_id_from_hal(&params.descr_id, &ev->data.descr_id);

	memcpy(&params.value.value, ev->data.value, ev->data.len);

	params.value_type = ev->data.value_type;
	params.value.len = ev->data.len;
	params.status = ev->data.status;

	if (cbs->client->read_descriptor_cb)
		cbs->client->read_descriptor_cb(ev->conn_id, ev->status,
								&params);
}

static void handle_write_descriptor(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_write_descriptor *ev = buf;
	btgatt_write_params_t params;

	memset(&params, 0, sizeof(params));

	srvc_id_from_hal(&params.srvc_id, &ev->data.srvc_id);
	gatt_id_from_hal(&params.char_id, &ev->data.char_id);
	gatt_id_from_hal(&params.descr_id, &ev->data.descr_id);

	params.status = ev->data.status;

	if (cbs->client->write_descriptor_cb)
		cbs->client->write_descriptor_cb(ev->conn_id, ev->status,
								&params);
}

static void handle_execute_write(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_exec_write *ev = buf;

	if (cbs->client->execute_write_cb)
		cbs->client->execute_write_cb(ev->conn_id, ev->status);
}

static void handle_read_remote_rssi(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_read_remote_rssi *ev = buf;

	if (cbs->client->read_remote_rssi_cb)
		cbs->client->read_remote_rssi_cb(ev->client_if,
						(bt_bdaddr_t *) ev->address,
						ev->rssi, ev->status);
}

static void handle_listen(void *buf, uint16_t len)
{
	struct hal_ev_gatt_client_listen *ev = buf;

	if (cbs->client->listen_cb)
		cbs->client->listen_cb(ev->status, ev->server_if);
}

/* Server Event Handlers */

static void handle_register_server(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_register *ev = buf;

	if (cbs->server->register_server_cb)
		cbs->server->register_server_cb(ev->status, ev->server_if,
						(bt_uuid_t *) &ev->uuid);
}

static void handle_connection(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_connection *ev = buf;

	if (cbs->server->connection_cb)
		cbs->server->connection_cb(ev->conn_id, ev->server_if,
						ev->connected,
						(bt_bdaddr_t *) &ev->bdaddr);
}

static void handle_service_added(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_service_added *ev = buf;
	btgatt_srvc_id_t srvc_id;

	srvc_id_from_hal(&srvc_id, &ev->srvc_id);

	if (cbs->server->service_added_cb)
		cbs->server->service_added_cb(ev->status, ev->server_if,
						&srvc_id, ev->srvc_handle);
}

static void handle_included_service_added(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_inc_srvc_added *ev = buf;

	if (cbs->server->included_service_added_cb)
		cbs->server->included_service_added_cb(ev->status,
							ev->server_if,
							ev->srvc_handle,
							ev->incl_srvc_handle);
}

static void handle_characteristic_added(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_characteristic_added *ev = buf;

	if (cbs->server->characteristic_added_cb)
		cbs->server->characteristic_added_cb(ev->status, ev->server_if,
							(bt_uuid_t *) &ev->uuid,
							ev->srvc_handle,
							ev->char_handle);
}

static void handle_descriptor_added(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_descriptor_added *ev = buf;

	if (cbs->server->descriptor_added_cb)
		cbs->server->descriptor_added_cb(ev->status, ev->server_if,
							(bt_uuid_t *) &ev->uuid,
							ev->srvc_handle,
							ev->descr_handle);
}

static void handle_service_started(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_service_started *ev = buf;

	if (cbs->server->service_started_cb)
		cbs->server->service_started_cb(ev->status, ev->server_if,
							ev->srvc_handle);
}

static void handle_service_stopped(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_service_stopped *ev = buf;

	if (cbs->server->service_stopped_cb)
		cbs->server->service_stopped_cb(ev->status, ev->server_if,
							ev->srvc_handle);
}

static void handle_service_deleted(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_service_deleted *ev = buf;

	if (cbs->server->service_deleted_cb)
		cbs->server->service_deleted_cb(ev->status, ev->server_if,
							ev->srvc_handle);
}

static void handle_request_read(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_request_read *ev = buf;

	if (cbs->server->request_read_cb)
		cbs->server->request_read_cb(ev->conn_id, ev->trans_id,
						(bt_bdaddr_t *) &ev->bdaddr,
						ev->attr_handle, ev->offset,
						ev->is_long);
}

static void handle_request_write(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_request_write *ev = buf;

	if (len != sizeof(*ev) + ev->length ) {
		error("gatt: invalid request write event, aborting");
		exit(EXIT_FAILURE);
	}

	if (cbs->server->request_write_cb)
		cbs->server->request_write_cb(ev->conn_id, ev->trans_id,
						(bt_bdaddr_t *) ev->bdaddr,
						ev->attr_handle, ev->offset,
						ev->length, ev->need_rsp,
						ev->is_prep, ev->value);
}

static void handle_request_exec_write(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_request_exec_write *ev = buf;

	if (cbs->server->request_exec_write_cb)
		cbs->server->request_exec_write_cb(ev->conn_id, ev->trans_id,
						(bt_bdaddr_t *) ev->bdaddr,
						ev->exec_write);
}

static void handle_response_confirmation(void *buf, uint16_t len)
{
	struct hal_ev_gatt_server_rsp_confirmation *ev = buf;

	if (cbs->server->response_confirmation_cb)
		cbs->server->response_confirmation_cb(ev->status, ev->handle);
}

/*
 * handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT'
 */
static const struct hal_ipc_handler ev_handlers[] = {
	/* HAL_EV_GATT_CLIENT_REGISTER_CLIENT */
	{ handle_register_client, false,
		sizeof(struct hal_ev_gatt_client_register_client) },
	/* HAL_EV_GATT_CLIENT_SCAN_RESULT */
	{ handle_scan_result, true,
		sizeof(struct hal_ev_gatt_client_scan_result) },
	/* HAL_EV_GATT_CLIENT_CONNECT */
	{ handle_connect, false, sizeof(struct hal_ev_gatt_client_connect) },
	/* HAL_EV_GATT_CLIENT_DISCONNECT */
	{ handle_disconnect, false,
		sizeof(struct hal_ev_gatt_client_disconnect) },
	/* HAL_EV_GATT_CLIENT_SEARCH_COMPLETE */
	{ handle_search_complete, false,
		sizeof(struct hal_ev_gatt_client_search_complete) },
	/* HAL_EV_GATT_CLIENT_SEARCH_RESULT */
	{ handle_search_result, false,
		sizeof(struct hal_ev_gatt_client_search_result) },
	/* HAL_EV_GATT_CLIENT_GET_CHARACTERISTIC */
	{ handle_get_characteristic, false,
		sizeof(struct hal_ev_gatt_client_get_characteristic) },
	/* HAL_EV_GATT_CLIENT_GET_DESCRIPTOR */
	{ handle_get_descriptor, false,
		sizeof(struct hal_ev_gatt_client_get_descriptor) },
	/* HAL_EV_GATT_CLIENT_GET_INC_SERVICE */
	{ handle_get_included_service, false,
		sizeof(struct hal_ev_gatt_client_get_inc_service) },
	/* HAL_EV_GATT_CLIENT_REGISTER_FOR_NOTIF */
	{ handle_register_for_notification, false,
		sizeof(struct hal_ev_gatt_client_reg_for_notif) },
	/* HAL_EV_GATT_CLIENT_NOTIFY */
	{ handle_notify, true, sizeof(struct hal_ev_gatt_client_notify) },
	/* HAL_EV_GATT_CLIENT_READ_CHARACTERISTIC */
	{ handle_read_characteristic, true,
		sizeof(struct hal_ev_gatt_client_read_characteristic) },
	/* HAL_EV_GATT_CLIENT_WRITE_CHARACTERISTIC */
	{ handle_write_characteristic, false,
		sizeof(struct hal_ev_gatt_client_write_characteristic) },
	/* HAL_EV_GATT_CLIENT_READ_DESCRIPTOR */
	{ handle_read_descriptor, true,
		sizeof(struct hal_ev_gatt_client_read_descriptor) },
	/* HAL_EV_GATT_CLIENT_WRITE_DESCRIPTOR */
	{ handle_write_descriptor, false,
		sizeof(struct hal_ev_gatt_client_write_descriptor) },
	/* HAL_EV_GATT_CLIENT_EXEC_WRITE */
	{ handle_execute_write, false,
		sizeof(struct hal_ev_gatt_client_exec_write) },
	/* HAL_EV_GATT_CLIENT_READ_REMOTE_RSSI */
	{ handle_read_remote_rssi, false,
		sizeof(struct hal_ev_gatt_client_read_remote_rssi) },
	/* HAL_EV_GATT_CLIENT_LISTEN */
	{ handle_listen, false, sizeof(struct hal_ev_gatt_client_listen) },
	/* HAL_EV_GATT_SERVER_REGISTER */
	{ handle_register_server, false,
		sizeof(struct hal_ev_gatt_server_register) },
	/* HAL_EV_GATT_SERVER_CONNECTION */
	{ handle_connection, false,
		sizeof(struct hal_ev_gatt_server_connection) },
	/* HAL_EV_GATT_SERVER_SERVICE_ADDED */
	{ handle_service_added, false,
		sizeof(struct hal_ev_gatt_server_service_added) },
	/* HAL_EV_GATT_SERVER_INC_SRVC_ADDED */
	{ handle_included_service_added, false,
		sizeof(struct hal_ev_gatt_server_inc_srvc_added) },
	/* HAL_EV_GATT_SERVER_CHAR_ADDED */
	{ handle_characteristic_added, false,
		sizeof(struct hal_ev_gatt_server_characteristic_added) },
	/* HAL_EV_GATT_SERVER_DESCRIPTOR_ADDED */
	{ handle_descriptor_added, false,
		sizeof(struct hal_ev_gatt_server_descriptor_added) },
	/* HAL_EV_GATT_SERVER_SERVICE_STARTED */
	{ handle_service_started, false,
		sizeof(struct hal_ev_gatt_server_service_started) },
	/* HAL_EV_GATT_SERVER_SERVICE_STOPPED */
	{ handle_service_stopped, false,
		sizeof(struct hal_ev_gatt_server_service_stopped) },
	/* HAL_EV_GATT_SERVER_SERVICE_DELETED */
	{ handle_service_deleted, false,
		sizeof(struct hal_ev_gatt_server_service_deleted) },
	/* HAL_EV_GATT_SERVER_REQUEST_READ */
	{ handle_request_read, false,
		sizeof(struct hal_ev_gatt_server_request_read) },
	/* HAL_EV_GATT_SERVER_REQUEST_WRITE */
	{ handle_request_write, true,
		sizeof(struct hal_ev_gatt_server_request_write) },
	/* HAL_EV_GATT_SERVER_REQUEST_EXEC_WRITE */
	{ handle_request_exec_write, false,
		sizeof(struct hal_ev_gatt_server_request_exec_write) },
	/* HAL_EV_GATT_SERVER_RSP_CONFIRMATION */
	{ handle_response_confirmation, false,
		sizeof(struct hal_ev_gatt_server_rsp_confirmation) },
};

/* Client API */

static bt_status_t register_client(bt_uuid_t *uuid)
{
	struct hal_cmd_gatt_client_register cmd;

	memcpy(cmd.uuid, uuid, sizeof(*uuid));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REGISTER,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t unregister_client(int client_if)
{
	struct hal_cmd_gatt_client_unregister cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_UNREGISTER,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t scan(int client_if, bool start)
{
	struct hal_cmd_gatt_client_scan cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;
	cmd.start = start;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_SCAN,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t connect(int client_if, const bt_bdaddr_t *bd_addr,
								bool is_direct)
{
	struct hal_cmd_gatt_client_connect cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;
	cmd.is_direct = is_direct;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_CONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t disconnect(int client_if, const bt_bdaddr_t *bd_addr,
								int conn_id)
{
	struct hal_cmd_gatt_client_disconnect cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;
	cmd.conn_id = conn_id;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_DISCONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t listen(int client_if, bool start)
{
	struct hal_cmd_gatt_client_listen cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;
	cmd.start = start;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_LISTEN,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t refresh(int client_if, const bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_gatt_client_refresh cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REFRESH,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t search_service(int conn_id, bt_uuid_t *filter_uuid)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_search_service *cmd = (void *) buf;
	size_t len = sizeof(*cmd);

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memset(cmd, 0, sizeof(*cmd));

	cmd->conn_id = conn_id;

	if (filter_uuid) {
		memcpy(cmd->filter_uuid, filter_uuid, sizeof(*filter_uuid));
		len += sizeof(*filter_uuid);
		cmd->filtered = 1;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_SEARCH_SERVICE,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t get_included_service(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_srvc_id_t *start_incl_srvc_id)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_get_included_service *cmd = (void *) buf;
	size_t len = sizeof(*cmd);

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;

	srvc_id_to_hal(&cmd->srvc_id, srvc_id);
	cmd->continuation = 0;

	if (start_incl_srvc_id) {
		srvc_id_to_hal(&cmd->incl_srvc_id[0], start_incl_srvc_id);
		len += sizeof(cmd->incl_srvc_id[0]);
		cmd->continuation = 1;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t get_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *start_char_id)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_get_characteristic *cmd = (void *) buf;
	size_t len = sizeof(*cmd);

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;

	srvc_id_to_hal(&cmd->srvc_id, srvc_id);
	cmd->continuation = 0;

	if (start_char_id) {
		gatt_id_to_hal(&cmd->char_id[0], start_char_id);
		len += sizeof(cmd->char_id[0]);
		cmd->continuation = 1;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_CHARACTERISTIC,
					len, cmd, 0, NULL, NULL);
}

static bt_status_t get_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					btgatt_gatt_id_t *start_descr_id)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_get_descriptor *cmd = (void *) buf;
	size_t len = sizeof(*cmd);

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;

	srvc_id_to_hal(&cmd->srvc_id, srvc_id);
	gatt_id_to_hal(&cmd->char_id, char_id);
	cmd->continuation = 0;

	if (start_descr_id) {
		gatt_id_to_hal(&cmd->descr_id[0], start_descr_id);
		len += sizeof(cmd->descr_id[0]);
		cmd->continuation = 1;
	}

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_DESCRIPTOR,
					len, cmd, 0 , NULL, NULL);
}

static bt_status_t read_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					int auth_req)
{
	struct hal_cmd_gatt_client_read_characteristic cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.conn_id = conn_id;
	cmd.auth_req = auth_req;

	srvc_id_to_hal(&cmd.srvc_id, srvc_id);
	gatt_id_to_hal(&cmd.char_id, char_id);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t write_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					int write_type, int len, int auth_req,
					char *p_value)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_write_characteristic *cmd = (void *) buf;
	size_t cmd_len = sizeof(*cmd) + len;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;
	cmd->write_type = write_type;
	cmd->len = len;
	cmd->auth_req = auth_req;

	srvc_id_to_hal(&cmd->srvc_id, srvc_id);
	gatt_id_to_hal(&cmd->char_id, char_id);

	memcpy(cmd->value, p_value, len);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC,
					cmd_len, cmd, 0, NULL, NULL);
}

static bt_status_t read_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id,
						btgatt_gatt_id_t *descr_id,
						int auth_req)
{
	struct hal_cmd_gatt_client_read_descriptor cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.conn_id = conn_id;
	cmd.auth_req = auth_req;

	srvc_id_to_hal(&cmd.srvc_id, srvc_id);
	gatt_id_to_hal(&cmd.char_id, char_id);
	gatt_id_to_hal(&cmd.descr_id, descr_id);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_READ_DESCRIPTOR,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t write_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					btgatt_gatt_id_t *descr_id,
					int write_type, int len, int auth_req,
					char *p_value)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_write_descriptor *cmd = (void *) buf;
	size_t cmd_len = sizeof(*cmd) + len;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;
	cmd->write_type = write_type;
	cmd->len = len;
	cmd->auth_req = auth_req;

	srvc_id_to_hal(&cmd->srvc_id, srvc_id);
	gatt_id_to_hal(&cmd->char_id, char_id);
	gatt_id_to_hal(&cmd->descr_id, descr_id);

	memcpy(cmd->value, p_value, len);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR,
					cmd_len, cmd, 0, NULL, NULL);
}

static bt_status_t execute_write(int conn_id, int execute)
{
	struct hal_cmd_gatt_client_execute_write cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.conn_id = conn_id;
	cmd.execute = execute;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_EXECUTE_WRITE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t register_for_notification(int client_if,
						const bt_bdaddr_t *bd_addr,
						btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id)
{
	struct hal_cmd_gatt_client_register_for_notification cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	srvc_id_to_hal(&cmd.srvc_id, srvc_id);
	gatt_id_to_hal(&cmd.char_id, char_id);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t deregister_for_notification(int client_if,
						const bt_bdaddr_t *bd_addr,
						btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id)
{
	struct hal_cmd_gatt_client_deregister_for_notification cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	srvc_id_to_hal(&cmd.srvc_id, srvc_id);
	gatt_id_to_hal(&cmd.char_id, char_id);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION,
				sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t read_remote_rssi(int client_if, const bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_gatt_client_read_remote_rssi cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.client_if = client_if;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int get_device_type(const bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_gatt_client_get_device_type cmd;
	uint8_t dev_type;
	size_t resp_len = sizeof(dev_type);
	bt_status_t status;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	status = hal_ipc_cmd(HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_GET_DEVICE_TYPE,
				sizeof(cmd), &cmd, &resp_len, &dev_type, NULL);

	if (status != BT_STATUS_SUCCESS || resp_len != sizeof(dev_type))
		return 0;

	return dev_type;
}

static bt_status_t set_adv_data(int server_if, bool set_scan_rsp,
				bool include_name, bool include_txpower,
				int min_interval, int max_interval,
				int appearance, uint16_t manufacturer_len,
				char *manufacturer_data)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_client_set_adv_data *cmd = (void *) buf;
	size_t cmd_len = sizeof(*cmd) + manufacturer_len;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->server_if = server_if;
	cmd->set_scan_rsp = set_scan_rsp;
	cmd->include_name = include_name;
	cmd->include_txpower = include_txpower;
	cmd->min_interval = min_interval;
	cmd->max_interval = max_interval;
	cmd->appearance = appearance;
	cmd->manufacturer_len = manufacturer_len;

	memcpy(cmd->manufacturer_data, manufacturer_data, manufacturer_len);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_SET_ADV_DATA,
						cmd_len, cmd, 0, NULL, NULL);
}

static bt_status_t test_command(int command, btgatt_test_params_t *params)
{
	struct hal_cmd_gatt_client_test_command cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.command = command;

	memcpy(cmd.bda1, params->bda1, sizeof(*params->bda1));
	memcpy(cmd.uuid1, params->uuid1, sizeof(*params->uuid1));

	cmd.u1 = params->u1;
	cmd.u2 = params->u2;
	cmd.u3 = params->u3;
	cmd.u4 = params->u4;
	cmd.u5 = params->u5;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_TEST_COMMAND,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

/* Server API */

static bt_status_t register_server(bt_uuid_t *uuid)
{
	struct hal_cmd_gatt_server_register cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	memcpy(cmd.uuid, uuid, sizeof(*uuid));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_REGISTER,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t unregister_server(int server_if)
{
	struct hal_cmd_gatt_server_unregister cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_UNREGISTER,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t server_connect(int server_if, const bt_bdaddr_t *bd_addr,
								bool is_direct)
{
	struct hal_cmd_gatt_server_connect cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.is_direct = is_direct;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_CONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t server_disconnect(int server_if, const bt_bdaddr_t *bd_addr,
								int conn_id)
{
	struct hal_cmd_gatt_server_disconnect cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.conn_id = conn_id;

	memcpy(cmd.bdaddr, bd_addr, sizeof(*bd_addr));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_DISCONNECT,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t add_service(int server_if, btgatt_srvc_id_t *srvc_id,
								int num_handles)
{
	struct hal_cmd_gatt_server_add_service cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.num_handles = num_handles;

	srvc_id_to_hal(&cmd.srvc_id, srvc_id);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_ADD_SERVICE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t add_included_service(int server_if, int service_handle,
						int included_handle)
{
	struct hal_cmd_gatt_server_add_inc_service cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;
	cmd.included_handle = included_handle;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_ADD_INC_SERVICE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t add_characteristic(int server_if, int service_handle,
						bt_uuid_t *uuid, int properties,
						int permissions)
{
	struct hal_cmd_gatt_server_add_characteristic cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;
	cmd.properties = properties;
	cmd.permissions = permissions;

	memcpy(cmd.uuid, uuid, sizeof(*uuid));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_ADD_CHARACTERISTIC,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t add_descriptor(int server_if, int service_handle,
					bt_uuid_t *uuid, int permissions)
{
	struct hal_cmd_gatt_server_add_descriptor cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;
	cmd.permissions = permissions;

	memcpy(cmd.uuid, uuid, sizeof(*uuid));

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_ADD_DESCRIPTOR,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t start_service(int server_if, int service_handle,
								int transport)
{
	struct hal_cmd_gatt_server_start_service cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;
	cmd.transport = transport;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_START_SERVICE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t stop_service(int server_if, int service_handle)
{
	struct hal_cmd_gatt_server_stop_service cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_STOP_SERVICE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t delete_service(int server_if, int service_handle)
{
	struct hal_cmd_gatt_server_delete_service cmd;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.server_if = server_if;
	cmd.service_handle = service_handle;

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_DELETE_SERVICE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t send_indication(int server_if, int attribute_handle,
					int conn_id, int len, int confirm,
					char *p_value)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_server_send_indication *cmd = (void *) buf;
	size_t cmd_len = sizeof(*cmd) + len;

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->server_if = server_if;
	cmd->attribute_handle = attribute_handle;
	cmd->conn_id = conn_id;
	cmd->len = len;
	cmd->confirm = confirm;

	memcpy(cmd->value, p_value, len);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_SEND_INDICATION,
					cmd_len, cmd, 0, NULL, NULL);
}

static bt_status_t send_response(int conn_id, int trans_id, int status,
						btgatt_response_t *response)
{
	char buf[IPC_MTU];
	struct hal_cmd_gatt_server_send_response *cmd = (void *) buf;
	size_t cmd_len = sizeof(*cmd) + sizeof(*response);

	memset(buf, 0 , IPC_MTU);

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd->conn_id = conn_id;
	cmd->trans_id = trans_id;
	cmd->status = status;
	cmd->handle = response->attr_value.handle;
	cmd->offset = response->attr_value.offset;
	cmd->auth_req = response->attr_value.auth_req;
	cmd->len = response->attr_value.len;

	memcpy(cmd->data, response->attr_value.value, cmd->len);

	return hal_ipc_cmd(HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_SEND_RESPONSE,
					cmd_len, cmd, 0, NULL, NULL);
}

static bt_status_t init(const btgatt_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_GATT, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_GATT;
	cmd.mode = HAL_MODE_DEFAULT;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_GATT);
	}

	return ret;
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_GATT;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_GATT);
}

static btgatt_client_interface_t client_iface = {
	.register_client = register_client,
	.unregister_client = unregister_client,
	.scan = scan,
	.connect = connect,
	.disconnect = disconnect,
	.listen = listen,
	.refresh = refresh,
	.search_service = search_service,
	.get_included_service = get_included_service,
	.get_characteristic = get_characteristic,
	.get_descriptor = get_descriptor,
	.read_characteristic = read_characteristic,
	.write_characteristic = write_characteristic,
	.read_descriptor = read_descriptor,
	.write_descriptor = write_descriptor,
	.execute_write = execute_write,
	.register_for_notification = register_for_notification,
	.deregister_for_notification = deregister_for_notification,
	.read_remote_rssi = read_remote_rssi,
	.get_device_type = get_device_type,
	.set_adv_data = set_adv_data,
	.test_command = test_command,
};

static btgatt_server_interface_t server_iface = {
	.register_server = register_server,
	.unregister_server = unregister_server,
	.connect = server_connect,
	.disconnect = server_disconnect,
	.add_service = add_service,
	.add_included_service = add_included_service,
	.add_characteristic = add_characteristic,
	.add_descriptor = add_descriptor,
	.start_service = start_service,
	.stop_service = stop_service,
	.delete_service = delete_service,
	.send_indication = send_indication,
	.send_response = send_response,
};

static btgatt_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.cleanup = cleanup,
	.client = &client_iface,
	.server = &server_iface,
};

btgatt_interface_t *bt_get_gatt_interface(void)
{
	return &iface;
}
