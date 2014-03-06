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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

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

static void srvc_id_from_hal(btgatt_srvc_id_t *to,
						struct hal_gatt_srvc_id *from)
{
	memcpy(&to->id.uuid, from->uuid, sizeof(to->id.uuid));
	to->id.inst_id = from->inst_id;
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

	if (cbs->client->scan_result_cb)
		cbs->client->scan_result_cb((bt_bdaddr_t *) ev->bda, ev->rssi,
								ev->adv_data);
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

}

static void handle_connection(void *buf, uint16_t len)
{

}

static void handle_service_added(void *buf, uint16_t len)
{

}

static void handle_included_service_added(void *buf, uint16_t len)
{

}

static void handle_characteristic_added(void *buf, uint16_t len)
{

}

static void handle_descriptor_added(void *buf, uint16_t len)
{

}

static void handle_service_started(void *buf, uint16_t len)
{

}

static void handle_service_stopped(void *buf, uint16_t len)
{

}

static void handle_service_deleted(void *buf, uint16_t len)
{

}

static void handle_request_read(void *buf, uint16_t len)
{

}

static void handle_request_write(void *buf, uint16_t len)
{

}

static void handle_request_exec_write(void *buf, uint16_t len)
{

}

static void handle_response_confirmation(void *buf, uint16_t len)
{

}

/* handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT'
 */
static const struct hal_ipc_handler ev_handlers[] = {
	/* Client Event Handlers */
	{handle_register_client, false,
			sizeof(struct hal_ev_gatt_client_register_client)},
	{handle_scan_result, true,
				sizeof(struct hal_ev_gatt_client_scan_result)},
	{handle_connect, false, sizeof(struct hal_ev_gatt_client_connect)},
	{handle_disconnect, false,
			sizeof(struct hal_ev_gatt_client_disconnect)},
	{handle_search_complete, false,
			sizeof(struct hal_ev_gatt_client_search_complete)},
	{handle_search_result, false,
			sizeof(struct hal_ev_gatt_client_search_result)},
	{handle_get_characteristic, false,
			sizeof(struct hal_ev_gatt_client_get_characteristic)},
	{handle_get_descriptor, false,
			sizeof(struct hal_ev_gatt_client_get_descriptor)},
	{handle_get_included_service, false,
			sizeof(struct hal_ev_gatt_client_get_inc_service)},
	{handle_register_for_notification, false,
			sizeof(struct hal_ev_gatt_client_reg_for_notif)},
	{handle_notify, true, sizeof(struct hal_ev_gatt_client_notify)},
	{handle_read_characteristic, true,
			sizeof(struct hal_ev_gatt_client_read_characteristic)},
	{handle_write_characteristic, false,
			sizeof(struct hal_ev_gatt_client_write_characteristic)},
	{handle_read_descriptor, true,
			sizeof(struct hal_ev_gatt_client_read_descriptor)},
	{handle_write_descriptor, false,
			sizeof(struct hal_ev_gatt_client_write_descriptor)},
	{handle_execute_write, false,
				sizeof(struct hal_ev_gatt_client_exec_write)},
	{handle_read_remote_rssi, false,
			sizeof(struct hal_ev_gatt_client_read_remote_rssi)},
	{handle_listen, false, sizeof(struct hal_ev_gatt_client_listen)},

	/* Server Event Handlers */
	{handle_register_server, false,
				sizeof(struct hal_ev_gatt_server_register)},
	{handle_connection, false,
				sizeof(struct hal_ev_gatt_server_connection)},
	{handle_service_added, false,
			sizeof(struct hal_ev_gatt_server_service_added)},
	{handle_included_service_added, false,
			sizeof(struct hal_ev_gatt_server_service_added)},
	{handle_characteristic_added, false,
			sizeof(struct hal_ev_gatt_server_characteristic_added)},
	{handle_descriptor_added, false,
			sizeof(struct hal_ev_gatt_server_descriptor_added)},
	{handle_service_started, false,
			sizeof(struct hal_ev_gatt_server_service_started)},
	{handle_service_stopped, false,
			sizeof(struct hal_ev_gatt_server_service_stopped)},
	{handle_service_deleted, false,
			sizeof(struct hal_ev_gatt_server_service_deleted)},
	{handle_request_read, false,
			sizeof(struct hal_ev_gatt_server_request_read)},
	{handle_request_write, true,
			sizeof(struct hal_ev_gatt_server_request_write)},
	{handle_request_exec_write, false,
			sizeof(struct hal_ev_gatt_server_request_exec_write)},
	{handle_response_confirmation, false,
			sizeof(struct hal_ev_gatt_server_rsp_confirmation)},
};

/* Client API */

static bt_status_t register_client(bt_uuid_t *uuid)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t unregister_client(int client_if)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t scan(int client_if, bool start)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t connect(int client_if, const bt_bdaddr_t *bd_addr,
								bool is_direct)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t disconnect(int client_if, const bt_bdaddr_t *bd_addr,
								int conn_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t listen(int client_if, bool start)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t refresh(int client_if, const bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t search_service(int conn_id, bt_uuid_t *filter_uuid)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_included_service(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_srvc_id_t *start_incl_srvc_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *start_char_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					btgatt_gatt_id_t *start_descr_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t read_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					int auth_req)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t write_characteristic(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					int write_type, int len, int auth_req,
					char *p_value)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t read_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id,
						btgatt_gatt_id_t *descr_id,
						int auth_req)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t write_descriptor(int conn_id, btgatt_srvc_id_t *srvc_id,
					btgatt_gatt_id_t *char_id,
					btgatt_gatt_id_t *descr_id,
					int write_type, int len, int auth_req,
					char *p_value)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t execute_write(int conn_id, int execute)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t register_for_notification(int client_if,
						const bt_bdaddr_t *bd_addr,
						btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t deregister_for_notification(int client_if,
						const bt_bdaddr_t *bd_addr,
						btgatt_srvc_id_t *srvc_id,
						btgatt_gatt_id_t *char_id)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t read_remote_rssi(int client_if, const bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int get_device_type(const bt_bdaddr_t *bd_addr)
{
	return 0;
}

static bt_status_t set_adv_data(int server_if, bool set_scan_rsp,
				bool include_name, bool include_txpower,
				int min_interval, int max_interval,
				int appearance, uint16_t manufacturer_len,
				char *manufacturer_data)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t test_command(int command, btgatt_test_params_t *params)
{
	return BT_STATUS_UNSUPPORTED;
}

/* Server API */

static bt_status_t register_server(bt_uuid_t *uuid)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t unregister_server(int server_if)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t server_connect(int server_if, const bt_bdaddr_t *bd_addr,
								bool is_direct)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t add_service(int server_if, btgatt_srvc_id_t *srvc_id,
								int num_handles)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t add_included_service(int server_if, int service_handle,
						int included_handle)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t add_characteristic(int server_if, int service_handle,
						bt_uuid_t *uuid, int properties,
						int permissions)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t add_descriptor(int server_if, int service_handle,
					bt_uuid_t *uuid, int permissions)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t start_service(int server_if, int service_handle,
								int transport)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t stop_service(int server_if, int service_handle)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t delete_service(int server_if, int service_handle)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t send_indication(int server_if, int attribute_handle,
					int conn_id, int len, int confirm,
					char *p_value)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t send_response(int conn_id, int trans_id, int status,
						btgatt_response_t *response)
{
	return BT_STATUS_UNSUPPORTED;
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
