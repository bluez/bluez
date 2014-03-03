/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <stdint.h>
#include <glib.h>

#include "ipc.h"
#include "lib/bluetooth.h"
#include "gatt.h"
#include "src/log.h"
#include "hal-msg.h"

static struct ipc *hal_ipc = NULL;
static bdaddr_t adapter_addr;

static void handle_client_register(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REGISTER,
							HAL_STATUS_FAILED);
}

static void handle_client_unregister(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_UNREGISTER, HAL_STATUS_FAILED);
}

static void handle_client_scan(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_SCAN,
							HAL_STATUS_FAILED);
}

static void handle_client_connect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_CONNECT,
							HAL_STATUS_FAILED);
}

static void handle_client_disconnect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_DISCONNECT, HAL_STATUS_FAILED);
}

static void handle_client_listen(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_LISTEN,
							HAL_STATUS_FAILED);
}

static void handle_client_refresh(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REFRESH,
							HAL_STATUS_FAILED);
}

static void handle_client_search_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_SEARCH_SERVICE, HAL_STATUS_FAILED);
}

static void handle_client_get_included_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
					HAL_STATUS_FAILED);
}

static void handle_client_get_characteristic(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_CHARACTERISTIC,
					HAL_STATUS_FAILED);
}

static void handle_client_get_descriptor(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_GET_DESCRIPTOR, HAL_STATUS_FAILED);
}

static void handle_client_read_characteristic(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC,
					HAL_STATUS_FAILED);
}

static void handle_client_write_characteristic(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC,
					HAL_STATUS_FAILED);
}

static void handle_client_read_descriptor(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_READ_DESCRIPTOR, HAL_STATUS_FAILED);
}

static void handle_client_write_descriptor(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR, HAL_STATUS_FAILED);
}

static void handle_client_execute_write(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_EXECUTE_WRITE, HAL_STATUS_FAILED);
}

static void handle_client_register_for_notification(const void *buf,
								uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION,
				HAL_STATUS_FAILED);
}

static void handle_client_deregister_for_notification(const void *buf,
								uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION,
				HAL_STATUS_FAILED);
}

static void handle_client_read_remote_rssi(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI, HAL_STATUS_FAILED);
}

static void handle_client_get_device_type(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_GET_DEVICE_TYPE, HAL_STATUS_FAILED);
}

static void handle_client_set_adv_data(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_SET_ADV_DATA, HAL_STATUS_FAILED);
}

static void handle_client_test_command(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_TEST_COMMAND, HAL_STATUS_FAILED);
}

static void handle_server_register(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_REGISTER,
							HAL_STATUS_FAILED);
}

static void handle_server_unregister(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_UNREGISTER, HAL_STATUS_FAILED);
}

static void handle_server_connect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_CONNECT,
							HAL_STATUS_FAILED);
}

static void handle_server_disconnect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_DISCONNECT, HAL_STATUS_FAILED);
}

static void handle_server_add_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_ADD_SERVICE, HAL_STATUS_FAILED);
}

static void handle_server_add_included_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_ADD_INC_SERVICE, HAL_STATUS_FAILED);
}

static void handle_server_add_characteristic(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_ADD_CHARACTERISTIC,
					HAL_STATUS_FAILED);
}

static void handle_server_add_descriptor(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_ADD_DESCRIPTOR, HAL_STATUS_FAILED);
}

static void handle_server_start_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_START_SERVICE, HAL_STATUS_FAILED);
}

static void handle_server_stop_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_STOP_SERVICE, HAL_STATUS_FAILED);
}

static void handle_server_delete_service(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_DELETE_SERVICE, HAL_STATUS_FAILED);
}

static void handle_server_send_indication(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_SEND_INDICATION, HAL_STATUS_FAILED);
}

static void handle_server_send_response(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_SEND_RESPONSE, HAL_STATUS_FAILED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_GATT_CLIENT_REGISTER */
	{handle_client_register, false,
				sizeof(struct hal_cmd_gatt_client_register)},
	/* HAL_OP_GATT_CLIENT_UNREGISTER */
	{handle_client_unregister, false,
				sizeof(struct hal_cmd_gatt_client_unregister)},
	/* HAL_OP_GATT_CLIENT_SCAN */
	{handle_client_scan, false,
				sizeof(struct hal_cmd_gatt_client_scan)},
	/* HAL_OP_GATT_CLIENT_CONNECT */
	{handle_client_connect, false,
				sizeof(struct hal_cmd_gatt_client_connect)},
	/* HAL_OP_GATT_CLIENT_DISCONNECT */
	{handle_client_disconnect, false,
				sizeof(struct hal_cmd_gatt_client_disconnect)},
	/* HAL_OP_GATT_CLIENT_LISTEN */
	{handle_client_listen, false,
				sizeof(struct hal_cmd_gatt_client_listen)},
	/* HAL_OP_GATT_CLIENT_REFRESH */
	{handle_client_refresh, false,
				sizeof(struct hal_cmd_gatt_client_refresh)},
	/* HAL_OP_GATT_CLIENT_SEARCH_SERVICE */
	{handle_client_search_service, true,
			sizeof(struct hal_cmd_gatt_client_search_service)},
	/* HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE */
	{handle_client_get_included_service, true,
		sizeof(struct hal_cmd_gatt_client_get_included_service)},
	/* HAL_OP_GATT_CLIENT_GET_CHARACTERISTIC */
	{handle_client_get_characteristic, true,
			sizeof(struct hal_cmd_gatt_client_get_characteristic)},
	/* HAL_OP_GATT_CLIENT_GET_DESCRIPTOR */
	{handle_client_get_descriptor, true,
			sizeof(struct hal_cmd_gatt_client_get_descriptor)},
	/* HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC */
	{handle_client_read_characteristic, false,
			sizeof(struct hal_cmd_gatt_client_read_characteristic)},
	/* HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC */
	{handle_client_write_characteristic, true,
		sizeof(struct hal_cmd_gatt_client_write_characteristic)},
	/* HAL_OP_GATT_CLIENT_READ_DESCRIPTOR */
	{handle_client_read_descriptor, false,
			sizeof(struct hal_cmd_gatt_client_read_descriptor)},
	/* HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR */
	{handle_client_write_descriptor, true,
			sizeof(struct hal_cmd_gatt_client_write_descriptor)},
	/* HAL_OP_GATT_CLIENT_EXECUTE_WRITE */
	{handle_client_execute_write, false,
			sizeof(struct hal_cmd_gatt_client_execute_write)},
	/* HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION */
	{handle_client_register_for_notification, false,
		sizeof(struct hal_cmd_gatt_client_register_for_notification)},
	/* HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION */
	{handle_client_deregister_for_notification, false,
		sizeof(struct hal_cmd_gatt_client_deregister_for_notification)},
	/* HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI */
	{handle_client_read_remote_rssi, false,
			sizeof(struct hal_cmd_gatt_client_read_remote_rssi)},
	/* HAL_OP_GATT_CLIENT_GET_DEVICE_TYPE */
	{handle_client_get_device_type, false,
			sizeof(struct hal_cmd_gatt_client_get_device_type)},
	/* HAL_OP_GATT_CLIENT_SET_ADV_DATA */
	{handle_client_set_adv_data, true,
			sizeof(struct hal_cmd_gatt_client_set_adv_data)},
	/* HAL_OP_GATT_CLIENT_TEST_COMMAND */
	{handle_client_test_command, false,
			sizeof(struct hal_cmd_gatt_client_test_command)},
	/* HAL_OP_GATT_SERVER_REGISTER */
	{handle_server_register, false,
				sizeof(struct hal_cmd_gatt_server_register)},
	/* HAL_OP_GATT_SERVER_UNREGISTER */
	{handle_server_unregister, false,
				sizeof(struct hal_cmd_gatt_server_unregister)},
	/* HAL_OP_GATT_SERVER_CONNECT */
	{handle_server_connect, false,
				sizeof(struct hal_cmd_gatt_server_connect)},
	/* HAL_OP_GATT_SERVER_DISCONNECT */
	{handle_server_disconnect, false,
				sizeof(struct hal_cmd_gatt_server_disconnect)},
	/* HAL_OP_GATT_SERVER_ADD_SERVICE */
	{handle_server_add_service, false,
				sizeof(struct hal_cmd_gatt_server_add_service)},
	/* HAL_OP_GATT_SERVER_ADD_INC_SERVICE */
	{handle_server_add_included_service, false,
			sizeof(struct hal_cmd_gatt_server_add_inc_service)},
	/* HAL_OP_GATT_SERVER_ADD_CHARACTERISTIC */
	{handle_server_add_characteristic, false,
			sizeof(struct hal_cmd_gatt_server_add_characteristic)},
	/* HAL_OP_GATT_SERVER_ADD_DESCRIPTOR */
	{handle_server_add_descriptor, false,
			sizeof(struct hal_cmd_gatt_server_add_descriptor)},
	/* HAL_OP_GATT_SERVER_START_SERVICE */
	{handle_server_start_service, false,
			sizeof(struct hal_cmd_gatt_server_start_service)},
	/* HAL_OP_GATT_SERVER_STOP_SERVICE */
	{handle_server_stop_service, false,
			sizeof(struct hal_cmd_gatt_server_stop_service)},
	/* HAL_OP_GATT_SERVER_DELETE_SERVICE */
	{handle_server_delete_service, false,
			sizeof(struct hal_cmd_gatt_server_delete_service)},
	/* HAL_OP_GATT_SERVER_SEND_INDICATION */
	{handle_server_send_indication, true,
			sizeof(struct hal_cmd_gatt_server_send_indication)},
	/* HAL_OP_GATT_SERVER_SEND_RESPONSE */
	{handle_server_send_response, true,
			sizeof(struct hal_cmd_gatt_server_send_response)},
};

bool bt_gatt_register(struct ipc *ipc, const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;

	ipc_register(hal_ipc, HAL_SERVICE_ID_GATT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_gatt_unregister(void)
{
	DBG("");

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_GATT);
	hal_ipc = NULL;
}
