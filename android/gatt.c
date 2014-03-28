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
#include <errno.h>
#include <sys/socket.h>

#include "ipc.h"
#include "ipc-common.h"
#include "lib/sdp.h"
#include "lib/uuid.h"
#include "bluetooth.h"
#include "gatt.h"
#include "src/log.h"
#include "hal-msg.h"
#include "utils.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "btio/btio.h"

struct gatt_client {
	int32_t id;
	uint8_t uuid[16];
};

struct element_id {
	bt_uuid_t uuid;
	uint8_t instance;
};

struct characteristic {
	struct element_id id;
	struct gatt_char ch;
};

struct service {
	struct element_id id;
	struct gatt_primary primary;

	struct queue *chars;
};

struct gatt_device {
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;

	struct queue *clients;

	bool connect_ready;
	int32_t conn_id;

	GAttrib *attrib;
	GIOChannel *att_io;
	struct queue *services;

	guint watch_id;
};

static struct ipc *hal_ipc = NULL;
static bdaddr_t adapter_addr;
static bool scanning = false;

static struct queue *gatt_clients = NULL;
static struct queue *conn_list	= NULL;		/* Connected devices */
static struct queue *conn_wait_queue = NULL;	/* Devs waiting to connect */

static void bt_le_discovery_stop_cb(void);

static void android2uuid(const uint8_t *uuid, bt_uuid_t *dst)
{
	uint8_t i;

	dst->type = BT_UUID128;

	for (i = 0; i < 16; i++)
		dst->value.u128.data[i] = uuid[15 - i];

}

static void uuid2android(const bt_uuid_t *src, uint8_t *uuid)
{
	bt_uuid_t uu128;
	uint8_t i;

	if (src->type != BT_UUID128) {
		bt_uuid_to_uuid128(src, &uu128);
		src = &uu128;
	}

	for (i = 0; i < 16; i++)
		uuid[15 - i] = src->value.u128.data[i];
}

static void destroy_service(void *data)
{
	struct service *srvc = data;

	if (!srvc)
		return;

	queue_destroy(srvc->chars, free);
	free(srvc);
}

static bool match_client_by_uuid(const void *data, const void *user_data)
{
	const uint8_t *exp_uuid = user_data;
	const struct gatt_client *client = data;

	return !memcmp(exp_uuid, client->uuid, sizeof(client->uuid));
}

static bool match_client_by_id(const void *data, const void *user_data)
{
	int32_t exp_id = PTR_TO_INT(user_data);
	const struct gatt_client *client = data;

	return client->id == exp_id;
}

static struct gatt_client *find_client_by_id(int32_t id)
{
	return queue_find(gatt_clients, match_client_by_id, INT_TO_PTR(id));
}

static bool match_by_value(const void *data, const void *user_data)
{
	return data == user_data;
}

static bool match_dev_by_bdaddr(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;
	const bdaddr_t *addr = user_data;

	return !bacmp(&dev->bdaddr, addr);
}

static bool match_dev_connect_ready(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;

	return dev->connect_ready;
}

static bool match_dev_by_conn_id(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;
	const int32_t conn_id = PTR_TO_INT(user_data);

	return dev->conn_id == conn_id;
}

static bool match_srvc_by_element_id(const void *data, const void *user_data)
{
	const struct element_id *exp_id = user_data;
	const struct service *service = data;
	bt_uuid_t uuid;

	bt_string_to_uuid(&uuid, service->primary.uuid);
	if (service->id.instance == exp_id->instance)
		return !bt_uuid_cmp(&uuid, &exp_id->uuid);

	return false;
}

static bool match_char_by_higher_inst_id(const void *data,
							const void *user_data)
{
	const struct characteristic *ch = data;
	uint8_t inst_id = PTR_TO_INT(user_data);

	/* For now we match inst_id as it is unique, we'll match uuids later */
	return inst_id < ch->id.instance;
}

static void destroy_device(void *data)
{
	struct gatt_device *dev = data;

	if (!dev)
		return;

	queue_destroy(dev->clients, NULL);
	queue_destroy(dev->services, destroy_service);
	free(dev);
}

static void handle_client_register(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_register *cmd = buf;
	struct hal_ev_gatt_client_register_client ev;
	struct gatt_client *client;
	static int32_t client_cnt = 1;
	uint8_t status;

	DBG("");

	if (!cmd->uuid) {
		error("gatt: no uuid received");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (queue_find(gatt_clients, match_client_by_uuid, &cmd->uuid)) {
		error("gatt: client uuid is already on list");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	client = new0(struct gatt_client, 1);
	if (!client) {
		error("gatt: cannot allocate memory for registering client");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	memcpy(client->uuid, cmd->uuid, sizeof(client->uuid));

	client->id = client_cnt++;

	queue_push_head(gatt_clients, client);

	status = HAL_STATUS_SUCCESS;

	ev.status = status;
	ev.client_if = client->id;
	memcpy(ev.app_uuid, client->uuid, sizeof(client->uuid));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_REGISTER_CLIENT, sizeof(ev), &ev);

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_REGISTER, status);
}

static void handle_client_unregister(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_unregister *cmd = buf;
	uint8_t status;
	struct gatt_client *cl;

	DBG("");

	cl = queue_remove_if(gatt_clients, match_client_by_id,
						INT_TO_PTR(cmd->client_if));
	if (!cl) {
		error("gatt: client_if=%d not found", cmd->client_if);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	free(cl);
	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_UNREGISTER, status);
}

static void primary_cb(uint8_t status, GSList *services, void *user_data)
{
	struct hal_ev_gatt_client_search_complete ev;
	struct gatt_device *dev = user_data;
	GSList *l;

	DBG("Status %d", status);

	if (status) {
		error("gatt: Discover all primary services failed: %s",
							att_ecode2str(status));
		ev.status = HAL_STATUS_FAILED;
		goto done;
	}

	if (!services) {
		info("gatt: No primary services found");
		ev.status = HAL_STATUS_SUCCESS;
		goto done;
	}

	for (l = services; l; l = l->next) {
		struct hal_ev_gatt_client_search_result ev_res;
		struct gatt_primary *prim = l->data;
		struct service *p;

		p = new0(struct service, 1);
		if (!p) {
			error("gatt: Cannot allocate memory for gatt_primary");
			continue;
		}

		p->chars = queue_new();
		if (!p->chars) {
			error("gatt: Cannot allocate memory for char cache");
			free(p);
			continue;
		}

		memset(&ev_res, 0, sizeof(ev_res));

		if (bt_string_to_uuid(&p->id.uuid, prim->uuid) < 0) {
			error("gatt: Cannot convert string to uuid");
			continue;
		}

		/* Put primary service to our local list */
		memcpy(&p->primary, prim, sizeof(p->primary));
		if (!queue_push_tail(dev->services, p)) {
			error("gatt: Cannot push primary service to the list");
			free(p);
			continue;
		}

		DBG("attr handle = 0x%04x, end grp handle = 0x%04x uuid: %s",
				prim->range.start, prim->range.end, prim->uuid);

		/* Set event data */
		ev_res.conn_id  = dev->conn_id;
		ev_res.srvc_id.is_primary = 1;
		ev_res.srvc_id.inst_id = 0;

		uuid2android(&p->id.uuid, ev_res.srvc_id.uuid);

		ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT ,
					HAL_EV_GATT_CLIENT_SEARCH_RESULT,
					sizeof(ev_res), &ev_res);
	}

	ev.status = HAL_STATUS_SUCCESS;

done:
	ev.conn_id = dev->conn_id;
	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_SEARCH_COMPLETE, sizeof(ev), &ev);
}

static void connection_cleanup(struct gatt_device *device)
{
	if (device->watch_id) {
		g_source_remove(device->watch_id);
		device->watch_id = 0;
	}

	if (device->att_io) {
		g_io_channel_shutdown(device->att_io, FALSE, NULL);
		g_io_channel_unref(device->att_io);
		device->att_io = NULL;
	}

	if (device->attrib) {
		GAttrib *attrib = device->attrib;
		device->attrib = NULL;
		g_attrib_cancel_all(attrib);
		g_attrib_unref(attrib);
	}
}

static void send_client_disconnect_notify(int32_t id, struct gatt_device *dev,
								uint8_t status)
{
	struct hal_ev_gatt_client_disconnect ev;

	ev.client_if = id;
	ev.conn_id = dev->conn_id;
	ev.status = status;
	bdaddr2android(&dev->bdaddr, &ev.bda);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_DISCONNECT, sizeof(ev), &ev);
}

static void client_disconnect_notify(void *data, void *user_data)
{
	struct gatt_device *dev = user_data;
	int32_t id = PTR_TO_INT(data);

	send_client_disconnect_notify(id, dev, HAL_STATUS_SUCCESS);
}

static bool is_device_wating_for_connect(const bdaddr_t *addr,
							uint8_t addr_type)
{
	struct gatt_device *dev;

	DBG("");

	dev = queue_find(conn_wait_queue, match_dev_by_bdaddr, (void *)addr);
	if (!dev)
		return false;

	dev->bdaddr_type = addr_type;

	/* Mark that this device is ready for connect.
	 * Need it because will continue with connect after scan is stopped
	 */
	dev->connect_ready = true;

	return true;
}

static void le_device_found_handler(const bdaddr_t *addr, uint8_t addr_type,
						int rssi, uint16_t eir_len,
							const void *eir)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_scan_result *ev = (void *) buf;
	char bda[18];

	if (!scanning)
		goto connect;

	ba2str(addr, bda);
	DBG("LE Device found: %s, rssi: %d, adv_data: %d", bda, rssi, !!eir);

	bdaddr2android(addr, ev->bda);
	ev->rssi = rssi;
	ev->len = eir_len;

	memcpy(ev->adv_data, eir, ev->len);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
						HAL_EV_GATT_CLIENT_SCAN_RESULT,
						sizeof(ev) + ev->len, ev);

connect:
	if (!is_device_wating_for_connect(addr, addr_type))
		return;

	/* We are ok to perform connect now. Stop discovery
	* and once it is stopped continue with creating ACL
	*/
	bt_le_discovery_stop(bt_le_discovery_stop_cb);
}

static gboolean disconnected_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	bdaddr_t *addr = user_data;
	struct gatt_device *dev;
	int sock, err = 0;
	socklen_t len;

	dev = queue_remove_if(conn_list, match_dev_by_bdaddr, addr);

	sock = g_io_channel_unix_get_fd(io);
	len = sizeof(err);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		goto done;

	DBG("%s (%d)", strerror(err), err);

	/* Keep scanning/re-connection active if disconnection reason
	 * is connection timeout, remote user terminated connection or local
	 * initiated disconnection.
	 */
	if (err == ETIMEDOUT || err == ECONNRESET || err == ECONNABORTED) {
		if (!queue_push_tail(conn_wait_queue, dev)) {
			error("gatt: Cannot push data");
		} else {
			bt_le_discovery_start(le_device_found_handler);
			return FALSE;
		}
	}

done:
	connection_cleanup(dev);

	queue_foreach(dev->clients, client_disconnect_notify, dev);
	destroy_device(dev);

	return FALSE;
}

static void send_client_connect_notify(void *data, void *user_data)
{
	struct hal_ev_gatt_client_connect *ev = user_data;
	int32_t id = PTR_TO_INT(data);

	ev->client_if = id;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_CLIENT_CONNECT, sizeof(*ev), ev);

}

static void connect_cb(GIOChannel *io, GError *gerr, gpointer user_data)
{
	bdaddr_t *addr = user_data;
	struct gatt_device *dev;
	struct hal_ev_gatt_client_connect ev;
	GAttrib *attrib;
	static uint32_t conn_id = 0;
	uint8_t status;

	/* Take device from conn waiting queue */
	dev = queue_remove_if(conn_wait_queue, match_dev_by_bdaddr, addr);
	if (!dev) {
		error("gatt: Device not on the connect wait queue!?");
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	g_io_channel_unref(dev->att_io);
	dev->att_io = NULL;

	/* Set address and client id in the event */
	bdaddr2android(&dev->bdaddr, &ev.bda);

	if (gerr) {
		error("gatt: connection failed %s", gerr->message);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	attrib = g_attrib_new(io);
	if (!attrib) {
		error("gatt: unable to create new GAttrib instance");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	dev->attrib = attrib;
	dev->watch_id = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							disconnected_cb, dev);
	dev->conn_id = ++conn_id;

	/* Move gatt device from connect queue to conn_list */
	if (!queue_push_tail(conn_list, dev)) {
		error("gatt: Cannot push dev on conn_list");
		connection_cleanup(dev);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	status = HAL_STATUS_SUCCESS;
	goto reply;

reply:
	ev.conn_id = dev ? dev->conn_id : 0;
	ev.status = status;

	queue_foreach(dev->clients, send_client_connect_notify, &ev);

	/* If connection did not succeed, destroy device */
	if (status)
		destroy_device(dev);

	/* Check if we should restart scan */
	if (scanning)
		bt_le_discovery_start(le_device_found_handler);

	/*FIXME: What to do if discovery won't start here. */
}

static int connect_le(struct gatt_device *dev)
{
	BtIOSecLevel sec_level;
	GIOChannel *io;
	GError *gerr = NULL;
	char addr[18];

	ba2str(&dev->bdaddr, addr);

	/* There is one connection attempt going on */
	if (dev->att_io) {
		info("gatt: connection to dev %s is ongoing", addr);
		return -EALREADY;
	}

	DBG("Connection attempt to: %s", addr);

	/*TODO: If we are bonded then we should use higier sec level */
	sec_level = BT_IO_SEC_LOW;

	/*
	 * This connection will help us catch any PDUs that comes before
	 * pairing finishes
	 */
	io = bt_io_connect(connect_cb, dev, NULL, &gerr,
			BT_IO_OPT_SOURCE_BDADDR,
			&adapter_addr,
			BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
			BT_IO_OPT_DEST_BDADDR, &dev->bdaddr,
			BT_IO_OPT_DEST_TYPE, dev->bdaddr_type,
			BT_IO_OPT_CID, ATT_CID,
			BT_IO_OPT_SEC_LEVEL, sec_level,
			BT_IO_OPT_INVALID);
	if (!io) {
		error("gatt: Failed bt_io_connect(%s): %s", addr,
							gerr->message);
		g_error_free(gerr);
		return -EIO;
	}

	/* Keep this, so we can cancel the connection */
	dev->att_io = io;

	return 0;
}

static void handle_client_scan(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_scan *cmd = buf;
	uint8_t status;
	void *registered;

	DBG("new state %d", cmd->start);

	registered = find_client_by_id(cmd->client_if);
	if (!registered) {
		error("gatt: Client not registered");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	/* Turn off scan */
	if (!cmd->start) {
		DBG("Stopping LE SCAN");

		if (scanning) {
			bt_le_discovery_stop(NULL);
			scanning = false;
		}

		status = HAL_STATUS_SUCCESS;
		goto reply;
	}

	/* Reply success if we already do scan */
	if (scanning) {
		status = HAL_STATUS_SUCCESS;
		goto reply;
	}

	/* Turn on scan */
	if (!bt_le_discovery_start(le_device_found_handler)) {
		error("gatt: LE scan switch failed");
		status = HAL_STATUS_FAILED;
		goto reply;
	}
	scanning = true;
	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_SCAN,
									status);
}

static int connect_next_dev(void)
{
	struct gatt_device *dev;

	DBG("");

	if (queue_isempty(conn_wait_queue))
		return 0;

	/* Discovery has been stopped because there is connection waiting */
	dev = queue_find(conn_wait_queue, match_dev_connect_ready, NULL);
	if (!dev)
		/* Lets try again. */
		return -1;

	dev->connect_ready = false;

	return connect_le(dev);
}

static void bt_le_discovery_stop_cb(void)
{
	DBG("");

	/* Check now if there is any device ready to connect*/
	if (connect_next_dev() < 0)
		bt_le_discovery_start(le_device_found_handler);
}

static struct gatt_device *find_device(bdaddr_t *addr)
{
	struct gatt_device *dev;

	dev = queue_find(conn_list, match_dev_by_bdaddr, addr);
	if (dev)
		return dev;

	dev = queue_find(conn_wait_queue, match_dev_by_bdaddr, addr);
	if (dev)
		return dev;

	return NULL;
}

static struct gatt_device *find_device_by_conn_id(int32_t conn_id)
{
	return queue_find(conn_list, match_dev_by_conn_id, INT_TO_PTR(conn_id));
}

static void handle_client_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_connect *cmd = buf;
	struct gatt_device *dev = NULL;
	void *l;
	bdaddr_t addr;
	uint8_t status;
	bool send_notify = false;

	DBG("");

	/* Check if client is registered */
	l = find_client_by_id(cmd->client_if);
	if (!l) {
		error("gatt: Client id %d not found", cmd->client_if);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	android2bdaddr(&cmd->bdaddr, &addr);

	/* We do support many clients for one device connection so lets check
	  * If device is connected or in connecting state just update list of
	  * clients
	  */
	dev = find_device(&addr);
	if (dev) {
		/* Remeber to send dummy notification event  if we area
		 * connected
		 */
		if (dev->conn_id)
			send_notify = true;

		if (queue_find(dev->clients, match_by_value,
						INT_TO_PTR(cmd->client_if))) {
			status = HAL_STATUS_SUCCESS;
			goto reply;
		}

		/* Store another client */
		if (!queue_push_tail(dev->clients,
						INT_TO_PTR(cmd->client_if))) {
			error("gatt: Cannot push client on gatt device list");
			status = HAL_STATUS_FAILED;
			goto reply;
		}

		status = HAL_STATUS_SUCCESS;
		goto reply;
	}

	/* Lets create new gatt device and put it on conn_wait_queue.
	  * Once it is connected we move it to conn_list
	  */
	dev = new0(struct gatt_device, 1);
	if (!dev) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	memcpy(&dev->bdaddr, &addr, sizeof(bdaddr_t));

	/* Create queue to keep list of clients for given device*/
	dev->clients = queue_new();
	if (!dev->clients) {
		error("gatt: Cannot create client queue");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	dev->services = queue_new();
	if (!dev->services) {
		error("gatt: Cannot create services queue");
		queue_destroy(dev->clients, NULL);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	/* Update client list of device */
	if (!queue_push_tail(dev->clients, INT_TO_PTR(cmd->client_if))) {
		error("gatt: Cannot push client on the client queue!?");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	/* Start le scan if not started */
	if (!scanning && !bt_le_discovery_start(le_device_found_handler)) {
		error("gatt: Could not start scan");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (!queue_push_tail(conn_wait_queue, dev)) {
		error("gatt: Cannot push device on conn_wait_queue");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_CONNECT,
								status);

	/* If there is an error here we should make sure dev is out.*/
	if ((status != HAL_STATUS_SUCCESS) && dev) {
		destroy_device(dev);
		return;
	}

	/* Send dummy notification since ACL is already up*/
	if (send_notify) {
		struct hal_ev_gatt_client_connect ev;

		ev.conn_id = dev->conn_id;
		ev.status = HAL_STATUS_SUCCESS;
		ev.client_if = cmd->client_if;
		bdaddr2android(&addr, &ev.bda);

		ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
						HAL_EV_GATT_CLIENT_CONNECT,
						sizeof(ev), &ev);
	}
}

static void handle_client_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_disconnect *cmd = buf;
	struct gatt_device *dev;
	uint8_t status;
	char addr[18];

	DBG("");

	ba2str((bdaddr_t *)&cmd->bdaddr, addr);

	dev = find_device_by_conn_id(cmd->conn_id);
	if (!dev) {
		error("gatt: dev %s with conn_id=%d not found",
							addr, cmd->conn_id);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	/*Check if client owns this connection */
	if (!queue_remove_if(dev->clients, match_by_value,
						INT_TO_PTR(cmd->client_if))) {
		error("gatt: cannot remove conn_id=%d", cmd->client_if);
		status = HAL_STATUS_FAILED;
	} else {
		status = HAL_STATUS_SUCCESS;
	}

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_DISCONNECT, status);

	if (status == HAL_STATUS_FAILED)
		return;

	/* Just send disconnect event. If there is more clients on this
	 * device then this is what we shall to do.
	 * If this is last client, this is still OK to do because on connect
	 * request we do le scan and wait until remote device start
	 * advertisement */
	send_client_disconnect_notify(cmd->client_if, dev, HAL_STATUS_SUCCESS);

	/* If there is more clients just return */
	if (!queue_isempty(dev->clients))
		return;

	/* If this is last client do more cleaning */
	connection_cleanup(dev);
	dev = queue_remove_if(conn_list, match_dev_by_bdaddr, &dev->bdaddr);
	destroy_device(dev);
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
	const struct hal_cmd_gatt_client_search_service *cmd = buf;
	struct gatt_device *dev;
	uint8_t status;

	DBG("");

	dev = find_device_by_conn_id(cmd->conn_id);
	if (!dev) {
		error("gatt: dev with conn_id=%d not found", cmd->conn_id);
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	/*TODO:  Handle filter uuid */

	if (!gatt_discover_primary(dev->attrib, NULL, primary_cb, dev)) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_SEARCH_SERVICE, status);
}

static bool match_service_by_uuid(const void *data, const void *user_data)
{
	const struct service *service = data;
	const bt_uuid_t *uuid = user_data;
	bt_uuid_t service_uuid;

	if (bt_string_to_uuid(&service_uuid, service->primary.uuid) < 0)
		return false;

	return !bt_uuid_cmp(uuid, &service_uuid);
}

static struct service *find_service_by_uuid(struct gatt_device *device,
								bt_uuid_t *uuid)
{
	return queue_find(device->services, match_service_by_uuid, uuid);
}

struct get_included_data {
	struct service *service;
	struct gatt_device *device;
};

static void get_included_cb(uint8_t status, GSList *included, void *user_data)
{
	struct get_included_data *data = user_data;

	/* TODO pass included services to notification */
	free(data);
}

static void handle_client_get_included_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_included_service *cmd = buf;
	struct get_included_data *data;
	struct gatt_device *device;
	struct service *service;
	uint8_t status;

	DBG("");

	device = find_device_by_conn_id(cmd->conn_id);
	if (!device) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (queue_isempty(device->services)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (!cmd->number) {
		service = queue_peek_head(device->services);
	} else {
		bt_uuid_t uuid;

		android2uuid(cmd->srvc_id->uuid, &uuid);
		service = find_service_by_uuid(device, &uuid);
	}

	if (!service) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	data = new0(struct get_included_data, 1);
	if (!data) {
		error("gatt: failed to allocate memory for included_data");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	data->service = service;
	data->device = device;

	gatt_find_included(device->attrib, service->primary.range.start,
				service->primary.range.end, get_included_cb,
				data);

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
					status);
}

static void send_client_char_notify(const struct characteristic *ch,
					int32_t conn_id,
					const struct service *service)
{
	struct hal_ev_gatt_client_get_characteristic ev;

	memset(&ev, 0, sizeof(ev));
	ev.status = ch ? HAL_STATUS_SUCCESS : HAL_STATUS_FAILED;

	if (ch) {
		ev.char_prop = ch->ch.properties;

		ev.char_id.inst_id = ch->id.instance;
		uuid2android(&ch->id.uuid, ev.char_id.uuid);
	}

	ev.conn_id = conn_id;
	/* TODO need to be handled for included services too */
	ev.srvc_id.is_primary = 1;
	ev.srvc_id.inst_id = service->id.instance;
	uuid2android(&service->id.uuid, ev.srvc_id.uuid);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_GET_CHARACTERISTIC,
					sizeof(ev), &ev);
}

static void cache_all_srvc_chars(GSList *characteristics, struct queue *q)
{
	uint16_t inst_id = 0;
	bt_uuid_t uuid;

	/* Refresh characteristics cache if already exist */
	if (!queue_isempty(q))
		queue_remove_all(q, NULL, NULL, free);

	for (; characteristics; characteristics = characteristics->next) {
		struct characteristic *ch;

		ch = new0(struct characteristic, 1);
		if (!ch) {
			error("gatt: Could not allocate characteristic");
			continue;
		}

		memcpy(&ch->ch, characteristics->data, sizeof(ch->ch));

		bt_string_to_uuid(&uuid, ch->ch.uuid);
		bt_uuid_to_uuid128(&uuid, &ch->id.uuid);

		/* For now we increment inst_id and use it as characteristic
		 * handle
		 */
		ch->id.instance = ++inst_id;

		if (!queue_push_tail(q, ch)) {
			error("gatt: Error while caching characteristic");
			free(ch);
		}
	}
}

struct discover_char_data {
	int32_t conn_id;
	struct service *service;
};

static void discover_char_cb(uint8_t status, GSList *characteristics,
								void *user_data)
{
	struct discover_char_data *data = user_data;

	cache_all_srvc_chars(characteristics, data->service->chars);

	send_client_char_notify(queue_peek_head(data->service->chars),
						data->conn_id, data->service);

	free(data);
}

static void hal_srvc_id_to_element_id(const struct hal_gatt_srvc_id *from,
							struct element_id *to)
{
	to->instance = from->inst_id;
	android2uuid(from->uuid, &to->uuid);
}

static bool find_service(int32_t conn_id, struct element_id *service_id,
				struct gatt_device **dev, struct service **srvc)
{
	struct gatt_device *device;
	struct service *service;

	device = find_device_by_conn_id(conn_id);
	if (!device) {
		error("gatt: conn_id=%d not found", conn_id);
		return false;
	}

	service = queue_find(device->services, match_srvc_by_element_id,
								service_id);
	if (!service) {
		error("gatt: Service with inst_id: %d not found",
							service_id->instance);
		return false;
	}

	*dev = device;
	*srvc = service;

	return true;
}

static void handle_client_get_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_characteristic *cmd = buf;
	struct characteristic *ch;
	struct element_id match_id;
	struct gatt_device *dev;
	struct service *srvc;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) + (cmd->number * sizeof(cmd->gatt_id[0]))) {
		error("Invalid get characteristic size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id, &match_id);
	if (!find_service(cmd->conn_id, &match_id, &dev, &srvc)) {
		status = HAL_STATUS_FAILED;
		goto done;
	}

	/* Discover all characteristics for services if not cached yet */
	if (queue_isempty(srvc->chars)) {
		struct discover_char_data *cb_data =
					new0(struct discover_char_data, 1);

		if (!cb_data) {
			error("gatt: Cannot allocate cb data");
			status = HAL_STATUS_FAILED;
			goto done;
		}

		cb_data->service = srvc;
		cb_data->conn_id = dev->conn_id;

		if (!gatt_discover_char(dev->attrib, srvc->primary.range.start,
					srvc->primary.range.end, NULL,
					discover_char_cb, cb_data)) {
			free(cb_data);

			status = HAL_STATUS_FAILED;
			goto done;
		}

		status = HAL_STATUS_SUCCESS;
		goto done;
	}

	if (cmd->number)
		ch = queue_find(srvc->chars, match_char_by_higher_inst_id,
					INT_TO_PTR(cmd->gatt_id[0].inst_id));
	else
		ch = queue_peek_head(srvc->chars);

	send_client_char_notify(ch, dev->conn_id, srvc);

	status = HAL_STATUS_SUCCESS;

done:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_GET_CHARACTERISTIC, status);
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

	conn_list = queue_new();
	if (!conn_list) {
		error("gatt: Can not create conn queue");
		return false;
	}

	conn_wait_queue = queue_new();
	if (!conn_wait_queue) {
		error("gatt: Can not create conn queue");
		return false;
	}

	ipc_register(hal_ipc, HAL_SERVICE_ID_GATT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	gatt_clients = queue_new();
	if (!gatt_clients) {
		error("gatt: Cannot allocate gatt_clients");
		return false;
	}

	return true;
}

void bt_gatt_unregister(void)
{
	DBG("");

	queue_destroy(gatt_clients, free);

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_GATT);
	hal_ipc = NULL;

	queue_destroy(conn_list, destroy_device);
	conn_list = NULL;

	queue_destroy(conn_wait_queue, destroy_device);
	conn_wait_queue = NULL;

}
