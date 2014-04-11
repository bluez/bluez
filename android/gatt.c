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

/* set according to Android bt_gatt_client.h */
#define GATT_MAX_ATTR_LEN 600

#define GATT_SUCCESS	0x00000000
#define GATT_FAILURE	0x00000101

struct gatt_client {
	int32_t id;
	uint8_t uuid[16];
	struct queue *notifications;
};

struct gatt_server {
	int32_t id;
	uint8_t uuid[16];
};

struct element_id {
	bt_uuid_t uuid;
	uint8_t instance;
};

struct descriptor {
	struct element_id id;
	uint16_t handle;
};

struct characteristic {
	struct element_id id;
	struct gatt_char ch;

	struct queue *descriptors;
};

struct service {
	struct element_id id;
	struct gatt_primary prim;
	struct gatt_included incl;

	bool primary;

	struct queue *chars;
	struct queue *included;	/* Valid only for primary services */
	bool incl_search_done;
};

struct notification_data {
	struct hal_gatt_srvc_id service;
	struct hal_gatt_gatt_id ch;
	struct gatt_client *client;
	struct gatt_device *dev;
	guint notif_id;
	guint ind_id;
	int ref;
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
static struct queue *gatt_servers = NULL;
static struct queue *conn_list = NULL;		/* Connected devices */
static struct queue *conn_wait_queue = NULL;	/* Devs waiting to connect */
static struct queue *disc_dev_list = NULL;	/* Disconnected devices */

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

static void hal_srvc_id_to_element_id(const struct hal_gatt_srvc_id *from,
							struct element_id *to)
{
	to->instance = from->inst_id;
	android2uuid(from->uuid, &to->uuid);
}

static void element_id_to_hal_srvc_id(const struct element_id *from,
						uint8_t primary,
						struct hal_gatt_srvc_id *to)
{
	to->is_primary = primary;
	to->inst_id = from->instance;
	uuid2android(&from->uuid, to->uuid);
}

static void hal_gatt_id_to_element_id(const struct hal_gatt_gatt_id *from,
							struct element_id *to)
{
	to->instance = from->inst_id;
	android2uuid(from->uuid, &to->uuid);
}

static void element_id_to_hal_gatt_id(const struct element_id *from,
						struct hal_gatt_gatt_id *to)
{
	to->inst_id = from->instance;
	uuid2android(&from->uuid, to->uuid);
}

static void destroy_characteristic(void *data)
{
	struct characteristic *chars = data;

	if (!chars)
		return;

	queue_destroy(chars->descriptors, free);
	free(chars);
}

static void destroy_service(void *data)
{
	struct service *srvc = data;

	if (!srvc)
		return;

	queue_destroy(srvc->chars, destroy_characteristic);

	/* Included services we keep on two queues.
	 * 1. On the same queue with primary services.
	 * 2. On the queue inside primary service.
	 * So we need to free service memory only once but we need to destroy
	 * two queues
	 */
	if (srvc->primary)
		queue_destroy(srvc->included, NULL);

	free(srvc);
}

static bool match_client_by_uuid(const void *data, const void *user_data)
{
	const uint8_t *exp_uuid = user_data;
	const struct gatt_client *client = data;

	return !memcmp(exp_uuid, client->uuid, sizeof(client->uuid));
}

static bool match_server_by_uuid(const void *data, const void *user_data)
{
	const uint8_t *exp_uuid = user_data;
	const struct gatt_server *server = data;

	return !memcmp(exp_uuid, server->uuid, sizeof(server->uuid));
}

static bool match_client_by_id(const void *data, const void *user_data)
{
	int32_t exp_id = PTR_TO_INT(user_data);
	const struct gatt_client *client = data;

	return client->id == exp_id;
}

static bool match_server_by_id(const void *data, const void *user_data)
{
	int32_t exp_id = PTR_TO_INT(user_data);
	const struct gatt_server *server = data;

	return server->id == exp_id;
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

	if (service->id.instance == exp_id->instance)
		return !bt_uuid_cmp(&service->id.uuid, &exp_id->uuid);

	return false;
}

static bool match_srvc_by_higher_inst_id(const void *data,
							const void *user_data)
{
	const struct service *s = data;
	uint8_t inst_id = PTR_TO_INT(user_data);

	/* For now we match inst_id as it is unique */
	return inst_id < s->id.instance;
}

static bool match_char_by_higher_inst_id(const void *data,
							const void *user_data)
{
	const struct characteristic *ch = data;
	uint8_t inst_id = PTR_TO_INT(user_data);

	/* For now we match inst_id as it is unique, we'll match uuids later */
	return inst_id < ch->id.instance;
}

static bool match_descr_by_element_id(const void *data, const void *user_data)
{
	const struct element_id *exp_id = user_data;
	const struct descriptor *descr = data;

	if (exp_id->instance == descr->id.instance)
		return !bt_uuid_cmp(&descr->id.uuid, &exp_id->uuid);

	return false;
}

static bool match_descr_by_higher_inst_id(const void *data,
							const void *user_data)
{
	const struct descriptor *descr = data;
	uint8_t instance = PTR_TO_INT(user_data);

	/* For now we match instance as it is unique */
	return instance < descr->id.instance;
}

static bool match_notification(const void *a, const void *b)
{
	const struct notification_data *a1 = a;
	const struct notification_data *b1 = b;

	if (bacmp(&a1->dev->bdaddr, &b1->dev->bdaddr))
		return false;

	if (memcmp(&a1->ch, &b1->ch, sizeof(a1->ch)))
		return false;

	if (memcmp(&a1->service, &b1->service, sizeof(a1->service)))
		return false;

	return true;
}

static bool match_char_by_element_id(const void *data, const void *user_data)
{
	const struct element_id *exp_id = user_data;
	const struct characteristic *chars = data;

	if (exp_id->instance == chars->id.instance)
		return !bt_uuid_cmp(&chars->id.uuid, &exp_id->uuid);

	return false;
}

static void destroy_notification(void *data)
{
	struct notification_data *notification = data;

	if (--notification->ref)
		return;

	queue_remove_if(notification->client->notifications, match_notification,
								notification);
	free(notification);
}

static void unregister_notification(void *data)
{
	struct notification_data *notification = data;

	if (notification->notif_id)
		g_attrib_unregister(notification->dev->attrib,
							notification->notif_id);

	if (notification->ind_id)
		g_attrib_unregister(notification->dev->attrib,
							notification->ind_id);
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

static void destroy_gatt_client(void *data)
{
	struct gatt_client *client = data;

	/* First we want to get all notifications and unregister them.
	 * We don't pass unregister_notification to queue_destroy,
	 * because destroy notification performs operations on queue
	 * too. So remove all elements and then destroy queue.
	 */
	while (queue_peek_head(client->notifications)) {
		struct notification_data *notification;

		notification = queue_pop_head(client->notifications);
		unregister_notification(notification);
	}

	queue_destroy(client->notifications, free);

	free(client);
}

static void destroy_gatt_server(void *data)
{
	struct gatt_server *server = data;

	free(server);
}

static void handle_client_register(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_register *cmd = buf;
	struct hal_ev_gatt_client_register_client ev;
	struct gatt_client *client;
	static int32_t client_cnt = 1;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	if (queue_find(gatt_clients, match_client_by_uuid, &cmd->uuid)) {
		error("gatt: client uuid is already on list");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	client = new0(struct gatt_client, 1);
	if (!client) {
		error("gatt: cannot allocate memory for registering client");
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	client->notifications = queue_new();
	if (!client->notifications) {
		error("gatt: couldn't allocate notifications queue");
		destroy_gatt_client(client);
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	memcpy(client->uuid, cmd->uuid, sizeof(client->uuid));

	client->id = client_cnt++;

	if (!queue_push_head(gatt_clients, client)) {
		error("gatt: Cannot push client on the list");
		destroy_gatt_client(client);
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	ev.client_if = client->id;

	status = HAL_STATUS_SUCCESS;

failed:
	if (status == HAL_STATUS_SUCCESS)
		ev.status = GATT_SUCCESS;
	else
		ev.status = GATT_FAILURE;

	/* We should send notification with given in cmd UUID */
	memcpy(ev.app_uuid, cmd->uuid, sizeof(ev.app_uuid));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_REGISTER_CLIENT, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REGISTER,
									status);
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
	} else {
		destroy_gatt_client(cl);
		status = HAL_STATUS_SUCCESS;
	}

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_UNREGISTER, status);
}

static void send_client_primary_notify(void *data, void *user_data)
{
	struct hal_ev_gatt_client_search_result ev;
	struct service *p = data;
	int32_t conn_id = PTR_TO_INT(user_data);

	/* In service queue we will have also included services */
	if (!p->primary)
		return;

	ev.conn_id  = conn_id;
	element_id_to_hal_srvc_id(&p->id, 1, &ev.srvc_id);

	uuid2android(&p->id.uuid, ev.srvc_id.uuid);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_SEARCH_RESULT,
					sizeof(ev), &ev);
}

static void send_client_all_primary(int32_t status, struct queue *services,
							int32_t conn_id)
{
	struct hal_ev_gatt_client_search_complete ev;

	if (!status)
		queue_foreach(services, send_client_primary_notify,
							INT_TO_PTR(conn_id));

	ev.status = status;
	ev.conn_id = conn_id;
	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_SEARCH_COMPLETE, sizeof(ev), &ev);

}

static struct service *create_service(uint8_t id, bool primary, char *uuid,
								void *data)
{
	struct service *s;

	s = new0(struct service, 1);
	if (!s) {
		error("gatt: Cannot allocate memory for gatt_primary");
		return NULL;
	}

	s->chars = queue_new();
	if (!s->chars) {
		error("gatt: Cannot allocate memory for char cache");
		free(s);
		return NULL;
	}

	if (bt_string_to_uuid(&s->id.uuid, uuid) < 0) {
		error("gatt: Cannot convert string to uuid");
		queue_destroy(s->chars, NULL);
		free(s);
		return NULL;
	}

	s->id.instance = id;

	/* Put primary service to our local list */
	s->primary = primary;
	if (s->primary) {
		memcpy(&s->prim, data, sizeof(s->prim));
	} else {
		memcpy(&s->incl, data, sizeof(s->incl));
		return s;
	}

	/* For primary service allocate queue for included services */
	s->included = queue_new();
	if (!s->included) {
		queue_destroy(s->chars, NULL);
		free(s);
		return NULL;
	}

	return s;
}

static void primary_cb(uint8_t status, GSList *services, void *user_data)
{
	struct gatt_device *dev = user_data;
	GSList *l;
	int32_t gatt_status;
	uint8_t instance_id;

	DBG("Status %d", status);

	if (status) {
		error("gatt: Discover all primary services failed: %s",
							att_ecode2str(status));
		gatt_status = GATT_FAILURE;
		goto done;
	}

	if (!services) {
		info("gatt: No primary services found");
		gatt_status = GATT_SUCCESS;
		goto done;
	}

	if (!queue_isempty(dev->services)) {
		info("gatt: Services already cached");
		gatt_status = GATT_SUCCESS;
		goto done;
	}

	/* There might be multiply services with same uuid. Therefore make sure
	 * each primary service one has unique instance_id
	 */
	instance_id = 0;

	for (l = services; l; l = l->next) {
		struct gatt_primary *prim = l->data;
		struct service *p;

		p = create_service(instance_id++, true, prim->uuid, prim);
		if (!p)
			continue;

		if (!queue_push_tail(dev->services, p)) {
			error("gatt: Cannot push primary service to the list");
			free(p);
			continue;
		}

		DBG("attr handle = 0x%04x, end grp handle = 0x%04x uuid: %s",
			prim->range.start, prim->range.end, prim->uuid);
	}

	gatt_status = GATT_SUCCESS;

done:
	send_client_all_primary(gatt_status, dev->services, dev->conn_id);
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
								int32_t status)
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

	send_client_disconnect_notify(id, dev, GATT_SUCCESS);
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
							const void *eir,
							bool discoverable)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_scan_result *ev = (void *) buf;
	char bda[18];

	if (!scanning || !discoverable)
		goto connect;

	ba2str(addr, bda);
	DBG("LE Device found: %s, rssi: %d, adv_data: %d", bda, rssi, !!eir);

	bdaddr2android(addr, ev->bda);
	ev->rssi = rssi;
	ev->len = eir_len;

	memcpy(ev->adv_data, eir, ev->len);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
						HAL_EV_GATT_CLIENT_SCAN_RESULT,
						sizeof(*ev) + ev->len, ev);

connect:
	if (!is_device_wating_for_connect(addr, addr_type))
		return;

	/* We are ok to perform connect now. Stop discovery
	 * and once it is stopped continue with creating ACL
	 */
	bt_le_discovery_stop(bt_le_discovery_stop_cb);
}

static void put_device_on_disc_list(struct gatt_device *dev)
{
	dev->conn_id = 0;
	queue_remove_all(dev->clients, NULL, NULL, NULL);
	queue_push_tail(disc_dev_list, dev);
}

static gboolean disconnected_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct gatt_device *dev = user_data;
	int sock, err = 0;
	socklen_t len;

	queue_remove(conn_list, dev);

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

	/* Reset conn_id and put on disconnected list. */
	put_device_on_disc_list(dev);

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
	struct gatt_device *dev = user_data;
	struct hal_ev_gatt_client_connect ev;
	GAttrib *attrib;
	static uint32_t conn_id = 0;
	int32_t status;

	/* Take device from conn waiting queue */
	if (!queue_remove(conn_wait_queue, dev)) {
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
		status = GATT_FAILURE;
		goto reply;
	}

	attrib = g_attrib_new(io);
	if (!attrib) {
		error("gatt: unable to create new GAttrib instance");
		status = GATT_FAILURE;
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
		status = GATT_FAILURE;
		goto reply;
	}

	status = GATT_SUCCESS;
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

	/* FIXME: What to do if discovery won't start here. */
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

	/* TODO: If we are bonded then we should use higier sec level */
	sec_level = BT_IO_SEC_LOW;

	/* This connection will help us catch any PDUs that comes before
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

	/* Check now if there is any device ready to connect */
	if (connect_next_dev() < 0)
		bt_le_discovery_start(le_device_found_handler);
}

static struct gatt_device *find_device(bdaddr_t *addr)
{
	struct gatt_device *dev;

	dev = queue_find(conn_list, match_dev_by_bdaddr, addr);
	if (dev)
		return dev;

	return queue_find(conn_wait_queue, match_dev_by_bdaddr, addr);
}

static struct gatt_device *find_device_by_conn_id(int32_t conn_id)
{
	return queue_find(conn_list, match_dev_by_conn_id, INT_TO_PTR(conn_id));
}

static struct gatt_device *create_device(bdaddr_t *addr)
{
	struct gatt_device *dev;

	dev = new0(struct gatt_device, 1);
	if (!dev)
		return NULL;

	bacpy(&dev->bdaddr, addr);

	dev->clients = queue_new();
	dev->services = queue_new();

	if (!dev->clients || !dev->services) {
		error("gatt: Failed to allocate memory for client");
		destroy_device(dev);
		return NULL;
	}

	return dev;
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

	/* Let's check if we know device already */
	dev = queue_remove_if(disc_dev_list, match_dev_by_bdaddr, &addr);
	if (!dev) {
		/* New device, create it. */
		dev = create_device(&addr);
		if (!dev) {
			status = HAL_STATUS_FAILED;
			goto reply;
		}
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

	/* If there is an error here we should make sure dev is out. */
	if ((status != HAL_STATUS_SUCCESS) && dev) {
		destroy_device(dev);
		return;
	}

	/* Send dummy notification since ACL is already up */
	if (send_notify) {
		struct hal_ev_gatt_client_connect ev;

		ev.conn_id = dev->conn_id;
		ev.status = GATT_SUCCESS;
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
	bdaddr_t bdaddr;
	uint8_t status;
	char addr[18];

	DBG("");

	android2bdaddr(cmd->bdaddr, &bdaddr);
	ba2str(&bdaddr, addr);

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
	send_client_disconnect_notify(cmd->client_if, dev, GATT_SUCCESS);

	/* If there is more clients just return */
	if (!queue_isempty(dev->clients))
		return;

	/* If this is last client do more cleaning */
	connection_cleanup(dev);
	queue_remove(conn_list, dev);
	put_device_on_disc_list(dev);
}

static void handle_client_listen(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_LISTEN,
							HAL_STATUS_FAILED);
}

static void handle_client_refresh(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_refresh *cmd = buf;
	struct gatt_device *dev;
	uint8_t status;
	bdaddr_t bda;

	/* This is Android's framework hidden API call. It seams that no
	 * notification is expected and Bluedroid silently updates device's
	 * cache under the hood. As we use lazy caching ,we can just clear the
	 * cache and we're done.
	 */

	DBG("");

	android2bdaddr(&cmd->bdaddr, &bda);
	dev = find_device(&bda);
	if (!dev) {
		status = HAL_STATUS_FAILED;
		goto done;
	}

	queue_remove_all(dev->services, NULL, NULL, destroy_service);

	status = HAL_STATUS_SUCCESS;

done:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REFRESH,
									status);
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

	/* Use cache if possible */
	if (!queue_isempty(dev->services)) {
		status = HAL_STATUS_SUCCESS;
		send_client_all_primary(GATT_SUCCESS, dev->services,
								dev->conn_id);
		goto reply;
	}

	if (!gatt_discover_primary(dev->attrib, NULL, primary_cb, dev)) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_SEARCH_SERVICE, status);
}

static void send_client_incl_service_notify(const struct service *prim,
						const struct service *incl,
						int32_t conn_id,
						int32_t status)
{
	struct hal_ev_gatt_client_get_inc_service ev;

	memset(&ev, 0, sizeof(ev));

	ev.conn_id = conn_id;
	ev.status = status;

	element_id_to_hal_srvc_id(&prim->id, 1, &ev.srvc_id);

	if (incl)
		element_id_to_hal_srvc_id(&incl->id, 0, &ev.incl_srvc_id);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT ,
					HAL_EV_GATT_CLIENT_GET_INC_SERVICE,
					sizeof(ev), &ev);
}

struct get_included_data {
	struct service *prim;
	struct gatt_device *device;
};

static int get_inst_id_of_prim_services(const struct gatt_device *dev)
{
	struct service *s = queue_peek_tail(dev->services);

	if (s)
		return s->id.instance;

	return -1;
}

static void get_included_cb(uint8_t status, GSList *included, void *user_data)
{
	struct get_included_data *data = user_data;
	struct gatt_device *device = data->device;
	struct service *service = data->prim;
	struct service *incl;
	int instance_id;

	DBG("");

	free(data);

	if (status) {
		error("gatt: no included services found");
		return;
	}

	/* Remember that we already search included services.*/
	service->incl_search_done = true;

	/* There might be multiply services with same uuid. Therefore make sure
	 * each service has unique instance id. Let's take the latest instance
	 * id of primary service and start iterate included services from this
	 * point.
	 */
	instance_id = get_inst_id_of_prim_services(device);
	if (instance_id < 0)
		goto failed;

	for (; included; included = included->next) {
		struct gatt_included *included_service = included->data;

		incl = create_service(++instance_id, false,
							included_service->uuid,
							included_service);
		if (!incl)
			continue;

		/* Lets keep included service on two queues.
		 * 1. on services queue together with primary service
		 * 2. on special queue inside primary service
		 */
		if (!queue_push_tail(service->included, incl) ||
				!queue_push_tail(device->services, incl)) {
			error("gatt: Cannot push incl service to the list");
			destroy_service(incl);
			continue;
		}
	}

	/* Notify upper layer about first included service.
	 * Android framework will iterate for next one.
	 */
	incl = queue_peek_head(service->included);

	if (incl) {
		send_client_incl_service_notify(service, incl, device->conn_id,
								GATT_SUCCESS);
		return;
	}

failed:
	send_client_incl_service_notify(service, NULL, device->conn_id,
								GATT_FAILURE);
}

static bool search_included_services(struct gatt_device *dev,
							struct service *prim)
{
	struct get_included_data *data;

	data = new0(struct get_included_data, 1);
	if (!data) {
		error("gatt: failed to allocate memory for included_data");
		return false;
	}

	data->prim = prim;
	data->device = dev;

	gatt_find_included(dev->attrib, prim->prim.range.start,
							prim->prim.range.end,
							get_included_cb, data);
	return true;
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

static void handle_client_get_included_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_included_service *cmd = buf;
	struct gatt_device *device;
	struct service *prim_service;
	struct service *incl_service;
	struct element_id match_id;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) + (cmd->number * sizeof(cmd->srvc_id[0]))) {
		error("Invalid get incl services size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id[0], &match_id);
	if (!find_service(cmd->conn_id, &match_id, &device, &prim_service)) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (!prim_service->incl_search_done) {
		if (search_included_services(device, prim_service))
			status = HAL_STATUS_SUCCESS;
		else
			status = HAL_STATUS_FAILED;

		goto reply;
	}

	/* Try to use cache here */
	if (cmd->number == 1) {
		incl_service = queue_peek_head(prim_service->included);
	} else {
		uint8_t inst_id = cmd->srvc_id[1].inst_id;
		incl_service = queue_find(prim_service->included,
						match_srvc_by_higher_inst_id,
						INT_TO_PTR(inst_id));
	}

	/* Note that Android framework expects failure notification
	 * which is treat as the end of included services
	 */
	if (!incl_service)
		send_client_incl_service_notify(prim_service, NULL,
						device->conn_id, GATT_FAILURE);
	else
		send_client_incl_service_notify(prim_service, incl_service,
						device->conn_id, GATT_SUCCESS);

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
					status);

	/* In case of error in handling request we need to send event with
	 * Android framework is stupid and do not check status of response
	 */
	if (status)
		send_client_incl_service_notify(prim_service, NULL,
						device->conn_id, GATT_FAILURE);
}

static void send_client_char_notify(const struct characteristic *ch,
					int32_t conn_id,
					const struct service *service)
{
	struct hal_ev_gatt_client_get_characteristic ev;

	memset(&ev, 0, sizeof(ev));
	ev.status = ch ? GATT_SUCCESS : GATT_FAILURE;

	if (ch) {
		ev.char_prop = ch->ch.properties;
		element_id_to_hal_gatt_id(&ch->id, &ev.char_id);
	}

	ev.conn_id = conn_id;
	element_id_to_hal_srvc_id(&service->id, service->primary, &ev.srvc_id);

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
		queue_remove_all(q, NULL, NULL, destroy_characteristic);

	for (; characteristics; characteristics = characteristics->next) {
		struct characteristic *ch;

		ch = new0(struct characteristic, 1);
		if (!ch) {
			error("gatt: Error while caching characteristic");
			continue;
		}

		ch->descriptors = queue_new();
		if (!ch->descriptors) {
			error("gatt: Error while caching characteristic");
			free(ch);
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
			destroy_characteristic(ch);
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

	if (queue_isempty(data->service->chars))
		cache_all_srvc_chars(characteristics, data->service->chars);

	send_client_char_notify(queue_peek_head(data->service->chars),
						data->conn_id, data->service);

	free(data);
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
		struct att_range range;

		struct discover_char_data *cb_data =
					new0(struct discover_char_data, 1);

		if (!cb_data) {
			error("gatt: Cannot allocate cb data");
			status = HAL_STATUS_FAILED;
			goto done;
		}

		cb_data->service = srvc;
		cb_data->conn_id = dev->conn_id;

		range = srvc->primary ? srvc->prim.range : srvc->incl.range;

		if (!gatt_discover_char(dev->attrib, range.start, range.end,
							NULL, discover_char_cb,
							cb_data)) {
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

static void send_client_descr_notify(int32_t status, int32_t conn_id,
					bool primary,
					const struct element_id *srvc,
					const struct element_id *ch,
					const struct element_id *opt_descr)
{
	struct hal_ev_gatt_client_get_descriptor ev;

	memset(&ev, 0, sizeof(ev));

	ev.status = status;
	ev.conn_id = conn_id;

	element_id_to_hal_srvc_id(srvc, primary, &ev.srvc_id);
	element_id_to_hal_gatt_id(ch, &ev.char_id);

	if (opt_descr)
		element_id_to_hal_gatt_id(opt_descr, &ev.descr_id);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_GET_DESCRIPTOR, sizeof(ev), &ev);
}

static void cache_all_descr(const uint8_t *pdu, guint16 len,
							struct queue *cache)
{
	struct att_data_list *list;
	guint8 format;
	int i;

	list = dec_find_info_resp(pdu, len, &format);
	if (!list)
		return;

	for (i = 0; i < list->num; i++) {
		char uuidstr[MAX_LEN_UUID_STR];
		struct descriptor *descr;
		bt_uuid_t uuid128;
		uint16_t handle;
		uint8_t *value;
		bt_uuid_t uuid;

		value = list->data[i];
		handle = get_le16(value);

		if (format == ATT_FIND_INFO_RESP_FMT_16BIT) {
			bt_uuid16_create(&uuid, get_le16(&value[2]));
			bt_uuid_to_uuid128(&uuid, &uuid128);
		} else {
			uint128_t u128;

			bswap_128(&value[2], &u128);
			bt_uuid128_create(&uuid128, u128);
		}

		bt_uuid_to_string(&uuid128, uuidstr, MAX_LEN_UUID_STR);
		DBG("handle 0x%04x uuid %s", handle, uuidstr);

		descr = new0(struct descriptor, 1);
		if (!descr)
			continue;

		descr->id.instance = i;
		descr->handle = handle;
		descr->id.uuid = uuid128;

		if (!queue_push_tail(cache, descr))
			free(descr);
	}

	att_data_list_free(list);
}

struct discover_desc_data {
	int32_t conn_id;
	const struct element_id *srvc_id;
	const struct characteristic *ch;
	uint8_t primary;
};

static void gatt_discover_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct discover_desc_data *data = user_data;
	struct descriptor *descr;

	if (status)
		error("gatt: Discover all char descriptors failed: %s",
							att_ecode2str(status));
	else if (queue_isempty(data->ch->descriptors))
		cache_all_descr(pdu, len, data->ch->descriptors);

	descr = queue_peek_head(data->ch->descriptors);

	send_client_descr_notify(status, data->conn_id, data->primary,
						data->srvc_id, &data->ch->id,
						descr ? &descr->id : NULL);

	free(data);
}

static bool build_descr_cache(int32_t conn_id, struct gatt_device *dev,
					struct service *srvc, uint8_t primary,
					struct characteristic *ch)
{
	struct discover_desc_data *cb_data;
	struct characteristic *next_ch;
	uint16_t start, end;

	/* Clip range to given characteristic */
	start = ch->ch.value_handle + 1;
	end = srvc->prim.range.end;

	/* Use next characteristic start as end. If there is none -
	 * service end is valid end.
	 * TODO: we should cache char end handle to avoid this search
	 */
	next_ch = queue_find(srvc->chars, match_char_by_higher_inst_id,
					INT_TO_PTR(ch->id.instance));
	if (next_ch)
		end = next_ch->ch.handle - 1;

	/* If there are no descriptors, notify with fail status. */
	if (start > end)
		return false;

	cb_data = new0(struct discover_desc_data, 1);
	if (!cb_data)
		return false;

	cb_data->conn_id = conn_id;
	cb_data->srvc_id = &srvc->id;
	cb_data->ch = ch;
	cb_data->primary = primary;

	if (!gatt_discover_char_desc(dev->attrib, start, end,
					gatt_discover_desc_cb, cb_data)) {
		free(cb_data);
		return false;
	}

	return true;
}

static void handle_client_get_descriptor(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_descriptor *cmd = buf;
	struct descriptor *descr = NULL;
	struct characteristic *ch;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	struct gatt_device *dev;
	int32_t conn_id;
	uint8_t primary;
	uint8_t status;

	DBG("");

	if ((len != sizeof(*cmd) + cmd->number * sizeof(cmd->gatt_id[0])) ||
				(cmd->number != 1 && cmd->number != 2)) {
		error("gatt: Invalid get descr command (%u bytes), terminating",
									len);

		raise(SIGTERM);
		return;
	}

	conn_id = cmd->conn_id;
	primary = cmd->srvc_id.is_primary;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->gatt_id[0], &char_id);

	if (!find_service(conn_id, &srvc_id, &dev, &srvc)) {
		error("gatt: Get descr. could not find service");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Get descr. could not find characteristic");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (queue_isempty(ch->descriptors)) {
		if (build_descr_cache(conn_id, dev, srvc, primary, ch)) {
			ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_DESCRIPTOR,
					HAL_STATUS_SUCCESS);
			return;
		}
	}

	status = HAL_STATUS_SUCCESS;

	/* Send from cache */
	if (cmd->number > 1)
		descr = queue_find(ch->descriptors,
					match_descr_by_higher_inst_id,
					INT_TO_PTR(cmd->gatt_id[1].inst_id));
	else
		descr = queue_peek_head(ch->descriptors);

failed:
	send_client_descr_notify(descr ? GATT_SUCCESS : GATT_FAILURE, conn_id,
						primary, &srvc_id, &char_id,
						&descr->id);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_GET_DESCRIPTOR, status);
}

struct read_char_data {
	int32_t conn_id;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t primary;
};

static void send_client_read_char_notify(int32_t status, const uint8_t *pdu,
						uint16_t len, int32_t conn_id,
						struct element_id *srvc_id,
						struct element_id *char_id,
						uint8_t primary)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_read_characteristic *ev = (void *) buf;
	ssize_t vlen;

	memset(buf, 0, sizeof(buf));

	ev->conn_id = conn_id;
	ev->status = status;

	element_id_to_hal_srvc_id(srvc_id, primary, &ev->data.srvc_id);
	element_id_to_hal_gatt_id(char_id, &ev->data.char_id);

	if (pdu) {
		vlen = dec_read_resp(pdu, len, ev->data.value, sizeof(buf));
		if (vlen < 0) {
			error("gatt: Protocol error");
			ev->status = GATT_FAILURE;
		} else {
			ev->data.len = vlen;
		}
	}

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_READ_CHARACTERISTIC,
					sizeof(*ev) + ev->data.len, ev);
}

static void read_char_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct read_char_data *data = user_data;

	send_client_read_char_notify(status, pdu, len, data->conn_id,
						&data->srvc_id, &data->char_id,
						data->primary);

	free(data);
}

static void handle_client_read_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_characteristic *cmd = buf;
	struct read_char_data *cb_data;
	struct characteristic *ch;
	struct gatt_device *dev;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t status;

	DBG("");

	/* TODO authorization needs to be handled */

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->gatt_id, &char_id);

	if (!find_service(cmd->conn_id, &srvc_id, &dev, &srvc)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* search characteristics by element id */
	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Characteristic with inst_id: %d not found",
							cmd->gatt_id.inst_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	cb_data = new0(struct read_char_data, 1);
	if (!cb_data) {
		error("gatt: Cannot allocate cb data");
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	cb_data->conn_id = cmd->conn_id;
	cb_data->primary = cmd->srvc_id.is_primary;
	cb_data->srvc_id = srvc_id;
	cb_data->char_id = char_id;

	if (!gatt_read_char(dev->attrib, ch->ch.value_handle,
						read_char_cb, cb_data)) {
		error("gatt: Cannot read characteristic with inst_id: %d",
							cmd->gatt_id.inst_id);
		status = HAL_STATUS_FAILED;
		free(cb_data);
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC, status);

	/* We should send notification with service, characteristic id in case
	 * of errors.
	 */
	if (status != HAL_STATUS_SUCCESS)
		send_client_read_char_notify(GATT_FAILURE, NULL, 0,
					cmd->conn_id, &srvc_id, &char_id,
					cmd->srvc_id.is_primary);
}

struct write_char_data {
	int32_t conn_id;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t primary;
};

static void send_client_write_char_notify(int32_t status, int32_t conn_id,
					struct element_id *srvc_id,
					struct element_id *char_id,
					uint8_t primary)
{
	struct hal_ev_gatt_client_write_characteristic ev;

	memset(&ev, 0, sizeof(ev));

	ev.conn_id = conn_id;
	ev.status = status;

	element_id_to_hal_srvc_id(srvc_id, primary, &ev.data.srvc_id);
	element_id_to_hal_gatt_id(char_id, &ev.data.char_id);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_WRITE_CHARACTERISTIC,
					sizeof(ev), &ev);
}

static void write_char_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct write_char_data *data = user_data;

	send_client_write_char_notify(status, data->conn_id, &data->srvc_id,
					&data->char_id, data->primary);

	free(data);
}

static void handle_client_write_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_write_characteristic *cmd = buf;
	struct write_char_data *cb_data;
	struct characteristic *ch;
	struct gatt_device *dev;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) + cmd->len) {
		error("Invalid write char size (%u bytes), terminating", len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->gatt_id, &char_id);

	if (!find_service(cmd->conn_id, &srvc_id, &dev, &srvc)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* search characteristics by instance id */
	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Characteristic with inst_id: %d not found",
							cmd->gatt_id.inst_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	cb_data = new0(struct write_char_data, 1);
	if (!cb_data) {
		error("gatt: Cannot allocate call data");
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	cb_data->conn_id = cmd->conn_id;
	cb_data->primary = cmd->srvc_id.is_primary;
	cb_data->srvc_id = srvc_id;
	cb_data->char_id = char_id;

	if (!gatt_write_char(dev->attrib, ch->ch.value_handle, cmd->value,
					cmd->len, write_char_cb, cb_data)) {
		error("gatt: Cannot read characteristic with inst_id: %d",
							cmd->gatt_id.inst_id);
		status = HAL_STATUS_FAILED;
		free(cb_data);
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC, status);

	/* We should send notification with service, characteristic id in case
	 * of errors.
	 */
	if (status != HAL_STATUS_SUCCESS)
		send_client_write_char_notify(GATT_FAILURE, cmd->conn_id,
						&srvc_id, &char_id,
						cmd->srvc_id.is_primary);
}

static void send_client_descr_read_notify(int32_t status, const uint8_t *pdu,
						guint16 len, int32_t conn_id,
						const struct element_id *srvc,
						const struct element_id *ch,
						const struct element_id *descr,
						uint8_t primary)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_read_descriptor *ev = (void *) buf;

	memset(buf, 0, sizeof(buf));

	ev->status = status;
	ev->conn_id = conn_id;

	element_id_to_hal_srvc_id(srvc, primary, &ev->data.srvc_id);
	element_id_to_hal_gatt_id(ch, &ev->data.char_id);
	element_id_to_hal_gatt_id(descr, &ev->data.descr_id);

	if (len && pdu) {
		ssize_t ret;

		ret = dec_read_resp(pdu, len, ev->data.value,
							GATT_MAX_ATTR_LEN);
		if (ret < 0) {
			error("gatt: Protocol error");
			ev->status = GATT_FAILURE;
		} else {
			ev->data.len = ret;
		}
	}

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_READ_DESCRIPTOR,
					sizeof(*ev) + ev->data.len, ev);
}

struct desc_data {
	int32_t conn_id;
	const struct element_id *srvc_id;
	const struct element_id *char_id;
	const struct element_id *descr_id;
	uint8_t primary;
};

static void read_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct desc_data *cb_data = user_data;

	if (status != 0)
		error("gatt: Discover all char descriptors failed: %s",
							att_ecode2str(status));

	send_client_descr_read_notify(status, pdu, len, cb_data->conn_id,
					cb_data->srvc_id, cb_data->char_id,
					cb_data->descr_id, cb_data->primary);

	free(cb_data);
}

static void handle_client_read_descriptor(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_descriptor *cmd = buf;
	struct desc_data *cb_data;
	struct characteristic *ch;
	struct descriptor *descr;
	struct service *srvc;
	struct element_id char_id;
	struct element_id descr_id;
	struct element_id srvc_id;
	struct gatt_device *dev;
	int32_t conn_id = 0;
	uint8_t primary;
	uint8_t status;

	DBG("");

	conn_id = cmd->conn_id;
	primary = cmd->srvc_id.is_primary;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);
	hal_gatt_id_to_element_id(&cmd->descr_id, &descr_id);

	if (!find_service(conn_id, &srvc_id, &dev, &srvc)) {
		error("gatt: Read descr. could not find service");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Read descr. could not find characteristic");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	descr = queue_find(ch->descriptors, match_descr_by_element_id,
								&descr_id);
	if (!descr) {
		error("gatt: Read descr. could not find descriptor");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	cb_data = new0(struct desc_data, 1);
	if (!cb_data) {
		error("gatt: Read descr. could not allocate callback data");

		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	cb_data->conn_id = conn_id;
	cb_data->srvc_id = &srvc->id;
	cb_data->char_id = &ch->id;
	cb_data->descr_id = &descr->id;
	cb_data->primary = primary;

	if (!gatt_read_char(dev->attrib, descr->handle, read_desc_cb,
								cb_data)) {
		free(cb_data);

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	if (status != HAL_STATUS_SUCCESS)
		send_client_descr_read_notify(GATT_FAILURE, NULL, 0, conn_id,
						&srvc_id, &char_id, &descr_id,
						primary);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_READ_DESCRIPTOR, status);
}

static void send_client_descr_write_notify(int32_t status, int32_t conn_id,
						const struct element_id *srvc,
						const struct element_id *ch,
						const struct element_id *descr,
						uint8_t primary) {
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_write_descriptor *ev = (void *) buf;

	memset(buf, 0, sizeof(buf));

	ev->status = status;
	ev->conn_id = conn_id;

	element_id_to_hal_srvc_id(srvc, primary, &ev->data.srvc_id);
	element_id_to_hal_gatt_id(ch, &ev->data.char_id);
	element_id_to_hal_gatt_id(descr, &ev->data.descr_id);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_WRITE_DESCRIPTOR,
					sizeof(*ev), ev);
}

static void write_descr_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct desc_data *cb_data = user_data;

	if (status)
		error("gatt: Write descriptors failed: %s",
							att_ecode2str(status));

	send_client_descr_write_notify(status, cb_data->conn_id,
					cb_data->srvc_id, cb_data->char_id,
					cb_data->descr_id, cb_data->primary);

	free(cb_data);
}

static void handle_client_write_descriptor(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_write_descriptor *cmd = buf;
	struct desc_data *cb_data;
	struct characteristic *ch;
	struct descriptor *descr;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	struct element_id descr_id;
	struct gatt_device *dev;
	int32_t conn_id;
	uint8_t primary;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) + cmd->len) {
		error("Invalid write desriptor command (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	primary = cmd->srvc_id.is_primary;
	conn_id = cmd->conn_id;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);
	hal_gatt_id_to_element_id(&cmd->descr_id, &descr_id);

	if (!find_service(cmd->conn_id, &srvc_id, &dev, &srvc)) {
		error("gatt: Write descr. could not find service");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Write descr. could not find characteristic");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	descr = queue_find(ch->descriptors, match_descr_by_element_id,
								&descr_id);
	if (!descr) {
		error("gatt: Write descr. could not find descriptor");

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	cb_data = new0(struct desc_data, 1);
	if (!cb_data) {
		error("gatt: Write descr. could not allocate callback data");

		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	cb_data->conn_id = conn_id;
	cb_data->srvc_id = &srvc->id;
	cb_data->char_id = &ch->id;
	cb_data->descr_id = &descr->id;
	cb_data->primary = primary;

	if (!gatt_write_char(dev->attrib, descr->handle, cmd->value, cmd->len,
						write_descr_cb, cb_data)) {
		free(cb_data);

		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	if (status != HAL_STATUS_SUCCESS)
		send_client_descr_write_notify(GATT_FAILURE, conn_id, &srvc_id,
						&char_id, &descr_id, primary);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR, status);
}

static void handle_client_execute_write(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_EXECUTE_WRITE, HAL_STATUS_FAILED);
}

static void handle_notification(const uint8_t *pdu, uint16_t len,
							gpointer user_data)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_notify *ev = (void *) buf;
	struct notification_data *notification = user_data;
	uint8_t data_offset = sizeof(uint8_t) + sizeof(uint16_t);

	if (len < data_offset)
		return;

	memcpy(&ev->char_id, &notification->ch, sizeof(ev->char_id));
	memcpy(&ev->srvc_id, &notification->service, sizeof(ev->srvc_id));
	bdaddr2android(&notification->dev->bdaddr, &ev->bda);
	ev->conn_id = notification->dev->conn_id;
	ev->is_notify = pdu[0] == ATT_OP_HANDLE_NOTIFY;

	/* We have to cut opcode and handle from data */
	ev->len = len - data_offset;
	memcpy(ev->value, pdu + data_offset, len - data_offset);

	if (!ev->is_notify) {
		uint8_t *res;
		uint16_t len;
		size_t plen;

		res = g_attrib_get_buffer(notification->dev->attrib, &plen);
		len = enc_confirmation(res, plen);
		if (len > 0)
			g_attrib_send(notification->dev->attrib, 0, res, len,
							NULL, NULL, NULL);
	}

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT, HAL_EV_GATT_CLIENT_NOTIFY,
						sizeof(*ev) + ev->len, ev);
}

static void send_register_for_notification_ev(int32_t id, int32_t registered,
					int32_t status,
					const struct hal_gatt_srvc_id *srvc,
					const struct hal_gatt_gatt_id *ch)
{
	struct hal_ev_gatt_client_reg_for_notif ev;

	ev.conn_id = id;
	ev.status = status;
	ev.registered = registered;
	memcpy(&ev.srvc_id, srvc, sizeof(ev.srvc_id));
	memcpy(&ev.char_id, ch, sizeof(ev.char_id));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_REGISTER_FOR_NOTIF, sizeof(ev), &ev);
}

static void handle_client_register_for_notification(const void *buf,
								uint16_t len)
{
	const struct hal_cmd_gatt_client_register_for_notification *cmd = buf;
	struct notification_data *notification;
	struct gatt_client *client;
	struct characteristic *c;
	struct element_id match_id;
	struct gatt_device *dev;
	struct service *service;
	int32_t conn_id = 0;
	uint8_t status;
	int32_t gatt_status;
	bdaddr_t addr;

	DBG("");

	client = find_client_by_id(cmd->client_if);
	if (!client) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2bdaddr(&cmd->bdaddr, &addr);

	dev = queue_find(conn_list, match_dev_by_bdaddr, &addr);
	if (!dev) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	conn_id = dev->conn_id;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &match_id);
	service = queue_find(dev->services, match_srvc_by_element_id,
								&match_id);
	if (!service) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	hal_gatt_id_to_element_id(&cmd->char_id, &match_id);
	c = queue_find(service->chars, match_char_by_element_id, &match_id);
	if (!c) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	notification = new0(struct notification_data, 1);
	if (!notification) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	memcpy(&notification->ch, &cmd->char_id, sizeof(notification->ch));
	memcpy(&notification->service, &cmd->srvc_id,
						sizeof(notification->service));
	notification->dev = dev;
	notification->client = client;

	if (queue_find(client->notifications, match_notification,
								notification)) {
		free(notification);
		status = HAL_STATUS_SUCCESS;
		goto failed;
	}

	notification->notif_id = g_attrib_register(dev->attrib,
							ATT_OP_HANDLE_NOTIFY,
							c->ch.value_handle,
							handle_notification,
							notification,
							destroy_notification);
	if (!notification->notif_id) {
		free(notification);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	notification->ind_id = g_attrib_register(dev->attrib, ATT_OP_HANDLE_IND,
							c->ch.value_handle,
							handle_notification,
							notification,
							destroy_notification);
	if (!notification->ind_id) {
		g_attrib_unregister(dev->attrib, notification->notif_id);
		free(notification);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* Because same data - notification - is shared by two handlers, we
	 * introduce ref counter to be sure that data can be freed with no risk.
	 * Counter is decremented in destroy_notification.
	 */
	notification->ref = 2;

	if (!queue_push_tail(client->notifications, notification)) {
		unregister_notification(notification);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	gatt_status = status ? GATT_FAILURE : GATT_SUCCESS;
	send_register_for_notification_ev(conn_id, 1, gatt_status,
						&cmd->srvc_id, &cmd->char_id);
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION,
				status);
}

static void handle_client_deregister_for_notification(const void *buf,
								uint16_t len)
{
	const struct hal_cmd_gatt_client_deregister_for_notification *cmd = buf;
	struct notification_data *notification, notif;
	struct gatt_client *client;
	struct gatt_device *dev;
	int32_t conn_id = 0;
	uint8_t status;
	int32_t gatt_status;
	bdaddr_t addr;

	DBG("");

	client = find_client_by_id(cmd->client_if);
	if (!client) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2bdaddr(&cmd->bdaddr, &addr);

	dev = find_device(&addr);
	if (!dev) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	conn_id = dev->conn_id;
	memcpy(&notif.ch, &cmd->char_id, sizeof(notif.ch));
	memcpy(&notif.service, &cmd->srvc_id, sizeof(notif.service));
	notif.dev = dev;

	notification = queue_find(client->notifications,
						match_notification, &notif);
	if (!notification) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	unregister_notification(notification);

	status = HAL_STATUS_SUCCESS;

failed:
	gatt_status = status ? GATT_FAILURE : GATT_SUCCESS;
	send_register_for_notification_ev(conn_id, 0, gatt_status,
						&cmd->srvc_id, &cmd->char_id);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION,
				status);
}

static void handle_client_read_remote_rssi(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_remote_rssi *cmd = buf;
	struct hal_ev_gatt_client_read_remote_rssi ev;
	uint8_t status;

	DBG("");

	if (!queue_find(gatt_clients, match_client_by_id,
						INT_TO_PTR(cmd->client_if))) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* TODO fake RSSI until kernel support is added */
	ev.client_if = cmd->client_if;
	memcpy(ev.address, cmd->bdaddr, sizeof(ev.address));
	ev.status = HAL_STATUS_SUCCESS;
	ev.rssi = -50 - (rand() % 40);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_READ_REMOTE_RSSI, sizeof(ev), &ev);

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI, status);
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
	const struct hal_cmd_gatt_server_register *cmd = buf;
	struct hal_ev_gatt_server_register ev;
	struct gatt_server *server;
	static int32_t server_cnt = 1;
	uint32_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	if (queue_find(gatt_servers, match_server_by_uuid, &cmd->uuid)) {
		error("gatt: Server uuid is already on list");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	server = new0(struct gatt_server, 1);
	if (!server) {
		error("gatt: Cannot allocate memory for registering server");
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	memcpy(server->uuid, cmd->uuid, sizeof(server->uuid));

	server->id = server_cnt++;

	if (!queue_push_head(gatt_servers, server)) {
		error("gatt: Cannot push server on the list");
		free(server);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ev.status = GATT_SUCCESS;
	ev.server_if = server->id;
	memcpy(ev.uuid, server->uuid, sizeof(server->uuid));

	status = HAL_STATUS_SUCCESS;

failed:
	if (status != HAL_STATUS_SUCCESS)
		ev.status = GATT_FAILURE;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_SERVER_REGISTER, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_REGISTER,
									status);
}

static void handle_server_unregister(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_unregister *cmd = buf;
	uint8_t status;
	struct gatt_server *server;

	DBG("");

	server = queue_remove_if(gatt_servers, match_server_by_id,
						INT_TO_PTR(cmd->server_if));
	if (!server) {
		error("gatt: server_if=%d not found", cmd->server_if);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	destroy_gatt_server(server);
	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_UNREGISTER, status);
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
	{ handle_client_register, false,
		sizeof(struct hal_cmd_gatt_client_register) },
	/* HAL_OP_GATT_CLIENT_UNREGISTER */
	{ handle_client_unregister, false,
		sizeof(struct hal_cmd_gatt_client_unregister) },
	/* HAL_OP_GATT_CLIENT_SCAN */
	{ handle_client_scan, false,
		sizeof(struct hal_cmd_gatt_client_scan) },
	/* HAL_OP_GATT_CLIENT_CONNECT */
	{ handle_client_connect, false,
		sizeof(struct hal_cmd_gatt_client_connect) },
	/* HAL_OP_GATT_CLIENT_DISCONNECT */
	{ handle_client_disconnect, false,
		sizeof(struct hal_cmd_gatt_client_disconnect) },
	/* HAL_OP_GATT_CLIENT_LISTEN */
	{ handle_client_listen, false,
		sizeof(struct hal_cmd_gatt_client_listen) },
	/* HAL_OP_GATT_CLIENT_REFRESH */
	{ handle_client_refresh, false,
		sizeof(struct hal_cmd_gatt_client_refresh) },
	/* HAL_OP_GATT_CLIENT_SEARCH_SERVICE */
	{ handle_client_search_service, true,
		sizeof(struct hal_cmd_gatt_client_search_service) },
	/* HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE */
	{ handle_client_get_included_service, true,
		sizeof(struct hal_cmd_gatt_client_get_included_service) },
	/* HAL_OP_GATT_CLIENT_GET_CHARACTERISTIC */
	{ handle_client_get_characteristic, true,
		sizeof(struct hal_cmd_gatt_client_get_characteristic) },
	/* HAL_OP_GATT_CLIENT_GET_DESCRIPTOR */
	{ handle_client_get_descriptor, true,
		sizeof(struct hal_cmd_gatt_client_get_descriptor) },
	/* HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC */
	{ handle_client_read_characteristic, false,
		sizeof(struct hal_cmd_gatt_client_read_characteristic) },
	/* HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC */
	{ handle_client_write_characteristic, true,
		sizeof(struct hal_cmd_gatt_client_write_characteristic) },
	/* HAL_OP_GATT_CLIENT_READ_DESCRIPTOR */
	{ handle_client_read_descriptor, false,
		sizeof(struct hal_cmd_gatt_client_read_descriptor) },
	/* HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR */
	{ handle_client_write_descriptor, true,
		sizeof(struct hal_cmd_gatt_client_write_descriptor) },
	/* HAL_OP_GATT_CLIENT_EXECUTE_WRITE */
	{ handle_client_execute_write, false,
		sizeof(struct hal_cmd_gatt_client_execute_write)},
	/* HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION */
	{ handle_client_register_for_notification, false,
		sizeof(struct hal_cmd_gatt_client_register_for_notification) },
	/* HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION */
	{ handle_client_deregister_for_notification, false,
		sizeof(struct hal_cmd_gatt_client_deregister_for_notification) },
	/* HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI */
	{ handle_client_read_remote_rssi, false,
		sizeof(struct hal_cmd_gatt_client_read_remote_rssi) },
	/* HAL_OP_GATT_CLIENT_GET_DEVICE_TYPE */
	{ handle_client_get_device_type, false,
		sizeof(struct hal_cmd_gatt_client_get_device_type) },
	/* HAL_OP_GATT_CLIENT_SET_ADV_DATA */
	{ handle_client_set_adv_data, true,
		sizeof(struct hal_cmd_gatt_client_set_adv_data) },
	/* HAL_OP_GATT_CLIENT_TEST_COMMAND */
	{ handle_client_test_command, false,
		sizeof(struct hal_cmd_gatt_client_test_command) },
	/* HAL_OP_GATT_SERVER_REGISTER */
	{ handle_server_register, false,
		sizeof(struct hal_cmd_gatt_server_register) },
	/* HAL_OP_GATT_SERVER_UNREGISTER */
	{ handle_server_unregister, false,
		sizeof(struct hal_cmd_gatt_server_unregister) },
	/* HAL_OP_GATT_SERVER_CONNECT */
	{ handle_server_connect, false,
		sizeof(struct hal_cmd_gatt_server_connect) },
	/* HAL_OP_GATT_SERVER_DISCONNECT */
	{ handle_server_disconnect, false,
		sizeof(struct hal_cmd_gatt_server_disconnect) },
	/* HAL_OP_GATT_SERVER_ADD_SERVICE */
	{ handle_server_add_service, false,
		sizeof(struct hal_cmd_gatt_server_add_service) },
	/* HAL_OP_GATT_SERVER_ADD_INC_SERVICE */
	{ handle_server_add_included_service, false,
		sizeof(struct hal_cmd_gatt_server_add_inc_service) },
	/* HAL_OP_GATT_SERVER_ADD_CHARACTERISTIC */
	{ handle_server_add_characteristic, false,
		sizeof(struct hal_cmd_gatt_server_add_characteristic) },
	/* HAL_OP_GATT_SERVER_ADD_DESCRIPTOR */
	{ handle_server_add_descriptor, false,
		sizeof(struct hal_cmd_gatt_server_add_descriptor) },
	/* HAL_OP_GATT_SERVER_START_SERVICE */
	{ handle_server_start_service, false,
		sizeof(struct hal_cmd_gatt_server_start_service) },
	/* HAL_OP_GATT_SERVER_STOP_SERVICE */
	{ handle_server_stop_service, false,
		sizeof(struct hal_cmd_gatt_server_stop_service) },
	/* HAL_OP_GATT_SERVER_DELETE_SERVICE */
	{ handle_server_delete_service, false,
		sizeof(struct hal_cmd_gatt_server_delete_service) },
	/* HAL_OP_GATT_SERVER_SEND_INDICATION */
	{ handle_server_send_indication, true,
		sizeof(struct hal_cmd_gatt_server_send_indication) },
	/* HAL_OP_GATT_SERVER_SEND_RESPONSE */
	{ handle_server_send_response, true,
		sizeof(struct hal_cmd_gatt_server_send_response) },
};

bool bt_gatt_register(struct ipc *ipc, const bdaddr_t *addr)
{
	DBG("");

	conn_list = queue_new();
	conn_wait_queue = queue_new();
	gatt_clients = queue_new();
	gatt_servers = queue_new();
	disc_dev_list = queue_new();

	if (!conn_list || !conn_wait_queue || !gatt_clients || !gatt_servers ||
							!disc_dev_list) {
		error("gatt: Failed to allocate memory for queues");

		queue_destroy(gatt_servers, NULL);
		gatt_servers = NULL;

		queue_destroy(gatt_clients, NULL);
		gatt_clients = NULL;

		queue_destroy(conn_list, NULL);
		conn_list = NULL;

		queue_destroy(conn_wait_queue, NULL);
		conn_wait_queue = NULL;

		queue_destroy(disc_dev_list, NULL);
		disc_dev_list = NULL;

		return false;
	}

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

	queue_destroy(gatt_servers, destroy_gatt_server);
	gatt_servers = NULL;

	queue_destroy(gatt_clients, destroy_gatt_client);
	gatt_clients = NULL;

	queue_destroy(conn_list, destroy_device);
	conn_list = NULL;

	queue_destroy(conn_wait_queue, destroy_device);
	conn_wait_queue = NULL;

	queue_destroy(disc_dev_list, destroy_device);
	disc_dev_list = NULL;
}
