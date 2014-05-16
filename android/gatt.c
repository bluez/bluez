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
#include "src/shared/gatt-db.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "btio/btio.h"

/* set according to Android bt_gatt_client.h */
#define GATT_MAX_ATTR_LEN 600

#define GATT_SUCCESS	0x00000000
#define GATT_FAILURE	0x00000101

#define BASE_UUID16_OFFSET     12

static const uint8_t BLUETOOTH_UUID[] = {
	0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

typedef enum {
	DEVICE_DISCONNECTED = 0,
	DEVICE_CONNECT_INIT,		/* connection procedure initiated */
	DEVICE_CONNECT_READY,		/* dev found during LE scan */
	DEVICE_CONNECTED,		/* connection has been established */
} gatt_device_state_t;

static const char const *device_state_str[] = {
	"DISCONNECTED",
	"CONNECT INIT",
	"CONNECT READY",
	"CONNECTED",
};

typedef enum {
	APP_CLIENT,
	APP_SERVER,
} gatt_app_type_t;

struct pending_trans_data {
	unsigned int id;
	uint8_t opcode;
};

struct gatt_app {
	int32_t id;
	uint8_t uuid[16];

	gatt_app_type_t type;

	/* Valid for client applications */
	struct queue *notifications;

	/* Transaction data valid for server application */
	struct pending_trans_data trans_id;
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
	uint16_t end_handle;

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
	struct app_connection *conn;
	guint notif_id;
	guint ind_id;
	int ref;
};

struct gatt_device {
	bdaddr_t bdaddr;
	uint8_t bdaddr_type;

	gatt_device_state_t state;

	GAttrib *attrib;
	GIOChannel *att_io;
	struct queue *services;
	bool partial_srvc_search;

	bool notify_services_changed;

	guint watch_id;
	guint server_id;

	int ref;
	int conn_cnt;

	struct queue *pending_requests;
};

struct app_connection {
	struct gatt_device *device;
	struct gatt_app *app;
	int32_t id;
};

static struct ipc *hal_ipc = NULL;
static bdaddr_t adapter_addr;
static bool scanning = false;
static unsigned int advertising_cnt = 0;

static struct queue *gatt_apps = NULL;
static struct queue *gatt_devices = NULL;
static struct queue *app_connections = NULL;

static struct queue *listen_apps = NULL;
static struct gatt_db *gatt_db = NULL;

static GIOChannel *listening_io = NULL;

static void bt_le_discovery_stop_cb(void);

static bool is_bluetooth_uuid(const uint8_t *uuid)
{
	int i;

	for (i = 0; i < 16; i++) {
		/* ignore minimal uuid (16) value */
		if (i == 12 || i == 13)
			continue;

		if (uuid[i] != BLUETOOTH_UUID[i])
			return false;
	}

	return true;
}

static void android2uuid(const uint8_t *uuid, bt_uuid_t *dst)
{
	if (is_bluetooth_uuid(uuid)) {
		/* copy 16 bit uuid value from full android 128bit uuid */
		dst->type = BT_UUID16;
		dst->value.u16 = (uuid[13] << 8) + uuid[12];
	} else {
		int i;

		dst->type = BT_UUID128;
		for (i = 0; i < 16; i++)
			dst->value.u128.data[i] = uuid[15 - i];
	}
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

	/*
	 * Included services we keep on two queues.
	 * 1. On the same queue with primary services.
	 * 2. On the queue inside primary service.
	 * So we need to free service memory only once but we need to destroy
	 * two queues
	 */
	if (srvc->primary)
		queue_destroy(srvc->included, NULL);

	free(srvc);
}

static bool match_app_by_uuid(const void *data, const void *user_data)
{
	const uint8_t *exp_uuid = user_data;
	const struct gatt_app *client = data;

	return !memcmp(exp_uuid, client->uuid, sizeof(client->uuid));
}

static bool match_app_by_id(const void *data, const void *user_data)
{
	int32_t exp_id = PTR_TO_INT(user_data);
	const struct gatt_app *client = data;

	return client->id == exp_id;
}

static struct gatt_app *find_app_by_id(int32_t id)
{
	return queue_find(gatt_apps, match_app_by_id, INT_TO_PTR(id));
}

static bool match_by_value(const void *data, const void *user_data)
{
	return data == user_data;
}

static bool match_device_by_bdaddr(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;
	const bdaddr_t *addr = user_data;

	return !bacmp(&dev->bdaddr, addr);
}

static bool match_device_by_state(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;

	if (dev->state != PTR_TO_UINT(user_data))
		return false;

	return true;
}

static bool match_pending_device(const void *data, const void *user_data)
{
	const struct gatt_device *dev = data;

	if ((dev->state == DEVICE_CONNECT_INIT) ||
					(dev->state == DEVICE_CONNECT_READY))
		return true;

	return false;
}

static bool match_connection_by_id(const void *data, const void *user_data)
{
	const struct app_connection *conn = data;
	const int32_t id = PTR_TO_INT(user_data);

	return conn->id == id;
}

static bool match_connection_by_device_and_app(const void *data,
							const void *user_data)
{
	const struct app_connection *conn = data;
	const struct app_connection *match = user_data;

	return conn->device == match->device && conn->app == match->app;
}

static struct app_connection *find_connection_by_id(int32_t conn_id)
{
	return queue_find(app_connections, match_connection_by_id,
							INT_TO_PTR(conn_id));
}

static bool match_connection_by_device(const void *data, const void *user_data)
{
	const struct app_connection *conn = data;
	const struct gatt_device *dev = user_data;

	return conn->device == dev;
}

static bool match_connection_by_app(const void *data, const void *user_data)
{
	const struct app_connection *conn = data;
	const struct gatt_app *app = user_data;

	return conn->app == app;
}

static struct gatt_device *find_device_by_addr(const bdaddr_t *addr)
{
	return queue_find(gatt_devices, match_device_by_bdaddr, (void *)addr);
}

static struct gatt_device *find_pending_device()
{
	return queue_find(gatt_devices, match_pending_device, NULL);
}

static struct gatt_device *find_device_by_state(uint32_t state)
{
	return queue_find(gatt_devices, match_device_by_state,
							UINT_TO_PTR(state));
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

static bool match_srvc_by_bt_uuid(const void *data, const void *user_data)
{
	const bt_uuid_t *exp_uuid = user_data;
	const struct service *service = data;

	return !bt_uuid_cmp(exp_uuid, &service->id.uuid);
}

static bool match_srvc_by_range(const void *data, const void *user_data)
{
	const struct service *srvc = data;
	const struct att_range *range = user_data;

	return !memcmp(&srvc->prim.range, range, sizeof(srvc->prim.range));
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

	if (a1->conn != b1->conn)
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
	struct gatt_app *app;

	if (--notification->ref)
		return;

	app = notification->conn->app;
	queue_remove_if(app->notifications, match_notification, notification);
	free(notification);
}

static void unregister_notification(void *data)
{
	struct notification_data *notification = data;
	struct gatt_device *dev = notification->conn->device;

	/*
	 * No device means it was already disconnected and client cleanup was
	 * triggered afterwards, but once client unregisters, device stays if
	 * used by others. Then just unregister single handle.
	 */
	if (!queue_find(gatt_devices, match_by_value, dev))
		return;

	if (notification->notif_id && dev)
		g_attrib_unregister(dev->attrib, notification->notif_id);

	if (notification->ind_id && dev)
		g_attrib_unregister(dev->attrib, notification->ind_id);
}

static void device_set_state(struct gatt_device *dev, uint32_t state)
{
	char bda[18];

	ba2str(&dev->bdaddr, bda);
	DBG("gatt: Device %s state changed %s -> %s", bda,
			device_state_str[dev->state], device_state_str[state]);

	dev->state = state;
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

	if (device->server_id > 0)
		g_attrib_unregister(device->attrib, device->server_id);

	if (device->attrib) {
		GAttrib *attrib = device->attrib;
		device->attrib = NULL;
		g_attrib_cancel_all(attrib);
		g_attrib_unref(attrib);
	}

	/*
	 * If device was in connection_pending or connectable state we
	 * search device list if we should stop the scan.
	 */
	if (!scanning && (device->state == DEVICE_CONNECT_INIT ||
				device->state == DEVICE_CONNECT_READY)) {
		if (!find_pending_device())
			bt_le_discovery_stop(NULL);
	}

	/* If device is not bonded service cache should be refreshed */
	if (!bt_device_is_bonded(&device->bdaddr))
		queue_remove_all(device->services, NULL, NULL, destroy_service);

	device_set_state(device, DEVICE_DISCONNECTED);
}

static void destroy_gatt_app(void *data)
{
	struct gatt_app *app = data;

	/*
	 * First we want to get all notifications and unregister them.
	 * We don't pass unregister_notification to queue_destroy,
	 * because destroy notification performs operations on queue
	 * too. So remove all elements and then destroy queue.
	 */

	if (app->type == APP_CLIENT)
		while (queue_peek_head(app->notifications)) {
			struct notification_data *notification;

			notification = queue_pop_head(app->notifications);
			unregister_notification(notification);
		}

	queue_destroy(app->notifications, free);

	free(app);
}

static int register_app(const uint8_t *uuid, gatt_app_type_t app_type)
{
	static int32_t application_id = 1;
	struct gatt_app *app;

	if (queue_find(gatt_apps, match_app_by_uuid, (void *) uuid)) {
		error("gatt: app uuid is already on list");
		return 0;
	}

	app = new0(struct gatt_app, 1);
	if (!app) {
		error("gatt: Cannot allocate memory for registering app");
		return 0;
	}

	app->type = app_type;

	if (app->type == APP_CLIENT) {
		app->notifications = queue_new();
		if (!app->notifications) {
			error("gatt: couldn't allocate notifications queue");
			destroy_gatt_app(app);
			return 0;
		}
	}

	memcpy(app->uuid, uuid, sizeof(app->uuid));

	app->id = application_id++;

	if (!queue_push_head(gatt_apps, app)) {
		error("gatt: Cannot push app on the list");
		destroy_gatt_app(app);
		return 0;
	}

	if ((app->type == APP_SERVER) &&
			!queue_push_tail(listen_apps, INT_TO_PTR(app->id))) {
		error("gatt: Cannot push server on the list");
		destroy_gatt_app(app);
		return 0;
	}

	return app->id;
}

static void handle_client_register(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_register *cmd = buf;
	struct hal_ev_gatt_client_register_client ev;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	ev.client_if = register_app(cmd->uuid, APP_CLIENT);

	if (ev.client_if)
		ev.status = GATT_SUCCESS;
	else
		ev.status = GATT_FAILURE;

	/* We should send notification with given in cmd UUID */
	memcpy(ev.app_uuid, cmd->uuid, sizeof(ev.app_uuid));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_REGISTER_CLIENT, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_REGISTER,
							HAL_STATUS_SUCCESS);
}

static void send_client_disconnection_notify(struct app_connection *connection,
								int32_t status)
{
	struct hal_ev_gatt_client_disconnect ev;

	ev.client_if = connection->app->id;
	ev.conn_id = connection->id;
	ev.status = status;

	bdaddr2android(&connection->device->bdaddr, &ev.bda);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_CLIENT_DISCONNECT, sizeof(ev), &ev);
}

static void send_client_connection_notify(struct app_connection *connection,
								int32_t status)
{
	struct hal_ev_gatt_client_connect ev;

	ev.client_if = connection->app->id;
	ev.conn_id = connection->id;
	ev.status = status;

	bdaddr2android(&connection->device->bdaddr, &ev.bda);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT, HAL_EV_GATT_CLIENT_CONNECT,
							sizeof(ev), &ev);
}

static void send_server_connection_notify(struct app_connection *connection,
								bool connected)
{
	struct hal_ev_gatt_server_connection ev;

	ev.server_if = connection->app->id;
	ev.conn_id = connection->id;
	ev.connected = connected;

	bdaddr2android(&connection->device->bdaddr, &ev.bdaddr);

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_SERVER_CONNECTION, sizeof(ev), &ev);
}

static void send_app_disconnect_notify(struct app_connection *connection,
								int32_t status)
{
	if (connection->app->type == APP_CLIENT)
		send_client_disconnection_notify(connection, status);
	else
		send_server_connection_notify(connection, !!status);
}

static void send_app_connect_notify(struct app_connection *connection,
								int32_t status)
{
	if (connection->app->type == APP_CLIENT)
		send_client_connection_notify(connection, status);
	else
		send_server_connection_notify(connection, !status);
}

static void disconnect_notify_by_device(void *data, void *user_data)
{
	struct app_connection *conn = data;
	struct gatt_device *dev = user_data;

	if (dev != conn->device)
		return;

	if (dev->state == DEVICE_CONNECTED)
		send_app_disconnect_notify(conn, GATT_SUCCESS);
	else if (dev->state == DEVICE_CONNECT_INIT ||
					dev->state == DEVICE_CONNECT_READY)
		send_app_connect_notify(conn, GATT_FAILURE);
}

#define READ_INIT -3
#define READ_PENDING -2
#define READ_FAILED -1

struct pending_request {
	uint16_t handle;
	int length;
	uint8_t *value;
	uint16_t offset;

	uint8_t *filter_value;
	uint16_t filter_vlen;
};

static void destroy_pending_request(void *data)
{
	struct pending_request *entry = data;

	free(entry->value);
	free(entry->filter_value);
	free(entry);
}

static void destroy_device(void *data)
{
	struct gatt_device *dev = data;

	if (!dev)
		return;

	queue_destroy(dev->services, destroy_service);
	queue_destroy(dev->pending_requests, destroy_pending_request);

	free(dev);
}

static struct gatt_device *device_ref(struct gatt_device *device)
{
	if (!device)
		return NULL;

	device->ref++;

	return device;
}

static void device_unref(struct gatt_device *device)
{
	if (!device)
		return;

	if (--device->ref)
		return;

	destroy_device(device);
}

static void destroy_connection(void *data)
{
	struct app_connection *conn = data;

	if (!queue_find(gatt_devices, match_by_value, conn->device))
		goto cleanup;

	conn->device->conn_cnt--;
	if (conn->device->conn_cnt == 0)
		connection_cleanup(conn->device);

cleanup:
	device_unref(conn->device);
	free(conn);
}

static void device_disconnect_clients(struct gatt_device *dev)
{
	/* Notify disconnection to all clients */
	queue_foreach(app_connections, disconnect_notify_by_device, dev);

	/* Remove all clients by given device's */
	queue_remove_all(app_connections, match_connection_by_device, dev,
							destroy_connection);
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
			HAL_EV_GATT_CLIENT_SEARCH_RESULT, sizeof(ev), &ev);
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

static void le_device_found_handler(const bdaddr_t *addr, uint8_t addr_type,
						int rssi, uint16_t eir_len,
							const void *eir,
							bool discoverable)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_scan_result *ev = (void *) buf;
	struct gatt_device *dev;
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
	dev = find_device_by_addr(addr);
	if (!dev || (dev->state != DEVICE_CONNECT_INIT))
		return;

	device_set_state(dev, DEVICE_CONNECT_READY);
	dev->bdaddr_type = addr_type;

	/*
	 * We are ok to perform connect now. Stop discovery
	 * and once it is stopped continue with creating ACL
	 */
	bt_le_discovery_stop(bt_le_discovery_stop_cb);
}

static gboolean disconnected_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct gatt_device *dev = user_data;
	int sock, err = 0;
	socklen_t len;

	sock = g_io_channel_unix_get_fd(io);
	len = sizeof(err);
	if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len))
		DBG("%s (%d)", strerror(err), err);

	device_disconnect_clients(dev);

	return FALSE;
}

struct connect_data {
	struct gatt_device *dev;
	int32_t status;
};

static void send_app_connect_notifications(void *data, void *user_data)
{
	struct app_connection *conn = data;
	struct connect_data *con_data = user_data;

	if (conn->device == con_data->dev)
		send_app_connect_notify(conn, con_data->status);
}

static void att_handler(const uint8_t *ipdu, uint16_t len, gpointer user_data);

static void connect_cb(GIOChannel *io, GError *gerr, gpointer user_data)
{
	struct gatt_device *dev = user_data;
	struct connect_data data;
	uint32_t status;
	GAttrib *attrib;

	if (dev->state != DEVICE_CONNECT_READY) {
		error("gatt: Device not in a connecting state!?");
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	g_io_channel_unref(dev->att_io);
	dev->att_io = NULL;

	if (gerr) {
		error("gatt: connection failed %s", gerr->message);
		device_set_state(dev, DEVICE_DISCONNECTED);
		status = GATT_FAILURE;
		goto reply;
	}

	attrib = g_attrib_new(io);
	if (!attrib) {
		error("gatt: unable to create new GAttrib instance");
		device_set_state(dev, DEVICE_DISCONNECTED);
		status = GATT_FAILURE;
		goto reply;
	}

	dev->attrib = attrib;
	dev->watch_id = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							disconnected_cb, dev);

	dev->server_id = g_attrib_register(attrib, GATTRIB_ALL_REQS,
						GATTRIB_ALL_HANDLES,
						att_handler, dev, NULL);
	if (dev->server_id == 0)
		error("gatt: Could not attach to server");

	device_set_state(dev, DEVICE_CONNECTED);

	status = GATT_SUCCESS;

reply:
	data.dev = dev;
	data.status = status;
	queue_foreach(app_connections, send_app_connect_notifications, &data);
	device_unref(dev);

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

	/*
	 * This connection will help us catch any PDUs that comes before
	 * pairing finishes
	 */
	io = bt_io_connect(connect_cb, device_ref(dev), NULL, &gerr,
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

	registered = find_app_by_id(cmd->client_if);
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

	dev = find_device_by_state(DEVICE_CONNECT_READY);
	if (!dev)
		return -ENODEV;

	return connect_le(dev);
}

static void bt_le_discovery_stop_cb(void)
{
	DBG("");

	/* Check now if there is any device ready to connect */
	if (connect_next_dev() < 0)
		bt_le_discovery_start(le_device_found_handler);
}

static struct gatt_device *create_device(const bdaddr_t *addr)
{
	struct gatt_device *dev;

	dev = new0(struct gatt_device, 1);
	if (!dev)
		return NULL;

	bacpy(&dev->bdaddr, addr);

	dev->services = queue_new();
	if (!dev->services) {
		error("gatt: Failed to allocate memory for client");
		destroy_device(dev);
		return NULL;
	}

	dev->pending_requests = queue_new();
	if (!dev->pending_requests) {
		error("gatt: Failed to allocate memory for client");
		destroy_device(dev);
		return NULL;
	}

	if (!queue_push_head(gatt_devices, dev)) {
		error("gatt: Cannot push device to queue");
		destroy_device(dev);
		return NULL;
	}

	return device_ref(dev);
}

static struct app_connection *create_connection(struct gatt_device *device,
						struct gatt_app *app)
{
	struct app_connection *new_conn;
	static int32_t last_conn_id = 1;

	/* Check if already connected */
	new_conn = new0(struct app_connection, 1);
	if (!new_conn)
		return NULL;

	/* Make connection id unique to connection record (app, device) pair */
	new_conn->app = app;
	new_conn->id = last_conn_id++;

	if (!queue_push_head(app_connections, new_conn)) {
		error("gatt: Cannot push client on the client queue!?");

		free(new_conn);
		return NULL;
	}

	new_conn->device = device_ref(device);
	new_conn->device->conn_cnt++;

	return new_conn;
}

static void trigger_disconnection(struct app_connection *connection)
{
	/* Notify client */
	if (queue_remove(app_connections, connection))
			send_app_disconnect_notify(connection, GATT_SUCCESS);

	destroy_connection(connection);
}

static void app_disconnect_devices(struct gatt_app *client)
{
	struct app_connection *conn;

	/* find every connection for client record and trigger disconnect */
	conn = queue_remove_if(app_connections, match_connection_by_app,
									client);
	while (conn) {
		trigger_disconnection(conn);

		conn = queue_remove_if(app_connections,
					match_connection_by_app, client);
	}
}

static bool trigger_connection(struct app_connection *connection)
{
	switch (connection->device->state) {
	case DEVICE_DISCONNECTED:
		device_set_state(connection->device, DEVICE_CONNECT_INIT);
		break;
	case DEVICE_CONNECTED:
		send_app_connect_notify(connection, GATT_SUCCESS);
		break;
	default:
		break;
	}

	/* after state change trigger discovering */
	if (!scanning && (connection->device->state == DEVICE_CONNECT_INIT))
		if (!bt_le_discovery_start(le_device_found_handler)) {
			error("gatt: Could not start scan");

			return false;
		}

	return true;
}

static void handle_client_unregister(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_unregister *cmd = buf;
	uint8_t status;
	struct gatt_app *cl;

	DBG("");

	cl = queue_remove_if(gatt_apps, match_app_by_id,
						INT_TO_PTR(cmd->client_if));
	if (!cl) {
		error("gatt: client_if=%d not found", cmd->client_if);
		status = HAL_STATUS_FAILED;
	} else {
		/*
		 * Check if there is any connect request or connected device
		 * for this client. If so, remove this client from those lists.
		 */
		app_disconnect_devices(cl);
		destroy_gatt_app(cl);
		status = HAL_STATUS_SUCCESS;
	}

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_UNREGISTER, status);
}

static struct app_connection *find_conn(const bdaddr_t *addr, int32_t app_id)
{
	struct app_connection conn_match;
	struct gatt_device *dev = NULL;
	struct gatt_app *app;

	/* Check if app is registered */
	app = find_app_by_id(app_id);
	if (!app) {
		error("gatt: Client id %d not found", app_id);
		return NULL;
	}

	/* Check if device is known */
	dev = find_device_by_addr(addr);
	if (!dev) {
		error("gatt: Client id %d not found", app_id);
		return NULL;
	}

	conn_match.device = dev;
	conn_match.app = app;

	return queue_find(app_connections, match_connection_by_device_and_app,
								&conn_match);
}

static uint8_t handle_connect(int32_t app_id, const bdaddr_t *addr)
{
	struct app_connection conn_match;
	struct app_connection *conn;
	struct gatt_device *device;
	struct gatt_app *app;

	DBG("");

	app = find_app_by_id(app_id);
	if (!app)
		return HAL_STATUS_FAILED;

	device = find_device_by_addr(addr);
	if (!device) {
		device = create_device(addr);
		if (!device)
			return HAL_STATUS_FAILED;
	}

	conn_match.device = device;
	conn_match.app = app;

	conn = queue_find(app_connections, match_connection_by_device_and_app,
								&conn_match);
	if (!conn) {
		conn = create_connection(device, app);
		if (!conn)
			return HAL_STATUS_NOMEM;
	}

	if (!trigger_connection(conn))
		return HAL_STATUS_FAILED;

	return HAL_STATUS_SUCCESS;
}

static void handle_client_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_connect *cmd = buf;
	uint8_t status;
	bdaddr_t addr;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &addr);

	/* TODO handle is_direct flag */

	status = handle_connect(cmd->client_if, &addr);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_CONNECT,
								status);
}

static void handle_client_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_disconnect *cmd = buf;
	struct app_connection *conn;
	uint8_t status;

	DBG("");

	/* TODO: should we care to match also bdaddr when conn_id is unique? */
	conn = find_connection_by_id(cmd->conn_id);
	if (conn)
		trigger_disconnection(conn);

	status = HAL_STATUS_SUCCESS;

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_DISCONNECT, status);
}

static void send_client_listen_notify(int32_t id, int32_t status)
{
	struct hal_ev_gatt_client_listen ev;

	/* Server if because of typo in android headers */
	ev.server_if = id;
	ev.status = status;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT, HAL_EV_GATT_CLIENT_LISTEN,
							sizeof(ev), &ev);
}

struct listen_data {
	int32_t client_id;
	bool start;
};

static void set_advertising_cb(uint8_t status, void *user_data)
{
	struct listen_data *l = user_data;

	send_client_listen_notify(l->client_id, status);

	/* In case of success update advertising state*/
	if (!status)
		advertising_cnt = l->start ? 1 : 0;

	/*
	 * Let's remove client from the list in two cases
	 * 1. Start failed
	 * 2. Stop succeed
	 */
	if ((l->start && status) || (!l->start && !status))
		queue_remove(listen_apps, INT_TO_PTR(l->client_id));

	free(l);
}

static void handle_client_listen(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_listen *cmd = buf;
	uint8_t status;
	struct listen_data *data;
	bool req_sent = false;
	void *listening_client;

	DBG("");

	if (!find_app_by_id(cmd->client_if)) {
		error("gatt: Client not registered");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	listening_client = queue_find(listen_apps, match_by_value,
						INT_TO_PTR(cmd->client_if));
	/* Start listening */
	if (cmd->start) {
		if (listening_client) {
			status = HAL_STATUS_SUCCESS;
			goto reply;
		}

		if (!queue_push_tail(listen_apps,
						INT_TO_PTR(cmd->client_if))) {
			error("gatt: Could not put client on listen queue");
			status = HAL_STATUS_FAILED;
			goto reply;
		}

		/* If listen is already on just return success*/
		if (advertising_cnt > 0) {
			advertising_cnt++;
			status = HAL_STATUS_SUCCESS;
			goto reply;
		}
	} else {
		/* Stop listening. Check if client was listening */
		if (!listening_client) {
			error("gatt: This client %d does not listen",
							cmd->client_if);
			status = HAL_STATUS_FAILED;
			goto reply;
		}

		/*
		 * In case there is more listening clients don't stop
		 * advertising
		 */
		if (advertising_cnt > 1) {
			advertising_cnt--;
			queue_remove(listen_apps,
						INT_TO_PTR(cmd->client_if));
			status = HAL_STATUS_SUCCESS;
			goto reply;
		}
	}

	data = new0(struct listen_data, 1);
	if (!data) {
		error("gatt: Could not allocate memory for listen data");
		status = HAL_STATUS_NOMEM;
		goto reply;
	}

	data->client_id = cmd->client_if;
	data->start = cmd->start;

	if (!bt_le_set_advertising(cmd->start, set_advertising_cb, data)) {
		error("gatt: Could not set advertising");
		status = HAL_STATUS_FAILED;
		free(data);
		goto reply;
	}

	/*
	 * Use this flag to keep in mind that we are waiting for callback with
	 * result
	 */
	req_sent = true;

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_CLIENT_LISTEN,
							status);

	/* In case of early success or error, just send notification up */
	if (!req_sent) {
		int32_t gatt_status = status == HAL_STATUS_SUCCESS ?
						GATT_SUCCESS : GATT_FAILURE;
		send_client_listen_notify(cmd->client_if, gatt_status);
	}
}

static void handle_client_refresh(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_refresh *cmd = buf;
	struct gatt_device *dev;
	uint8_t status;
	bdaddr_t bda;

	/*
	 * This is Android's framework hidden API call. It seams that no
	 * notification is expected and Bluedroid silently updates device's
	 * cache under the hood. As we use lazy caching ,we can just clear the
	 * cache and we're done.
	 */

	DBG("");

	android2bdaddr(&cmd->bdaddr, &bda);
	dev = find_device_by_addr(&bda);
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

struct discover_srvc_data {
	bt_uuid_t uuid;
	struct app_connection *conn;
};

static void send_client_search_complete_notify(int32_t status, int32_t conn_id)
{
	struct hal_ev_gatt_client_search_complete ev;

	ev.status = status;
	ev.conn_id = conn_id;
	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_SEARCH_COMPLETE, sizeof(ev), &ev);
}

static void discover_srvc_all_cb(uint8_t status, GSList *services,
								void *user_data)
{
	struct discover_srvc_data *cb_data = user_data;
	struct gatt_device *dev = cb_data->conn->device;
	int32_t gatt_status;
	GSList *l;
	/*
	 * There might be multiply services with same uuid. Therefore make sure
	 * each primary service one has unique instance_id
	 */
	uint8_t instance_id = queue_length(dev->services);

	DBG("Status %d", status);

	if (status) {
		error("gatt: Discover all primary services failed: %s",
							att_ecode2str(status));
		gatt_status = GATT_FAILURE;
		goto reply;
	}

	if (!services) {
		info("gatt: No primary services found");
		gatt_status = GATT_SUCCESS;
		goto reply;
	}

	for (l = services; l; l = l->next) {
		struct gatt_primary *prim = l->data;
		struct service *p;

		if (queue_find(dev->services, match_srvc_by_range,
								&prim->range))
			continue;

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

	/*
	 * Send all found services notifications - first cache,
	 * then send notifies
	 */
	queue_foreach(dev->services, send_client_primary_notify,
						INT_TO_PTR(cb_data->conn->id));

	/* Full search service scanning was performed */
	dev->partial_srvc_search = false;
	gatt_status = GATT_SUCCESS;

reply:
	send_client_search_complete_notify(gatt_status, cb_data->conn->id);
	free(cb_data);
}

static void discover_srvc_by_uuid_cb(uint8_t status, GSList *ranges,
								void *user_data)
{
	struct discover_srvc_data *cb_data = user_data;
	struct gatt_primary prim;
	struct service *s;
	int32_t gatt_status;
	struct gatt_device *dev = cb_data->conn->device;
	uint8_t instance_id = queue_length(dev->services);

	DBG("Status %d", status);

	if (status) {
		error("gatt: Discover pri srvc filtered by uuid failed: %s",
							att_ecode2str(status));
		gatt_status = GATT_FAILURE;
		goto reply;
	}

	if (!ranges) {
		info("gatt: No primary services searched by uuid found");
		gatt_status = GATT_SUCCESS;
		goto reply;
	}

	bt_uuid_to_string(&cb_data->uuid, prim.uuid, sizeof(prim.uuid));
	/*
	 * If multiple instances of the same service (as identified by UUID)
	 * exist, the first instance of the service is returned.
	 */
	memcpy(&prim.range, ranges->data, sizeof(prim.range));

	s = create_service(instance_id++, true, prim.uuid, &prim);
	if (!s) {
		gatt_status = GATT_FAILURE;
		goto reply;
	}

	if (!queue_push_tail(dev->services, s)) {
		error("gatt: Cannot push primary service to the list");
		gatt_status = GATT_FAILURE;
		goto reply;
	}

	send_client_primary_notify(s, INT_TO_PTR(cb_data->conn->id));

	DBG("attr handle = 0x%04x, end grp handle = 0x%04x uuid: %s",
		prim.range.start, prim.range.end, prim.uuid);

	/* Partial search service scanning was performed */
	dev->partial_srvc_search = true;
	gatt_status = GATT_SUCCESS;

reply:
	send_client_search_complete_notify(gatt_status, cb_data->conn->id);
	free(cb_data);
}

static guint search_dev_for_srvc(struct app_connection *conn, bt_uuid_t *uuid)
{
	struct discover_srvc_data *cb_data =
					new0(struct discover_srvc_data, 1);

	if (!cb_data) {
		error("gatt: Cannot allocate cb data");
		return 0;
	}

	cb_data->conn = conn;

	if (uuid) {
		memcpy(&cb_data->uuid, uuid, sizeof(cb_data->uuid));
		return gatt_discover_primary(conn->device->attrib, uuid,
					discover_srvc_by_uuid_cb, cb_data);
	}

	return gatt_discover_primary(conn->device->attrib, NULL,
						discover_srvc_all_cb, cb_data);
}

static void handle_client_search_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_search_service *cmd = buf;
	struct app_connection *conn;
	uint8_t status;
	struct service *s;
	bt_uuid_t uuid;
	guint srvc_search_success;

	DBG("");

	if (len != sizeof(*cmd) + (cmd->filtered ? 16 : 0)) {
		error("Invalid search service size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	conn = find_connection_by_id(cmd->conn_id);
	if (!conn) {
		error("gatt: dev with conn_id=%d not found", cmd->conn_id);

		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (conn->device->state != DEVICE_CONNECTED) {
		char bda[18];

		ba2str(&conn->device->bdaddr, bda);
		error("gatt: device %s not connected", bda);

		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (cmd->filtered)
		android2uuid(cmd->filter_uuid, &uuid);

	/* Services not cached yet */
	if (queue_isempty(conn->device->services)) {
		if (cmd->filtered)
			srvc_search_success = search_dev_for_srvc(conn, &uuid);
		else
			srvc_search_success = search_dev_for_srvc(conn, NULL);

		if (!srvc_search_success) {
			status = HAL_STATUS_FAILED;
			goto reply;
		}

		status = HAL_STATUS_SUCCESS;
		goto reply;
	}

	/* Search in cached services for given service */
	if (cmd->filtered) {
		/* Search in cache for service by uuid */
		s = queue_find(conn->device->services, match_srvc_by_bt_uuid,
									&uuid);

		if (s) {
			send_client_primary_notify(s, INT_TO_PTR(conn->id));
		} else {
			if (!search_dev_for_srvc(conn, &uuid))
				status = HAL_STATUS_FAILED;

			status = HAL_STATUS_SUCCESS;
			goto reply;
		}
	} else {
		/* Refresh service cache if only partial search was performed */
		if (conn->device->partial_srvc_search)
			srvc_search_success = search_dev_for_srvc(conn, NULL);
		else
			queue_foreach(conn->device->services,
						send_client_primary_notify,
						INT_TO_PTR(cmd->conn_id));
	}

	send_client_search_complete_notify(GATT_SUCCESS, conn->id);

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_SEARCH_SERVICE, status);
}

static void send_client_incl_service_notify(const struct element_id *srvc_id,
						const struct service *incl,
						int32_t conn_id)
{
	struct hal_ev_gatt_client_get_inc_service ev;

	memset(&ev, 0, sizeof(ev));

	ev.conn_id = conn_id;

	element_id_to_hal_srvc_id(srvc_id, 1, &ev.srvc_id);

	if (incl) {
		element_id_to_hal_srvc_id(&incl->id, 0, &ev.incl_srvc_id);
		ev.status = GATT_SUCCESS;
	} else {
		ev.status = GATT_FAILURE;
	}

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT ,
					HAL_EV_GATT_CLIENT_GET_INC_SERVICE,
					sizeof(ev), &ev);
}

struct get_included_data {
	struct service *prim;
	struct app_connection *conn;
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
	struct app_connection *conn = data->conn;
	struct service *service = data->prim;
	struct service *incl = NULL;
	int instance_id;

	DBG("");

	free(data);

	if (status) {
		error("gatt: no included services found");
		return;
	}

	/* Remember that we already search included services.*/
	service->incl_search_done = true;

	/*
	 * There might be multiply services with same uuid. Therefore make sure
	 * each service has unique instance id. Let's take the latest instance
	 * id of primary service and start iterate included services from this
	 * point.
	 */
	instance_id = get_inst_id_of_prim_services(conn->device);
	if (instance_id < 0)
		goto failed;

	for (; included; included = included->next) {
		struct gatt_included *included_service = included->data;

		incl = create_service(++instance_id, false,
							included_service->uuid,
							included_service);
		if (!incl)
			continue;

		/*
		 * Lets keep included service on two queues.
		 * 1. on services queue together with primary service
		 * 2. on special queue inside primary service
		 */
		if (!queue_push_tail(service->included, incl) ||
			!queue_push_tail(conn->device->services, incl)) {
			error("gatt: Cannot push incl service to the list");
			destroy_service(incl);
			continue;
		}
	}

	/*
	 * Notify upper layer about first included service.
	 * Android framework will iterate for next one.
	 */
	incl = queue_peek_head(service->included);

failed:
	send_client_incl_service_notify(&service->id, incl, conn->id);
}

static bool search_included_services(struct app_connection *connection,
							struct service *service)
{
	struct get_included_data *data;

	data = new0(struct get_included_data, 1);
	if (!data) {
		error("gatt: failed to allocate memory for included_data");
		return false;
	}

	data->prim = service;
	data->conn = connection;

	gatt_find_included(connection->device->attrib,
				service->prim.range.start,
				service->prim.range.end, get_included_cb, data);
	return true;
}

static bool find_service(int32_t conn_id, struct element_id *service_id,
					struct app_connection **connection,
					struct service **service)
{
	struct service *srvc;
	struct app_connection *conn;

	conn = find_connection_by_id(conn_id);
	if (!conn) {
		error("gatt: conn_id=%d not found", conn_id);
		return false;
	}

	srvc = queue_find(conn->device->services, match_srvc_by_element_id,
								service_id);
	if (!srvc) {
		error("gatt: Service with inst_id: %d not found",
							service_id->instance);
		return false;
	}

	*connection = conn;
	*service = srvc;

	return true;
}

static void handle_client_get_included_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_included_service *cmd = buf;
	struct app_connection *conn;
	struct service *prim_service;
	struct service *incl_service = NULL;
	struct element_id match_id;
	struct element_id srvc_id;
	uint8_t status;

	DBG("");

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);

	if (len != sizeof(*cmd) +
			(cmd->continuation ? sizeof(cmd->incl_srvc_id[0]) : 0)) {
		error("Invalid get incl services size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id, &match_id);
	if (!find_service(cmd->conn_id, &match_id, &conn, &prim_service)) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (!prim_service->incl_search_done) {
		if (search_included_services(conn, prim_service))
			status = HAL_STATUS_SUCCESS;
		else
			status = HAL_STATUS_FAILED;

		ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
				status);
		return;
	}

	/* Try to use cache here */
	if (!cmd->continuation) {
		incl_service = queue_peek_head(prim_service->included);
	} else {
		uint8_t inst_id = cmd->incl_srvc_id[0].inst_id;
		incl_service = queue_find(prim_service->included,
						match_srvc_by_higher_inst_id,
						INT_TO_PTR(inst_id));
	}

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE, status);

	/*
	 * In case of error in handling request we need to send event with
	 * service id of cmd and gatt failure status.
	 */
	send_client_incl_service_notify(&srvc_id, incl_service, cmd->conn_id);
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

static void cache_all_srvc_chars(struct service *srvc, GSList *characteristics)
{
	uint16_t inst_id = 0;
	bt_uuid_t uuid;

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

		/*
		 * For now we increment inst_id and use it as characteristic
		 * handle
		 */
		ch->id.instance = ++inst_id;

		/* Store end handle to use later for descriptors discovery */
		if (characteristics->next) {
			struct gatt_char *next = characteristics->next->data;
			ch->end_handle = next->handle - 1;
		} else {
			ch->end_handle = srvc->primary ? srvc->prim.range.end :
							srvc->incl.range.end;
		}

		if (!queue_push_tail(srvc->chars, ch)) {
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
	struct service *srvc = data->service;

	if (queue_isempty(srvc->chars))
		cache_all_srvc_chars(srvc, characteristics);

	send_client_char_notify(queue_peek_head(srvc->chars), data->conn_id,
									srvc);

	free(data);
}

static void handle_client_get_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_characteristic *cmd = buf;
	struct characteristic *ch;
	struct element_id match_id;
	struct app_connection *conn;
	struct service *srvc;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) + (cmd->continuation ? sizeof(cmd->char_id[0]) : 0)) {
		error("Invalid get characteristic size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id, &match_id);
	if (!find_service(cmd->conn_id, &match_id, &conn, &srvc)) {
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
		cb_data->conn_id = conn->id;

		range = srvc->primary ? srvc->prim.range : srvc->incl.range;

		if (!gatt_discover_char(conn->device->attrib, range.start,
						range.end, NULL,
						discover_char_cb, cb_data)) {
			free(cb_data);

			status = HAL_STATUS_FAILED;
			goto done;
		}

		status = HAL_STATUS_SUCCESS;
		goto done;
	}

	if (cmd->continuation)
		ch = queue_find(srvc->chars, match_char_by_higher_inst_id,
					INT_TO_PTR(cmd->char_id[0].inst_id));
	else
		ch = queue_peek_head(srvc->chars);

	send_client_char_notify(ch, conn->id, srvc);

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

struct discover_desc_data {
	struct app_connection *conn;
	struct service *srvc;
	struct characteristic *ch;
};

static void gatt_discover_desc_cb(guint8 status, GSList *descs,
							gpointer user_data)
{
	struct discover_desc_data *data = user_data;
	struct app_connection *conn = data->conn;
	struct service *srvc = data->srvc;
	struct characteristic *ch = data->ch;
	struct descriptor *descr;
	int i = 0;

	if (status != 0) {
		error("Discover all characteristic descriptors failed [%s]: %s",
					ch->ch.uuid, att_ecode2str(status));
		goto reply;
	}

	for ( ; descs; descs = descs->next) {
		struct gatt_desc *desc = descs->data;
		bt_uuid_t uuid;

		descr = new0(struct descriptor, 1);
		if (!descr)
			continue;

		bt_string_to_uuid(&uuid, desc->uuid);
		bt_uuid_to_uuid128(&uuid, &descr->id.uuid);

		descr->id.instance = i++;
		descr->handle = desc->handle;

		if (!queue_push_tail(ch->descriptors, descr))
			free(descr);
	}

reply:
	descr = queue_peek_head(ch->descriptors);

	send_client_descr_notify(status, conn->id, srvc->primary, &srvc->id,
						&ch->id,
						descr ? &descr->id : NULL);

	free(data);
}

static bool build_descr_cache(struct app_connection *connection,
					struct service *srvc,
					struct characteristic *ch)
{
	struct discover_desc_data *cb_data;
	uint16_t start, end;

	/* Clip range to given characteristic */
	start = ch->ch.value_handle + 1;
	end = ch->end_handle;

	/* If there are no descriptors, notify with fail status. */
	if (start > end)
		return false;

	cb_data = new0(struct discover_desc_data, 1);
	if (!cb_data)
		return false;

	cb_data->conn = connection;
	cb_data->srvc = srvc;
	cb_data->ch = ch;

	if (!gatt_discover_desc(connection->device->attrib, start, end, NULL,
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
	struct app_connection *conn;
	int32_t conn_id;
	uint8_t primary;
	uint8_t status;

	DBG("");

	if (len != sizeof(*cmd) +
			(cmd->continuation ? sizeof(cmd->descr_id[0]) : 0)) {
		error("gatt: Invalid get descr command (%u bytes), terminating",
									len);

		raise(SIGTERM);
		return;
	}

	conn_id = cmd->conn_id;
	primary = cmd->srvc_id.is_primary;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);

	if (!find_service(conn_id, &srvc_id, &conn, &srvc)) {
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
		if (build_descr_cache(conn, srvc, ch)) {
			ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_DESCRIPTOR,
					HAL_STATUS_SUCCESS);
			return;
		}
	}

	status = HAL_STATUS_SUCCESS;

	/* Send from cache */
	if (cmd->continuation)
		descr = queue_find(ch->descriptors,
					match_descr_by_higher_inst_id,
					INT_TO_PTR(cmd->descr_id[0].inst_id));
	else
		descr = queue_peek_head(ch->descriptors);

failed:
	send_client_descr_notify(descr ? GATT_SUCCESS : GATT_FAILURE, conn_id,
						primary, &srvc_id, &char_id,
						&descr->id);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_GET_DESCRIPTOR, status);
}

struct char_op_data {
	int32_t conn_id;
	const struct element_id *srvc_id;
	const struct element_id *char_id;
	uint8_t primary;
};

static struct char_op_data *create_char_op_data(int32_t conn_id,
						const struct element_id *s_id,
						const struct element_id *ch_id,
						bool primary)
{
	struct char_op_data *d;

	d = new0(struct char_op_data, 1);
	if (!d)
		return NULL;

	d->conn_id = conn_id;
	d->srvc_id = s_id;
	d->char_id = ch_id;
	d->primary = primary;

	return d;
}

static void send_client_read_char_notify(int32_t status, const uint8_t *pdu,
						uint16_t len, int32_t conn_id,
						const struct element_id *s_id,
						const struct element_id *ch_id,
						uint8_t primary)
{
	uint8_t buf[IPC_MTU];
	struct hal_ev_gatt_client_read_characteristic *ev = (void *) buf;
	ssize_t vlen;

	memset(buf, 0, sizeof(buf));

	ev->conn_id = conn_id;
	ev->status = status;

	element_id_to_hal_srvc_id(s_id, primary, &ev->data.srvc_id);
	element_id_to_hal_gatt_id(ch_id, &ev->data.char_id);

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
	struct char_op_data *data = user_data;

	send_client_read_char_notify(status, pdu, len, data->conn_id,
						data->srvc_id, data->char_id,
						data->primary);

	free(data);
}

static void handle_client_read_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_characteristic *cmd = buf;
	struct char_op_data *cb_data;
	struct characteristic *ch;
	struct app_connection *conn;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t status;

	DBG("");

	/* TODO authorization needs to be handled */

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);

	if (!find_service(cmd->conn_id, &srvc_id, &conn, &srvc)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* search characteristics by element id */
	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Characteristic with inst_id: %d not found",
							cmd->char_id.inst_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	cb_data = create_char_op_data(cmd->conn_id, &srvc->id, &ch->id,
						cmd->srvc_id.is_primary);
	if (!cb_data) {
		error("gatt: Cannot allocate cb data");
		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	if (!gatt_read_char(conn->device->attrib, ch->ch.value_handle,
						read_char_cb, cb_data)) {
		error("gatt: Cannot read characteristic with inst_id: %d",
							cmd->char_id.inst_id);
		status = HAL_STATUS_FAILED;
		free(cb_data);
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_READ_CHARACTERISTIC, status);

	/*
	 * We should send notification with service, characteristic id in case
	 * of errors.
	 */
	if (status != HAL_STATUS_SUCCESS)
		send_client_read_char_notify(GATT_FAILURE, NULL, 0,
					cmd->conn_id, &srvc_id, &char_id,
					cmd->srvc_id.is_primary);
}

static void send_client_write_char_notify(int32_t status, int32_t conn_id,
					const struct element_id *srvc_id,
					const struct element_id *char_id,
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
	struct char_op_data *data = user_data;

	send_client_write_char_notify(status, data->conn_id, data->srvc_id,
						data->char_id, data->primary);

	free(data);
}

static void handle_client_write_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_write_characteristic *cmd = buf;
	struct char_op_data *cb_data = NULL;
	struct characteristic *ch;
	struct app_connection *conn;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	uint8_t status;
	guint res;

	DBG("");

	if (len != sizeof(*cmd) + cmd->len) {
		error("Invalid write char size (%u bytes), terminating", len);
		raise(SIGTERM);
		return;
	}

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);

	if (!find_service(cmd->conn_id, &srvc_id, &conn, &srvc)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* search characteristics by instance id */
	ch = queue_find(srvc->chars, match_char_by_element_id, &char_id);
	if (!ch) {
		error("gatt: Characteristic with inst_id: %d not found",
							cmd->char_id.inst_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (cmd->write_type != GATT_WRITE_TYPE_NO_RESPONSE) {
		cb_data = create_char_op_data(cmd->conn_id, &srvc->id, &ch->id,
						cmd->srvc_id.is_primary);
		if (!cb_data) {
			error("gatt: Cannot allocate call data");
			status = HAL_STATUS_NOMEM;
			goto failed;
		}
	}

	switch (cmd->write_type) {
	case GATT_WRITE_TYPE_NO_RESPONSE:
		res = gatt_write_cmd(conn->device->attrib, ch->ch.value_handle,
							cmd->value, cmd->len,
							NULL, NULL);
		break;
	case GATT_WRITE_TYPE_PREPARE:
		res = gatt_reliable_write_char(conn->device->attrib,
							ch->ch.value_handle,
							cmd->value, cmd->len,
							write_char_cb, cb_data);
		break;
	case GATT_WRITE_TYPE_DEFAULT:
		res = gatt_write_char(conn->device->attrib, ch->ch.value_handle,
							cmd->value, cmd->len,
							write_char_cb, cb_data);
		break;
	default:
		error("gatt: Write type %d unsupported", cmd->write_type);
		status = HAL_STATUS_UNSUPPORTED;
		goto failed;
	}

	if (!res) {
		error("gatt: Cannot write char. with inst_id: %d",
							cmd->char_id.inst_id);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_WRITE_CHARACTERISTIC, status);

	/*
	 * We should send notification with service, characteristic id in case
	 * of error and write with no response
	 */
	if (status != HAL_STATUS_SUCCESS ||
			cmd->write_type == GATT_WRITE_TYPE_NO_RESPONSE) {
		int32_t gatt_status = (status == HAL_STATUS_SUCCESS) ?
						GATT_SUCCESS : GATT_FAILURE;

		send_client_write_char_notify(gatt_status, cmd->conn_id,
						&srvc_id, &char_id,
						cmd->srvc_id.is_primary);
		free(cb_data);
	}
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

static struct desc_data *create_desc_data(int32_t conn_id,
						const struct element_id *s_id,
						const struct element_id *ch_id,
						const struct element_id *d_id,
						uint8_t primary)
{
	struct desc_data *d;

	d = new0(struct desc_data, 1);
	if (!d)
		return NULL;

	d->conn_id = conn_id;
	d->srvc_id = s_id;
	d->char_id = ch_id;
	d->descr_id = d_id;
	d->primary = primary;

	return d;
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
	struct app_connection *conn;
	int32_t conn_id = 0;
	uint8_t primary;
	uint8_t status;

	DBG("");

	conn_id = cmd->conn_id;
	primary = cmd->srvc_id.is_primary;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &srvc_id);
	hal_gatt_id_to_element_id(&cmd->char_id, &char_id);
	hal_gatt_id_to_element_id(&cmd->descr_id, &descr_id);

	if (!find_service(conn_id, &srvc_id, &conn, &srvc)) {
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

	cb_data = create_desc_data(conn_id, &srvc->id, &ch->id, &descr->id,
								primary);
	if (!cb_data) {
		error("gatt: Read descr. could not allocate callback data");

		status = HAL_STATUS_NOMEM;
		goto failed;
	}

	if (!gatt_read_char(conn->device->attrib, descr->handle, read_desc_cb,
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
	struct desc_data *cb_data = NULL;
	struct characteristic *ch;
	struct descriptor *descr;
	struct service *srvc;
	struct element_id srvc_id;
	struct element_id char_id;
	struct element_id descr_id;
	struct app_connection *conn;
	int32_t conn_id;
	uint8_t primary;
	uint8_t status;
	guint res;

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

	if (!find_service(cmd->conn_id, &srvc_id, &conn, &srvc)) {
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

	if (cmd->write_type != GATT_WRITE_TYPE_NO_RESPONSE) {
		cb_data = create_desc_data(conn_id, &srvc->id, &ch->id,
							&descr->id, primary);
		if (!cb_data) {
			error("gatt: Write descr. could not allocate cb_data");

			status = HAL_STATUS_NOMEM;
			goto failed;
		}
	}

	switch (cmd->write_type) {
	case GATT_WRITE_TYPE_NO_RESPONSE:
		res = gatt_write_cmd(conn->device->attrib, descr->handle,
					cmd->value, cmd->len, NULL , NULL);
		break;
	case GATT_WRITE_TYPE_PREPARE:
		res = gatt_reliable_write_char(conn->device->attrib,
						descr->handle, cmd->value,
						cmd->len, write_descr_cb,
						cb_data);
		break;
	case GATT_WRITE_TYPE_DEFAULT:
		res = gatt_write_char(conn->device->attrib, descr->handle,
						cmd->value, cmd->len,
						write_descr_cb, cb_data);
		break;
	default:
		error("gatt: Write type %d unsupported", cmd->write_type);
		status = HAL_STATUS_UNSUPPORTED;
		goto failed;
	}

	if (!res) {
		error("gatt: Write desc, could not write desc");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	if (status != HAL_STATUS_SUCCESS ||
			cmd->write_type == GATT_WRITE_TYPE_NO_RESPONSE) {
		int32_t gatt_status = (status == HAL_STATUS_SUCCESS) ?
						GATT_SUCCESS : GATT_FAILURE;

		send_client_descr_write_notify(gatt_status, conn_id, &srvc_id,
						&char_id, &descr_id, primary);
		free(cb_data);
	}

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_WRITE_DESCRIPTOR, status);
}

static void send_client_write_execute_notify(int32_t id, int32_t status)
{
	struct hal_ev_gatt_client_exec_write ev;

	ev.conn_id = id;
	ev.status = status;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_CLIENT_EXEC_WRITE,
					sizeof(ev), &ev);
}

static void write_execute_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	send_client_write_execute_notify(PTR_TO_INT(user_data), status);
}

static void handle_client_execute_write(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_execute_write *cmd = buf;
	struct app_connection *conn;
	uint8_t status;
	uint8_t flags;

	DBG("");

	conn = find_connection_by_id(cmd->conn_id);
	if (!conn) {
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	flags = cmd->execute ? ATT_WRITE_ALL_PREP_WRITES :
						ATT_CANCEL_ALL_PREP_WRITES;

	if (!gatt_execute_write(conn->device->attrib, flags, write_execute_cb,
						INT_TO_PTR(cmd->conn_id))) {
		error("gatt: Could not send execute write");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	status = HAL_STATUS_SUCCESS;
reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_EXECUTE_WRITE, status);

	/* In case of early error send also notification.*/
	if (status != HAL_STATUS_SUCCESS)
		send_client_write_execute_notify(cmd->conn_id, GATT_FAILURE);
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
	bdaddr2android(&notification->conn->device->bdaddr, &ev->bda);
	ev->conn_id = notification->conn->id;
	ev->is_notify = pdu[0] == ATT_OP_HANDLE_NOTIFY;

	/* We have to cut opcode and handle from data */
	ev->len = len - data_offset;
	memcpy(ev->value, pdu + data_offset, len - data_offset);

	if (!ev->is_notify) {
		uint8_t *res;
		uint16_t len;
		size_t plen;

		res = g_attrib_get_buffer(
				notification->conn->device->attrib,
				&plen);
		len = enc_confirmation(res, plen);
		if (len > 0)
			g_attrib_send(notification->conn->device->attrib,
						0, res, len, NULL, NULL, NULL);
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
	struct characteristic *c;
	struct element_id match_id;
	struct app_connection *conn;
	int32_t conn_id = 0;
	struct service *service;
	uint8_t status;
	int32_t gatt_status;
	bdaddr_t addr;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &addr);

	conn = find_conn(&addr, cmd->client_if);
	if (!conn) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	conn_id = conn->id;

	hal_srvc_id_to_element_id(&cmd->srvc_id, &match_id);
	service = queue_find(conn->device->services, match_srvc_by_element_id,
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
	notification->conn = conn;

	if (queue_find(conn->app->notifications, match_notification,
								notification)) {
		free(notification);
		status = HAL_STATUS_SUCCESS;
		goto failed;
	}

	notification->notif_id = g_attrib_register(conn->device->attrib,
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

	notification->ind_id = g_attrib_register(conn->device->attrib,
							ATT_OP_HANDLE_IND,
							c->ch.value_handle,
							handle_notification,
							notification,
							destroy_notification);
	if (!notification->ind_id) {
		g_attrib_unregister(conn->device->attrib,
							notification->notif_id);
		free(notification);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/*
	 * Because same data - notification - is shared by two handlers, we
	 * introduce ref counter to be sure that data can be freed with no risk.
	 * Counter is decremented in destroy_notification.
	 */
	notification->ref = 2;

	if (!queue_push_tail(conn->app->notifications, notification)) {
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
			HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION, status);
}

static void handle_client_deregister_for_notification(const void *buf,
								uint16_t len)
{
	const struct hal_cmd_gatt_client_deregister_for_notification *cmd = buf;
	struct notification_data *notification, notif;
	struct app_connection *conn;
	int32_t conn_id = 0;
	uint8_t status;
	int32_t gatt_status;
	bdaddr_t addr;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &addr);

	conn = find_conn(&addr, cmd->client_if);
	if (!conn) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	conn_id = conn->id;

	memcpy(&notif.ch, &cmd->char_id, sizeof(notif.ch));
	memcpy(&notif.service, &cmd->srvc_id, sizeof(notif.service));
	notif.conn = conn;

	notification = queue_find(conn->app->notifications,
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
			HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION, status);
}

static void send_client_remote_rssi_notify(int32_t client_if,
						const bdaddr_t *addr,
						int32_t rssi, int32_t status)
{
	struct hal_ev_gatt_client_read_remote_rssi ev;

	ev.client_if = client_if;
	bdaddr2android(addr, &ev.address);
	ev.rssi = rssi;
	ev.status = status;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_CLIENT_READ_REMOTE_RSSI, sizeof(ev), &ev);
}

static void read_remote_rssi_cb(uint8_t status, const bdaddr_t *addr,
						int8_t rssi, void *user_data)
{
	int32_t client_if = PTR_TO_INT(user_data);
	int32_t gatt_status = status ? GATT_FAILURE : GATT_SUCCESS;

	send_client_remote_rssi_notify(client_if, addr, rssi, gatt_status);
}

static void handle_client_read_remote_rssi(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_remote_rssi *cmd = buf;
	uint8_t status;
	bdaddr_t bdaddr;

	DBG("");

	if (!find_app_by_id(cmd->client_if)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2bdaddr(cmd->bdaddr, &bdaddr);
	if (!bt_read_device_rssi(&bdaddr, read_remote_rssi_cb,
						INT_TO_PTR(cmd->client_if))) {
		error("gatt: Could not read RSSI");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_CLIENT_READ_REMOTE_RSSI, status);

	if (status != HAL_STATUS_SUCCESS)
		send_client_remote_rssi_notify(cmd->client_if, &bdaddr, 0,
								GATT_FAILURE);
}

static void handle_client_get_device_type(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_get_device_type *cmd = buf;
	struct hal_rsp_gatt_client_get_device_type rsp;
	bdaddr_t bdaddr;

	DBG("");

	android2bdaddr(cmd->bdaddr, &bdaddr);

	rsp.type = bt_get_device_android_type(&bdaddr);

	ipc_send_rsp_full(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_DEVICE_TYPE,
					sizeof(rsp), &rsp, -1);
}

static void handle_client_set_adv_data(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_set_adv_data *cmd = buf;
	uint8_t status;

	if (len != sizeof(*cmd) + cmd->manufacturer_len) {
		error("Invalid set adv data command (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	DBG("scan_rsp=%u name=%u tx=%u min=%d max=%d app=%d manufacturer=%u",
		cmd->set_scan_rsp, cmd->include_name, cmd->include_txpower,
		cmd->min_interval, cmd->max_interval, cmd->appearance,
		cmd->manufacturer_len);

	/*
	 * TODO
	 * Currently kernel is setting all except for vendor data.
	 * This should be implemented when kernel supports it.
	 */

	if (cmd->manufacturer_len) {
		error("gatt: Manufacturer advertising data not supported");
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_CLIENT_SET_ADV_DATA, status);
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

	DBG("");

	memset(&ev, 0, sizeof(ev));

	ev.server_if = register_app(cmd->uuid, APP_SERVER);

	if (ev.server_if)
		ev.status = GATT_SUCCESS;
	else
		ev.status = GATT_FAILURE;

	memcpy(ev.uuid, cmd->uuid, sizeof(ev.uuid));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_SERVER_REGISTER, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_REGISTER,
							HAL_STATUS_SUCCESS);
}

static void handle_server_unregister(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_unregister *cmd = buf;
	uint8_t status;
	struct gatt_app *server;

	DBG("");

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		error("gatt: server_if=%d not found", cmd->server_if);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	destroy_gatt_app(server);
	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_UNREGISTER, status);
}

static void handle_server_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_connect *cmd = buf;
	uint8_t status;
	bdaddr_t addr;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &addr);

	status = handle_connect(cmd->server_if, &addr);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT, HAL_OP_GATT_SERVER_CONNECT,
								status);
}

static void handle_server_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_disconnect *cmd = buf;
	struct app_connection *conn;
	uint8_t status;

	DBG("");

	/* TODO: should we care to match also bdaddr when conn_id is unique? */
	conn = find_connection_by_id(cmd->conn_id);
	if (conn)
		trigger_disconnection(conn);

	status = HAL_STATUS_SUCCESS;

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_DISCONNECT, status);
}

static void handle_server_add_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_add_service *cmd = buf;
	struct hal_ev_gatt_server_service_added ev;
	struct gatt_app *server;
	uint8_t status;
	bt_uuid_t uuid;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2uuid(cmd->srvc_id.uuid, &uuid);

	ev.srvc_handle = gatt_db_add_service(gatt_db, &uuid,
							cmd->srvc_id.is_primary,
							cmd->num_handles);
	if (!ev.srvc_handle) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;
	ev.srvc_id = cmd->srvc_id;
	ev.server_if = cmd->server_if;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_SERVICE_ADDED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_SERVER_ADD_SERVICE, status);
}

static void handle_server_add_included_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_add_inc_service *cmd = buf;
	struct hal_ev_gatt_server_inc_srvc_added ev;
	struct gatt_app *server;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	ev.incl_srvc_handle = gatt_db_add_included_service(gatt_db,
							cmd->service_handle,
							cmd->included_handle);
	if (!ev.incl_srvc_handle) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;
failed:
	ev.srvc_handle = cmd->service_handle;
	ev.status = status;
	ev.server_if = cmd->server_if;
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_INC_SRVC_ADDED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_ADD_INC_SERVICE, status);
}

static bool is_service(const bt_uuid_t *type)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	if (!bt_uuid_cmp(&uuid, type))
		return true;

	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	if (!bt_uuid_cmp(&uuid, type))
		return true;

	return false;
}

static void send_dev_pending_response(struct gatt_device *device,
								uint8_t opcode)
{
	uint8_t rsp[ATT_DEFAULT_LE_MTU];
	struct pending_request *val;
	uint16_t len = 0;
	uint8_t error = 0;

	switch (opcode) {
	case ATT_OP_READ_BY_TYPE_REQ: {
		struct att_data_list *adl;
		int iterator = 0;
		int length;
		struct queue *temp;


		temp = queue_new();
		if (!temp)
			goto done;

		val = queue_pop_head(device->pending_requests);
		if (!val) {
			queue_destroy(temp, NULL);
			error = ATT_ECODE_ATTR_NOT_FOUND;
			goto done;
		}

		length = val->length;

		while (val && val->length == length) {
			queue_push_tail(temp, val);
			val = queue_pop_head(device->pending_requests);
		}

		adl = att_data_list_alloc(queue_length(temp), sizeof(uint16_t) +
									length);

		val = queue_pop_head(temp);
		while (val) {
			uint8_t *value = adl->data[iterator++];

			put_le16(val->handle, value);
			memcpy(&value[2], val->value, val->length);

			destroy_pending_request(val);
			val = queue_pop_head(temp);
		}

		len = enc_read_by_type_resp(adl, rsp, sizeof(rsp));

		att_data_list_free(adl);
		queue_destroy(temp, destroy_pending_request);

		break;
	}
	case ATT_OP_READ_BLOB_REQ:
		val = queue_pop_head(device->pending_requests);
		if (!val || val->length < 0) {
			error = ATT_ECODE_ATTR_NOT_FOUND;
			goto done;
		}

		len = enc_read_blob_resp(val->value, val->length, val->offset,
							rsp, sizeof(rsp));
		destroy_pending_request(val);
		break;
	case ATT_OP_READ_REQ:
		val = queue_pop_head(device->pending_requests);
		if (!val || val->length < 0) {
			error = ATT_ECODE_ATTR_NOT_FOUND;
			goto done;
		}

		len = enc_read_resp(val->value, val->length, rsp, sizeof(rsp));
		destroy_pending_request(val);
		break;
	case ATT_OP_READ_BY_GROUP_REQ: {
		struct att_data_list *adl;
		int iterator = 0;
		int length;
		struct queue *temp;

		temp = queue_new();
		if (!temp)
			goto done;

		val = queue_pop_head(device->pending_requests);
		if (!val) {
			queue_destroy(temp, NULL);
			error = ATT_ECODE_ATTR_NOT_FOUND;
			goto done;
		}

		length = val->length;

		while (val && val->length == length) {
			queue_push_tail(temp, val);
			val = queue_pop_head(device->pending_requests);
		}

		adl = att_data_list_alloc(queue_length(temp),
						2 * sizeof(uint16_t) + length);

		val = queue_pop_head(temp);
		while (val) {
			uint8_t *value = adl->data[iterator++];
			uint16_t end_handle;

			end_handle = gatt_db_get_end_handle(gatt_db,
								val->handle);

			put_le16(val->handle, value);
			put_le16(end_handle, &value[2]);
			memcpy(&value[4], val->value, val->length);

			destroy_pending_request(val);
			val = queue_pop_head(temp);
		}

		len = enc_read_by_grp_resp(adl, rsp, sizeof(rsp));

		att_data_list_free(adl);
		queue_destroy(temp, destroy_pending_request);

		break;
	}
	case ATT_OP_FIND_BY_TYPE_REQ: {
		GSList *list = NULL;

		val = queue_pop_head(device->pending_requests);
		while (val) {
			struct att_range *range;
			const bt_uuid_t *type;

			/* Its find by type and value - filter by value here */
			if ((val->length != val->filter_vlen) ||
				memcmp(val->value, val->filter_value,
								val->length)) {

				destroy_pending_request(val);
				val = queue_pop_head(device->pending_requests);
				continue;
			}

			range = new0(struct att_range, 1);
			if (!range) {
				destroy_pending_request(val);
				error = ATT_ECODE_INSUFF_RESOURCES;
				break;
			}

			range->start = val->handle;
			range->end = range->start;

			/* Get proper end handle if its group type */
			type = gatt_db_get_attribute_type(gatt_db, val->handle);
			if (is_service(type))
				range->end = gatt_db_get_end_handle(gatt_db,
								val->handle);

			list = g_slist_append(list, range);

			destroy_pending_request(val);
			val = queue_pop_head(device->pending_requests);
		}

		if (list && !error)
			len = enc_find_by_type_resp(list, rsp, sizeof(rsp));
		else
			error = ATT_ECODE_ATTR_NOT_FOUND;

		g_slist_free_full(list, free);

		break;
	}
	case ATT_OP_EXEC_WRITE_REQ:
		val = queue_pop_head(device->pending_requests);
		if (!val) {
			error = ATT_ECODE_ATTR_NOT_FOUND;
			break;
		}

		len = enc_exec_write_resp(rsp);
		destroy_pending_request(val);
		break;
	case ATT_OP_WRITE_REQ:
		val = queue_pop_head(device->pending_requests);
		if (!val) {
			error = ATT_ECODE_ATTR_NOT_FOUND;
			break;
		}

		len = enc_write_resp(rsp);
		destroy_pending_request(val);
		break;
	case ATT_OP_PREP_WRITE_REQ:
		val = queue_pop_head(device->pending_requests);
		if (!val) {
			error = ATT_ECODE_ATTR_NOT_FOUND;
			break;
		}

		len = enc_prep_write_resp(val->handle, val->offset, val->value,
						val->length, rsp, sizeof(rsp));
		destroy_pending_request(val);
		break;
	default:
		break;
	}

done:
	if (!len)
		len = enc_error_resp(opcode, 0x0000, error, rsp,
							ATT_DEFAULT_LE_MTU);

	g_attrib_send(device->attrib, 0, rsp, len, NULL, NULL, NULL);

	queue_remove_all(device->pending_requests, NULL, NULL,
						destroy_pending_request);
}

struct request_processing_data {
	uint8_t opcode;
	struct gatt_device *device;
};

static bool match_pending_dev_request(const void *data, const void *user_data)
{
	const struct pending_request *pending_request = data;

	return pending_request->length == READ_PENDING;
}

static bool match_dev_request_by_handle(const void *data, const void *user_data)
{
	const struct pending_request *handle_data = data;
	uint16_t handle = PTR_TO_UINT(user_data);

	return handle_data->handle == handle;
}

static void read_requested_attributes(void *data, void *user_data)
{
	struct pending_request *resp_data = data;
	struct request_processing_data *process_data = user_data;
	uint8_t *value;
	int value_len;

	if (!gatt_db_read(gatt_db, resp_data->handle,
						resp_data->offset,
						process_data->opcode,
						&process_data->device->bdaddr,
						&value, &value_len)) {
		resp_data->length = READ_FAILED;
		return;
	}

	/* We have value here already if no callback will be called */
	if (value_len >= 0) {
		resp_data->value = malloc0(value_len);
		if (!resp_data->value) {
			/* If data cannot be copied, act like when read fails */
			resp_data->length = READ_FAILED;
			return;
		}

		memcpy(resp_data->value, value, value_len);
		resp_data->length = value_len;
	} else if (resp_data->length == READ_INIT) {
		resp_data->length = READ_PENDING;
	}
}

static void process_dev_pending_requests(struct gatt_device *device,
							uint8_t att_opcode)
{
	struct request_processing_data process_data;

	process_data.device = device;
	process_data.opcode = att_opcode;

	/* Process pending requests and prepare response */
	queue_foreach(device->pending_requests, read_requested_attributes,
								&process_data);

	if (!queue_find(device->pending_requests,
					match_pending_dev_request, NULL))
		send_dev_pending_response(device, att_opcode);
}

static void send_gatt_response(uint8_t opcode, uint16_t handle,
					uint16_t offset, uint8_t status,
					uint16_t len, const uint8_t *data,
					bdaddr_t *bdaddr)
{
	struct gatt_device *dev;
	struct pending_request *entry;

	dev = find_device_by_addr(bdaddr);
	if (!dev) {
		error("gatt: send_gatt_response, could not find dev");
		goto done;
	}

	if (status)
		goto done;

	entry = queue_find(dev->pending_requests, match_dev_request_by_handle,
							UINT_TO_PTR(handle));
	if (!entry) {
		DBG("No pending response found! Bogus android response?");
		return;
	}

	entry->handle = handle;
	entry->offset = offset;
	entry->length = len;

	if (!len)
		goto done;

	entry->value = malloc0(len);
	if (!entry->value) {
		/* send_dev_pending_request on empty queue sends error resp. */
		queue_remove(dev->pending_requests, entry);
		destroy_pending_request(entry);

		goto done;
	}

	memcpy(entry->value, data, len);

done:
	if (!queue_find(dev->pending_requests, match_pending_dev_request, NULL))
		send_dev_pending_response(dev, opcode);
}

static void set_trans_id(struct gatt_app *app, unsigned int id, int8_t opcode)
{
	app->trans_id.id = id;
	app->trans_id.opcode = opcode;
}

static void clear_trans_id(struct gatt_app *app)
{
	app->trans_id.id = 0;
	app->trans_id.opcode = 0;
}

static void read_cb(uint16_t handle, uint16_t offset, uint8_t att_opcode,
					bdaddr_t *bdaddr, void *user_data)
{
	struct hal_ev_gatt_server_request_read ev;
	struct gatt_app *app;
	struct app_connection *conn;
	int32_t id = PTR_TO_INT(user_data);
	static int32_t trans_id = 1;

	app = find_app_by_id(id);
	if (!app) {
		error("gatt: read_cb, cound not found app id");
		goto failed;
	}

	conn = find_conn(bdaddr, app->id);
	if (!conn) {
		error("gatt: read_cb, cound not found connection");
		goto failed;
	}

	memset(&ev, 0, sizeof(ev));

	/* Store the request data, complete callback and transaction id */
	set_trans_id(app, trans_id++, att_opcode);

	bdaddr2android(bdaddr, ev.bdaddr);
	ev.conn_id = conn->id;
	ev.attr_handle = handle;
	ev.offset = offset;
	ev.is_long = att_opcode == ATT_OP_READ_BLOB_REQ;
	ev.trans_id = app->trans_id.id;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_EV_GATT_SERVER_REQUEST_READ,
					sizeof(ev), &ev);

	return;

failed:
	send_gatt_response(att_opcode, handle, 0, ATT_ECODE_UNLIKELY, 0,
							NULL, bdaddr);
}

static void write_cb(uint16_t handle, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t att_opcode, bdaddr_t *bdaddr,
					void *user_data)
{
	struct hal_ev_gatt_server_request_write ev;
	struct gatt_app *app;
	int32_t id = PTR_TO_INT(user_data);
	static int32_t trans_id = 1;
	struct app_connection *conn;

	app = find_app_by_id(id);
	if (!app) {
		error("gatt: write_cb could not found app id");
		goto failed;
	}

	conn = find_conn(bdaddr, app->id);
	if (!conn) {
		error("gatt: write_cb could not found connection");
		goto failed;
	}

	/* Store the request data, complete callback and transaction id */
	set_trans_id(app, trans_id++, att_opcode);

	/* TODO figure it out */
	if (att_opcode == ATT_OP_EXEC_WRITE_REQ)
		goto failed;

	memset(&ev, 0, sizeof(ev));

	bdaddr2android(bdaddr, ev.bdaddr);
	ev.attr_handle = handle;
	ev.offset = offset;

	ev.conn_id = conn->id;
	ev.trans_id = app->trans_id.id;

	ev.is_prep = att_opcode == ATT_OP_PREP_WRITE_REQ;
	ev.need_rsp = att_opcode == ATT_OP_WRITE_REQ;

	ev.length = len;
	memcpy(&ev.value, value, len);

	return;

failed:
	send_gatt_response(att_opcode, handle, 0, ATT_ECODE_UNLIKELY, 0, NULL,
								bdaddr);
}

static void handle_server_add_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_add_characteristic *cmd = buf;
	struct hal_ev_gatt_server_characteristic_added ev;
	struct gatt_app *server;
	bt_uuid_t uuid;
	uint8_t status;
	int32_t app_id = cmd->server_if;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(app_id);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2uuid(cmd->uuid, &uuid);

	/*FIXME: Handle properties. Register callback if needed. */
	ev.char_handle = gatt_db_add_characteristic(gatt_db,
							cmd->service_handle,
							&uuid, cmd->permissions,
							cmd->properties,
							read_cb, write_cb,
							INT_TO_PTR(app_id));
	if (!ev.char_handle)
		status = HAL_STATUS_FAILED;
	else
		status = HAL_STATUS_SUCCESS;

failed:
	ev.srvc_handle = cmd->service_handle;
	ev.status = status;
	ev.server_if = app_id;
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;
	memcpy(ev.uuid, cmd->uuid, sizeof(cmd->uuid));

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_EV_GATT_SERVER_CHAR_ADDED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_ADD_CHARACTERISTIC, status);
}

static void handle_server_add_descriptor(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_add_descriptor *cmd = buf;
	struct hal_ev_gatt_server_descriptor_added ev;
	struct gatt_app *server;
	bt_uuid_t uuid;
	uint8_t status;
	int32_t app_id = cmd->server_if;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(app_id);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2uuid(cmd->uuid, &uuid);

	/*FIXME: Handle properties. Register callback if needed. */
	ev.descr_handle = gatt_db_add_char_descriptor(gatt_db,
							cmd->service_handle,
							&uuid, cmd->permissions,
							read_cb, write_cb,
							INT_TO_PTR(app_id));
	if (!ev.descr_handle)
		status = HAL_STATUS_FAILED;
	else
		status = HAL_STATUS_SUCCESS;

failed:
	ev.server_if = app_id;
	ev.srvc_handle = cmd->service_handle;
	memcpy(ev.uuid, cmd->uuid, sizeof(cmd->uuid));
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_DESCRIPTOR_ADDED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_ADD_DESCRIPTOR, status);
}

static void handle_server_start_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_start_service *cmd = buf;
	struct hal_ev_gatt_server_service_started ev;
	struct gatt_app *server;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	/* TODO: support BR/EDR (cmd->transport) */

	if (!gatt_db_service_set_active(gatt_db, cmd->service_handle, true)) {
		/* we ignore service now */
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;
	ev.server_if = cmd->server_if;
	ev.srvc_handle = cmd->service_handle;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_SERVICE_STARTED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_START_SERVICE, status);
}

static void handle_server_stop_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_stop_service *cmd = buf;
	struct hal_ev_gatt_server_service_stopped ev;
	struct gatt_app *server;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (!gatt_db_service_set_active(gatt_db, cmd->service_handle, false))
		status = HAL_STATUS_FAILED;
	else
		status = HAL_STATUS_SUCCESS;

failed:
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;
	ev.server_if = cmd->server_if;
	ev.srvc_handle = cmd->service_handle;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_SERVICE_STOPPED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_STOP_SERVICE, status);
}

static void handle_server_delete_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_delete_service *cmd = buf;
	struct hal_ev_gatt_server_service_deleted ev;
	struct gatt_app *server;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	if (!gatt_db_remove_service(gatt_db, cmd->service_handle)) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	status = HAL_STATUS_SUCCESS;

failed:
	ev.status = status == HAL_STATUS_SUCCESS ? GATT_SUCCESS : GATT_FAILURE;
	ev.srvc_handle = cmd->service_handle;
	ev.server_if = cmd->server_if;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_EV_GATT_SERVER_SERVICE_DELETED, sizeof(ev), &ev);

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_DELETE_SERVICE, status);
}

static void handle_server_send_indication(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_send_indication *cmd = buf;
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	struct app_connection *conn;
	uint8_t status;
	uint16_t length;

	DBG("");

	conn = find_connection_by_id(cmd->conn_id);
	if (!conn) {
		error("gatt: Could not find connection");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (cmd->confirm)
		/* TODO: Add data to track confirmation for this request */
		length = enc_indication(cmd->attribute_handle,
					(uint8_t *)cmd->value, cmd->len,
					pdu, sizeof(pdu));
	else
		length = enc_notification(cmd->attribute_handle,
						(uint8_t *)cmd->value, cmd->len,
						pdu, sizeof(pdu));

	g_attrib_send(conn->device->attrib, 0, pdu, length, NULL, NULL, NULL);

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
				HAL_OP_GATT_SERVER_SEND_INDICATION, status);
}

static void handle_server_send_response(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_send_response *cmd = buf;
	struct app_connection *conn;
	struct gatt_app *app;
	uint8_t status;

	DBG("");

	conn = find_connection_by_id(cmd->conn_id);
	if (!conn) {
		error("gatt: could not found connection");
		status = HAL_STATUS_FAILED;
		goto reply;
	}

	app = conn->app;

	if ((unsigned int)cmd->trans_id != app->trans_id.id) {
		error("gatt: transaction ID mismatch (%d!=%d)",
					cmd->trans_id, app->trans_id.id);

		status = HAL_STATUS_FAILED;
		goto reply;
	}

	send_gatt_response(conn->app->trans_id.opcode, cmd->handle, cmd->offset,
					cmd->status, cmd->len, cmd->data,
					&conn->device->bdaddr);

	/* Clean request data */
	clear_trans_id(app);

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
			HAL_OP_GATT_SERVER_SEND_RESPONSE, status);
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

static uint8_t read_by_group_type(const uint8_t *cmd, uint16_t cmd_len,
						uint8_t *rsp, size_t rsp_size,
						uint16_t *length,
						struct gatt_device *device)
{
	uint16_t start, end;
	int len;
	bt_uuid_t uuid;
	struct queue *q;

	len = dec_read_by_grp_req(cmd, cmd_len, &start, &end, &uuid);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	q = queue_new();
	if (!q)
		return ATT_ECODE_INSUFF_RESOURCES;

	gatt_db_read_by_group_type(gatt_db, start, end, uuid, q);

	if (queue_isempty(q)) {
		queue_destroy(q, NULL);
		return ATT_ECODE_ATTR_NOT_FOUND;
	}

	while (queue_peek_head(q)) {
		uint16_t handle = PTR_TO_UINT(queue_pop_head(q));
		uint8_t *value;
		int value_len;
		struct pending_request *entry;

		entry = new0(struct pending_request, 1);
		if (!entry) {
			queue_destroy(q, destroy_pending_request);
			return ATT_ECODE_UNLIKELY;
		}

		entry->handle = handle;

		if (!gatt_db_read(gatt_db, handle, 0, ATT_OP_READ_BY_GROUP_REQ,
					&device->bdaddr, &value, &value_len))
			break;

		entry->value = malloc0(value_len);
		if (!entry->value) {
			queue_destroy(q, destroy_pending_request);
			return ATT_ECODE_UNLIKELY;
		}

		memcpy(entry->value, value, value_len);
		entry->length = value_len;

		if (!queue_push_tail(device->pending_requests, entry)) {
			queue_remove_all(device->pending_requests, NULL, NULL,
						destroy_pending_request);
			queue_destroy(q, NULL);
			return ATT_ECODE_UNLIKELY;
		}
	}

	queue_destroy(q, NULL);

	send_dev_pending_response(device, cmd[0]);

	return 0;
}

static uint8_t read_by_type(const uint8_t *cmd, uint16_t cmd_len,
						struct gatt_device *device)
{
	uint16_t start, end;
	uint16_t len;
	bt_uuid_t uuid;
	struct queue *q;

	DBG("");

	len = dec_read_by_type_req(cmd, cmd_len, &start, &end, &uuid);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	q = queue_new();
	if (!q)
		return ATT_ECODE_INSUFF_RESOURCES;

	gatt_db_read_by_type(gatt_db, start, end, uuid, q);

	if (queue_isempty(q)) {
		queue_destroy(q, NULL);
		return ATT_ECODE_ATTR_NOT_FOUND;
	}

	while (queue_peek_head(q)) {
		struct pending_request *data;
		uint16_t handle = PTR_TO_UINT(queue_pop_head(q));

		data = new0(struct pending_request, 1);
		if (!data) {
			queue_destroy(q, NULL);
			return ATT_ECODE_INSUFF_RESOURCES;
		}

		data->length = READ_INIT;
		data->handle = handle;
		queue_push_tail(device->pending_requests, data);
	}

	queue_destroy(q, NULL);

	process_dev_pending_requests(device, ATT_OP_READ_BY_TYPE_REQ);

	return 0;
}

static uint8_t read_request(const uint8_t *cmd, uint16_t cmd_len,
							struct gatt_device *dev)
{
	uint16_t handle;
	uint16_t len;
	uint16_t offset;
	struct pending_request *data;

	DBG("");

	switch (cmd[0]) {
	case ATT_OP_READ_BLOB_REQ:
		len = dec_read_blob_req(cmd, cmd_len, &handle, &offset);
		if (!len)
			return ATT_ECODE_INVALID_PDU;
		break;
	case ATT_OP_READ_REQ:
		len = dec_read_req(cmd, cmd_len, &handle);
		if (!len)
			return ATT_ECODE_INVALID_PDU;
		offset = 0;
		break;
	default:
		error("gatt: Unexpected read type 0x%02x", cmd[0]);
		return ATT_ECODE_REQ_NOT_SUPP;
	}

	data = new0(struct pending_request, 1);
	if (!data)
		return ATT_ECODE_INSUFF_RESOURCES;

	data->offset = offset;
	data->handle = handle;
	data->length = READ_INIT;
	if (!queue_push_tail(dev->pending_requests, data)) {
		free(data);
		return ATT_ECODE_INSUFF_RESOURCES;
	}

	process_dev_pending_requests(dev, cmd[0]);

	return 0;
}

static uint8_t mtu_att_handle(const uint8_t *cmd, uint16_t cmd_len,
					uint8_t *rsp, size_t rsp_size,
					struct gatt_device *dev,
					uint16_t *length)
{
	uint16_t mtu, imtu, omtu;
	GIOChannel *io;
	GError *gerr = NULL;
	uint16_t len;

	DBG("");

	len = dec_mtu_req(cmd, cmd_len, &mtu);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	if (mtu < ATT_DEFAULT_LE_MTU)
		return ATT_ECODE_REQ_NOT_SUPP;

	io = g_attrib_get_channel(dev->attrib);

	bt_io_get(io, &gerr,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_OMTU, &omtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("bt_io_get: %s", gerr->message);
		g_error_free(gerr);
		return ATT_ECODE_UNLIKELY;
	}

	/* Limit OMTU to received value */
	mtu = MIN(mtu, omtu);
	g_attrib_set_mtu(dev->attrib, mtu);

	/* Respond with our IMTU */
	len = enc_mtu_resp(imtu, rsp, rsp_size);
	if (!len)
		return ATT_ECODE_UNLIKELY;

	*length = len;

	return 0;
}

static uint8_t find_info_handle(const uint8_t *cmd, uint16_t cmd_len,
						uint8_t *rsp, size_t rsp_size,
						uint16_t *length)
{
	struct queue *q;
	struct att_data_list *adl;
	int iterator = 0;
	uint16_t start, end;
	uint16_t len;

	DBG("");

	len = dec_find_info_req(cmd, cmd_len, &start, &end);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	q = queue_new();
	if (!q)
		return ATT_ECODE_UNLIKELY;

	gatt_db_find_information(gatt_db, start, end, q);

	if (queue_isempty(q)) {
		queue_destroy(q, NULL);
		return ATT_ECODE_ATTR_NOT_FOUND;
	}

	len = queue_length(q);
	adl = att_data_list_alloc(len, 2 * sizeof(uint16_t));
	if (!adl) {
		queue_destroy(q, NULL);
		return ATT_ECODE_INSUFF_RESOURCES;
	}

	while (queue_peek_head(q)) {
		uint8_t *value;
		const bt_uuid_t *type;
		uint16_t handle = PTR_TO_UINT(queue_pop_head(q));

		type = gatt_db_get_attribute_type(gatt_db, handle);
		if (!type)
			break;

		value = adl->data[iterator++];

		put_le16(handle, value);
		memcpy(&value[2], &type->value.u16, bt_uuid_len(type));

	}

	if (!adl) {
		queue_destroy(q, NULL);
		return ATT_ECODE_INSUFF_RESOURCES;
	}

	len = enc_find_info_resp(ATT_FIND_INFO_RESP_FMT_16BIT, adl, rsp,
								rsp_size);
	if (!len)
		return ATT_ECODE_UNLIKELY;

	*length = len;
	att_data_list_free(adl);
	queue_destroy(q, free);

	return 0;
}

static uint8_t find_by_type_request(const uint8_t *cmd, uint16_t cmd_len,
						struct gatt_device *device)
{
	uint8_t search_value[ATT_DEFAULT_LE_MTU];
	size_t search_vlen;
	uint16_t start, end;
	uint16_t handle;
	struct queue *q;
	bt_uuid_t uuid;
	uint16_t len;

	DBG("");

	len = dec_find_by_type_req(cmd, cmd_len, &start, &end, &uuid,
						search_value, &search_vlen);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	q = queue_new();
	if (!q)
		return ATT_ECODE_UNLIKELY;

	gatt_db_find_by_type(gatt_db, start, end, &uuid, q);

	handle = PTR_TO_UINT(queue_pop_head(q));
	while (handle) {
		struct pending_request *data;

		data = new0(struct pending_request, 1);
		if (!data) {
			queue_destroy(q, NULL);
			return ATT_ECODE_INSUFF_RESOURCES;
		}

		data->filter_value = malloc0(search_vlen);
		if (!data) {
			destroy_pending_request(data);
			queue_destroy(q, NULL);
			return ATT_ECODE_INSUFF_RESOURCES;
		}

		data->length = READ_INIT;
		data->handle = handle;
		data->filter_vlen = search_vlen;
		memcpy(data->filter_value, search_value, search_vlen);

		queue_push_tail(device->pending_requests, data);

		handle = PTR_TO_UINT(queue_pop_head(q));
	}

	queue_destroy(q, NULL);

	process_dev_pending_requests(device, ATT_OP_FIND_BY_TYPE_REQ);

	return 0;
}

static uint8_t write_cmd_request(const uint8_t *cmd, uint16_t cmd_len,
						struct gatt_device *dev)
{
	uint8_t value[ATT_DEFAULT_LE_MTU];
	uint16_t handle;
	uint16_t len;
	size_t vlen;

	len = dec_write_cmd(cmd, cmd_len, &handle, value, &vlen);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	if (!gatt_db_write(gatt_db, handle, 0, value, vlen, cmd[0],
								&dev->bdaddr))
		return ATT_ECODE_UNLIKELY;

	return 0;
}

static uint8_t write_req_request(const uint8_t *cmd, uint16_t cmd_len,
						struct gatt_device *dev)
{
	uint8_t value[ATT_DEFAULT_LE_MTU];
	uint16_t handle;
	uint16_t len;
	size_t vlen;

	len = dec_write_req(cmd, cmd_len, &handle, value, &vlen);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	if (!gatt_db_write(gatt_db, handle, 0, value, vlen, cmd[0],
								&dev->bdaddr))
		return ATT_ECODE_UNLIKELY;

	return 0;
}

static uint8_t write_prep_request(const uint8_t *cmd, uint16_t cmd_len,
						struct gatt_device *dev)
{
	uint8_t value[ATT_DEFAULT_LE_MTU];
	uint16_t handle;
	uint16_t offset;
	uint16_t len;
	size_t vlen;

	len = dec_prep_write_req(cmd, cmd_len, &handle, &offset,
						value, &vlen);
	if (!len)
		return ATT_ECODE_INVALID_PDU;

	if (!gatt_db_write(gatt_db, handle, offset, value, vlen, cmd[0],
								&dev->bdaddr))
		return ATT_ECODE_UNLIKELY;

	return 0;
}

static void att_handler(const uint8_t *ipdu, uint16_t len, gpointer user_data)
{
	struct gatt_device *dev = user_data;
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	uint8_t status;
	uint16_t length = 0;
	size_t vlen;
	uint8_t *value = g_attrib_get_buffer(dev->attrib, &vlen);

	DBG("op 0x%02x", ipdu[0]);

	if (len > vlen) {
		error("gatt: Too much data on ATT socket %p", value);
		status = ATT_ECODE_INVALID_PDU;
		goto done;
	}

	switch (ipdu[0]) {
	case ATT_OP_READ_BY_GROUP_REQ:
		status = read_by_group_type(ipdu, len, opdu, sizeof(opdu),
								&length, dev);
		break;
	case ATT_OP_READ_BY_TYPE_REQ:
		status = read_by_type(ipdu, len, dev);
		break;
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
		status = read_request(ipdu, len, dev);
		break;
	case ATT_OP_MTU_REQ:
		status = mtu_att_handle(ipdu, len, opdu, sizeof(opdu), dev,
								&length);
		break;
	case ATT_OP_FIND_INFO_REQ:
		status = find_info_handle(ipdu, len, opdu, sizeof(opdu),
								&length);
		break;
	case ATT_OP_WRITE_REQ:
		status = write_req_request(ipdu, len, dev);
		if (!status)
			return;
		break;
	case ATT_OP_WRITE_CMD:
		status = write_cmd_request(ipdu, len, dev);
		if (!status)
			return;
		break;
	case ATT_OP_PREP_WRITE_REQ:
		status = write_prep_request(ipdu, len, dev);
		if (!status)
			return;
		break;
	case ATT_OP_FIND_BY_TYPE_REQ:
		status = find_by_type_request(ipdu, len, dev);
		break;
	case ATT_OP_EXEC_WRITE_REQ:
		/* TODO */
	case ATT_OP_HANDLE_CNF:
	case ATT_OP_HANDLE_IND:
	case ATT_OP_HANDLE_NOTIFY:
	case ATT_OP_READ_MULTI_REQ:
	default:
		DBG("Unsupported request 0x%02x", ipdu[0]);
		status = ATT_ECODE_REQ_NOT_SUPP;
		goto done;
	}

done:
	if (status)
		length = enc_error_resp(ipdu[0], 0x0000, status, opdu,
							ATT_DEFAULT_LE_MTU);

	if (length)
		g_attrib_send(dev->attrib, 0, opdu, length, NULL, NULL, NULL);
}

static void create_listen_connections(void *data, void *user_data)
{
	struct gatt_device *dev = user_data;
	int32_t id = PTR_TO_INT(data);
	struct gatt_app *app;

	app = find_app_by_id(id);
	if (app)
		create_connection(dev, app);
}

static void connect_event(GIOChannel *io, GError *gerr, void *user_data)
{
	struct gatt_device *dev;
	uint8_t dst_type;
	bdaddr_t dst;
	struct connect_data data;

	DBG("");

	if (gerr) {
		error("gatt: %s", gerr->message);
		g_error_free(gerr);
		return;
	}

	bt_io_get(io, &gerr,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST_TYPE, &dst_type,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("gatt: bt_io_get: %s", gerr->message);
		g_error_free(gerr);
		return;
	}

	/* TODO Handle collision */
	dev = find_device_by_addr(&dst);
	if (!dev) {
		dev = create_device(&dst);
		if (!dev) {
			error("gatt: Could not create device");
			return;
		}

		dev->bdaddr_type = dst_type;
	} else {
		if (dev->state != DEVICE_DISCONNECTED) {
			char addr[18];

			ba2str(&dst, addr);
			info("gatt: Rejecting incoming connection from %s",
									addr);
			return;
		}
	}

	dev->attrib = g_attrib_new(io);
	if (!dev->attrib) {
		error("gatt: unable to create new GAttrib instance");
		destroy_device(dev);
		return;
	}
	dev->watch_id = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							disconnected_cb, dev);

	queue_foreach(listen_apps, create_listen_connections, dev);

	data.dev = dev;
	data.status = GATT_SUCCESS;
	device_set_state(dev, DEVICE_CONNECTED);

	queue_foreach(app_connections, send_app_connect_notifications, &data);

	dev->server_id = g_attrib_register(dev->attrib, GATTRIB_ALL_REQS,
						GATTRIB_ALL_HANDLES,
						att_handler, dev, NULL);
	if (dev->server_id == 0)
		error("gatt: Could not attach to server");
}

struct gap_srvc_handles {
	uint16_t srvc;

	/* Characteristics */
	uint16_t dev_name;
	uint16_t appear;
	uint16_t priv;
};

static struct gap_srvc_handles gap_srvc_data;

#define APPEARANCE_GENERIC_PHONE 0x0040
#define PERIPHERAL_PRIVACY_DISABLE 0x00

static void gap_read_cb(uint16_t handle, uint16_t offset, uint8_t att_opcode,
					bdaddr_t *bdaddr, void *user_data)
{
	struct pending_request *entry;
	struct gatt_device *dev;

	DBG("");

	dev = find_device_by_addr(bdaddr);
	if (!dev) {
		error("gatt: Could not find device ?!");
		return;
	}

	entry = queue_find(dev->pending_requests, match_dev_request_by_handle,
							UINT_TO_PTR(handle));
	if (!entry)
		return;

	if (handle == gap_srvc_data.dev_name) {
		const char *name = bt_get_adapter_name();

		entry->value = malloc0(strlen(name));
		if (!entry->value) {
			queue_remove(dev->pending_requests, entry);
			free(entry);
			return;
		}

		entry->length = strlen(name);
		memcpy(entry->value, bt_get_adapter_name(), entry->length);
	} else if (handle == gap_srvc_data.appear) {
		entry->value = malloc0(2);
		if (!entry->value) {
			queue_remove(dev->pending_requests, entry);
			free(entry);
			return;
		}

		put_le16(APPEARANCE_GENERIC_PHONE, entry->value);
		entry->length = sizeof(uint8_t) * 2;
	} else if (handle == gap_srvc_data.priv) {
		entry->value = malloc0(1);
		if (!entry->value) {
			queue_remove(dev->pending_requests, entry);
			free(entry);
			return;
		}

		*entry->value = PERIPHERAL_PRIVACY_DISABLE;
		entry->length = sizeof(uint8_t);
	}

	entry->offset = offset;
}

static void register_gap_service(void)
{
	bt_uuid_t uuid;

	/* GAP UUID */
	bt_uuid16_create(&uuid, 0x1800);
	gap_srvc_data.srvc = gatt_db_add_service(gatt_db, &uuid, true, 7);

	/* Device name characteristic */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gap_srvc_data.dev_name =
			gatt_db_add_characteristic(gatt_db, gap_srvc_data.srvc,
							&uuid, 0,
							GATT_CHR_PROP_READ,
							gap_read_cb, NULL,
							NULL);

	/* Appearance */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	gap_srvc_data.appear =
			gatt_db_add_characteristic(gatt_db, gap_srvc_data.srvc,
							&uuid, 0,
							GATT_CHR_PROP_READ,
							gap_read_cb, NULL,
							NULL);

	/* Pripheral privacy flag */
	bt_uuid16_create(&uuid, GATT_CHARAC_PERIPHERAL_PRIV_FLAG);
	gap_srvc_data.priv =
			gatt_db_add_characteristic(gatt_db, gap_srvc_data.srvc,
							&uuid, 0,
							GATT_CHR_PROP_READ,
							gap_read_cb, NULL,
							NULL);

	gatt_db_service_set_active(gatt_db, gap_srvc_data.srvc , true);
}

/* TODO: Get those data from device possible via androig/bluetooth.c */
static struct device_info {
	const char *manufacturer_name;
	const char *system_id;
	const char *model_number;
	const char *serial_number;
	const char *firmware_rev;
	const char *hardware_rev;
	const char *software_rev;
} device_info = {
	.manufacturer_name =	"BlueZ",
	.system_id =		"BlueZ for Android",
	.model_number =		"model no",
	.serial_number =	"serial no",
	.firmware_rev =		"firmware rev",
	.hardware_rev =		"hardware rev",
	.software_rev =		"software rev",
};

static void device_info_read_cb(uint16_t handle, uint16_t offset,
					uint8_t att_opcode, bdaddr_t *bdaddr,
					void *user_data)
{
	struct pending_request *entry;
	struct gatt_device *dev;
	char *buf = user_data;

	dev = find_device_by_addr(bdaddr);
	if (!dev) {
		error("gatt: Could not find device ?!");
		return;
	}

	entry = queue_find(dev->pending_requests, match_dev_request_by_handle,
							UINT_TO_PTR(handle));
	if (!entry)
		return;

	entry->value = malloc0(strlen(buf));
	if (!entry->value) {
		queue_remove(dev->pending_requests, entry);
		free(entry);
		return;
	}

	entry->length = strlen(buf);
	memcpy(entry->value, buf, entry->length);
	entry->offset = offset;
}

static void register_device_info_service(void)
{
	bt_uuid_t uuid;
	uint16_t srvc_handle;

	DBG("");

	/* Device Information Service */
	bt_uuid16_create(&uuid, 0x180a);
	srvc_handle = gatt_db_add_service(gatt_db, &uuid, true, 15);

	/* User data are not const hence (void *) cast is used */
	bt_uuid16_create(&uuid, GATT_CHARAC_SYSTEM_ID);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.system_id);

	bt_uuid16_create(&uuid, GATT_CHARAC_MODEL_NUMBER_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.model_number);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERIAL_NUMBER_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.serial_number);

	bt_uuid16_create(&uuid, GATT_CHARAC_FIRMWARE_REVISION_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.firmware_rev);

	bt_uuid16_create(&uuid, GATT_CHARAC_HARDWARE_REVISION_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.hardware_rev);

	bt_uuid16_create(&uuid, GATT_CHARAC_SOFTWARE_REVISION_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.software_rev);

	bt_uuid16_create(&uuid, GATT_CHARAC_MANUFACTURER_NAME_STRING);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_READ,
					device_info_read_cb, NULL,
					(void *) device_info.manufacturer_name);

	gatt_db_service_set_active(gatt_db, srvc_handle, true);
}

static void gatt_srvc_change_register_cb(uint16_t handle, uint16_t offset,
						const uint8_t *val, size_t len,
						uint8_t att_opcode,
						bdaddr_t *bdaddr,
						void *user_data)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	struct gatt_device *dev;
	uint16_t length;

	dev = find_device_by_addr(bdaddr);
	if (!dev) {
		error("gatt: Could not find device ?!");
		return;
	}

	/* TODO handle CCC */

	/* Set services changed notification flag */
	dev->notify_services_changed = !!(*val);

	length = enc_write_resp(pdu);

	g_attrib_send(dev->attrib, 0, pdu, length, NULL, NULL, NULL);
}

static void register_gatt_service(void)
{
	bt_uuid_t uuid;
	uint16_t srvc_handle;

	DBG("");

	bt_uuid16_create(&uuid, 0x1801);
	srvc_handle = gatt_db_add_service(gatt_db, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	gatt_db_add_characteristic(gatt_db, srvc_handle, &uuid, 0,
					GATT_CHR_PROP_INDICATE, NULL, NULL,
					NULL);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_add_char_descriptor(gatt_db, srvc_handle, &uuid, 0, NULL,
					gatt_srvc_change_register_cb, NULL);

	gatt_db_service_set_active(gatt_db, srvc_handle, true);
}

static bool start_listening_io(void)
{
	GError *gerr = NULL;

	/* For now only listen on BLE */
	listening_io = bt_io_listen(connect_event, NULL,
					&listening_io, NULL, &gerr,
					BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
					BT_IO_OPT_CID, ATT_CID,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (!listening_io) {
		error("gatt: Failed to start listening IO (%s)", gerr->message);
		g_error_free(gerr);
		return false;
	}

	return true;
}

bool bt_gatt_register(struct ipc *ipc, const bdaddr_t *addr)
{
	DBG("");

	if (!start_listening_io())
		return false;

	gatt_devices = queue_new();
	gatt_apps = queue_new();
	app_connections = queue_new();
	listen_apps = queue_new();
	gatt_db = gatt_db_new();

	if (!gatt_devices || !gatt_apps || !listen_apps ||
						!app_connections || !gatt_db) {
		error("gatt: Failed to allocate memory for queues");

		queue_destroy(gatt_apps, NULL);
		gatt_apps = NULL;

		queue_destroy(gatt_devices, NULL);
		gatt_devices = NULL;

		queue_destroy(app_connections, NULL);
		app_connections = NULL;

		queue_destroy(listen_apps, NULL);
		listen_apps = NULL;

		gatt_db_destroy(gatt_db);
		gatt_db = NULL;

		g_io_channel_unref(listening_io);
		listening_io = NULL;

		return false;
	}

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;

	ipc_register(hal_ipc, HAL_SERVICE_ID_GATT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	register_gap_service();
	register_device_info_service();
	register_gatt_service();

	return true;
}

void bt_gatt_unregister(void)
{
	DBG("");

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_GATT);
	hal_ipc = NULL;

	queue_destroy(gatt_apps, destroy_gatt_app);
	gatt_apps = NULL;

	queue_destroy(app_connections, destroy_connection);
	app_connections = NULL;

	queue_destroy(gatt_devices, destroy_device);
	gatt_devices = NULL;

	queue_destroy(listen_apps, NULL);
	listen_apps = NULL;

	gatt_db_destroy(gatt_db);
	gatt_db = NULL;

	g_io_channel_unref(listening_io);
	listening_io = NULL;
}
