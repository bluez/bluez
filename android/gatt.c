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

struct gatt_app {
	int32_t id;
	uint8_t uuid[16];

	gatt_app_type_t type;

	/* Valid for client applications */
	struct queue *notifications;
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

	guint watch_id;
	guint server_id;

	int ref;
	int conn_cnt;
};

struct app_connection {
	struct gatt_device *device;
	struct gatt_app *app;
	int32_t id;
};

static struct ipc *hal_ipc = NULL;
static bdaddr_t adapter_addr;
static bool scanning = false;

static struct queue *gatt_apps = NULL;
static struct queue *gatt_devices = NULL;
static struct queue *app_connections = NULL;

static struct queue *listen_apps = NULL;
static struct gatt_db *gatt_db = NULL;

static GIOChannel *listening_io = NULL;

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

static void destroy_device(void *data)
{
	struct gatt_device *dev = data;

	if (!dev)
		return;

	queue_destroy(dev->services, destroy_service);

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
					HAL_EV_GATT_CLIENT_SEARCH_RESULT,
					sizeof(ev), &ev);
}

static void send_client_all_primary(struct app_connection *connection,
								int32_t status)
{
	struct hal_ev_gatt_client_search_complete ev;

	if (!status)
		queue_foreach(connection->device->services,
						send_client_primary_notify,
						INT_TO_PTR(connection->id));

	ev.status = status;
	ev.conn_id = connection->id;
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
	struct app_connection *conn = user_data;
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

	if (!queue_isempty(conn->device->services)) {
		info("gatt: Services already cached");
		gatt_status = GATT_SUCCESS;
		goto done;
	}

	/*
	 * There might be multiply services with same uuid. Therefore make sure
	 * each primary service one has unique instance_id
	 */
	instance_id = 0;

	for (l = services; l; l = l->next) {
		struct gatt_primary *prim = l->data;
		struct service *p;

		p = create_service(instance_id++, true, prim->uuid, prim);
		if (!p)
			continue;

		if (!queue_push_tail(conn->device->services, p)) {
			error("gatt: Cannot push primary service to the list");
			free(p);
			continue;
		}

		DBG("attr handle = 0x%04x, end grp handle = 0x%04x uuid: %s",
			prim->range.start, prim->range.end, prim->uuid);
	}

	gatt_status = GATT_SUCCESS;

done:
	send_client_all_primary(conn, gatt_status);
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

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_GATT,
						HAL_EV_GATT_CLIENT_LISTEN,
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
		if (queue_length(listen_apps) > 1) {
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
		if (queue_length(listen_apps) > 1) {
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

static void handle_client_search_service(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_search_service *cmd = buf;
	struct app_connection *conn;
	uint8_t status;

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

	/* TODO:  Handle filter uuid */

	/* Use cache if possible */
	if (!queue_isempty(conn->device->services)) {
		send_client_all_primary(conn, GATT_SUCCESS);

		status = HAL_STATUS_SUCCESS;
		goto reply;
	}

	if (conn->device->state != DEVICE_CONNECTED) {
		char bda[18];

		ba2str(&conn->device->bdaddr, bda);
		error("gatt: device %s not connected", bda);

		status = HAL_STATUS_FAILED;
		goto reply;
	}

	if (!gatt_discover_primary(conn->device->attrib, NULL, primary_cb,
									conn)) {
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

	if (incl) {
		send_client_incl_service_notify(service, incl, conn->id,
								GATT_SUCCESS);
		return;
	}

failed:
	send_client_incl_service_notify(service, NULL, conn->id,
								GATT_FAILURE);
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
	struct service *incl_service;
	struct element_id match_id;
	uint8_t status;

	DBG("");

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

		goto reply;
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

	/*
	 * Note that Android framework expects failure notification
	 * which is treat as the end of included services
	 */
	if (!incl_service)
		send_client_incl_service_notify(prim_service, NULL,
						conn->id, GATT_FAILURE);
	else
		send_client_incl_service_notify(prim_service, incl_service,
						conn->id, GATT_SUCCESS);

	status = HAL_STATUS_SUCCESS;

reply:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_GATT,
					HAL_OP_GATT_CLIENT_GET_INCLUDED_SERVICE,
					status);

	/*
	 * In case of error in handling request we need to send event with
	 * Android framework is stupid and do not check status of response
	 */
	if (status)
		send_client_incl_service_notify(prim_service, NULL,
						conn->id, GATT_FAILURE);
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

static void cache_all_srvc_chars(struct service *srvc,
							GSList *characteristics)
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

static uint16_t parse_descrs(const uint8_t *pdu, guint16 len,
							struct queue *cache)
{
	struct att_data_list *list;
	guint8 format;
	uint16_t handle = 0xffff;
	int i;

	list = dec_find_info_resp(pdu, len, &format);
	if (!list)
		return handle;

	for (i = 0; i < list->num; i++) {
		char uuidstr[MAX_LEN_UUID_STR];
		struct descriptor *descr;
		bt_uuid_t uuid128;
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

	return handle;
}

struct discover_desc_data {
	struct app_connection *conn;
	struct service *srvc;
	struct characteristic *ch;

	struct queue *result;
};

static void gatt_discover_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct discover_desc_data *data = user_data;
	struct app_connection *conn = data->conn;
	struct service *srvc = data->srvc;
	struct characteristic *ch = data->ch;
	struct descriptor *descr;

	if (!status) {
		uint16_t last_handle = parse_descrs(pdu, len, data->result);

		if (last_handle >= ch->end_handle)
			goto reply;

		if (!gatt_discover_char_desc(conn->device->attrib,
						last_handle + 1, ch->end_handle,
						gatt_discover_desc_cb, data))
			goto reply;

		/* Do not reply yet, wait for next piece */
		return;
	} else if (status != ATT_ECODE_ATTR_NOT_FOUND) {
		error("gatt: Discover all char descriptors failed: %s",
							att_ecode2str(status));
	}

reply:
	queue_destroy(ch->descriptors, free);
	ch->descriptors = data->result;

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
	cb_data->result = queue_new();

	if (!cb_data->result) {
		free(cb_data);
		return false;
	}

	if (!gatt_discover_char_desc(connection->device->attrib, start, end,
					gatt_discover_desc_cb, cb_data)) {
		queue_destroy(cb_data->result, NULL);
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
				HAL_OP_GATT_CLIENT_REGISTER_FOR_NOTIFICATION,
				status);
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
				HAL_OP_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION,
				status);
}

static void handle_client_read_remote_rssi(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_client_read_remote_rssi *cmd = buf;
	struct hal_ev_gatt_client_read_remote_rssi ev;
	uint8_t status;

	DBG("");

	if (!find_app_by_id(cmd->client_if)) {
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

static void handle_server_add_characteristic(const void *buf, uint16_t len)
{
	const struct hal_cmd_gatt_server_add_characteristic *cmd = buf;
	struct hal_ev_gatt_server_characteristic_added ev;
	struct gatt_app *server;
	bt_uuid_t uuid;
	uint8_t status;

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2uuid(cmd->uuid, &uuid);

	ev.char_handle = gatt_db_add_characteristic(gatt_db,
							cmd->service_handle,
							&uuid, cmd->permissions,
							cmd->properties,
							NULL, NULL, NULL);
	if (!ev.char_handle)
		status = HAL_STATUS_FAILED;
	else
		status = HAL_STATUS_SUCCESS;

failed:
	ev.srvc_handle = cmd->service_handle;
	ev.status = status;
	ev.server_if = cmd->server_if;
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

	DBG("");

	memset(&ev, 0, sizeof(ev));

	server = find_app_by_id(cmd->server_if);
	if (!server) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	android2uuid(cmd->uuid, &uuid);

	ev.descr_handle = gatt_db_add_char_descriptor(gatt_db,
							cmd->service_handle,
							&uuid, cmd->permissions,
							NULL, NULL, NULL);
	if (!ev.descr_handle)
		status = HAL_STATUS_FAILED;
	else
		status = HAL_STATUS_SUCCESS;

failed:
	ev.server_if = cmd->server_if;
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

static void att_handler(const uint8_t *ipdu, uint16_t len, gpointer user_data)
{
	struct gatt_device *dev = user_data;
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	uint8_t status;
	uint16_t length = 0;

	DBG("op 0x%02x", ipdu[0]);

	switch (ipdu[0]) {
	case ATT_OP_READ_BY_GROUP_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_WRITE_REQ:
	case ATT_OP_WRITE_CMD:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_HANDLE_CNF:
	case ATT_OP_HANDLE_IND:
	case ATT_OP_HANDLE_NOTIFY:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	default:
		DBG("Unsupported request 0x%02x", ipdu[0]);
		status = ATT_ECODE_REQ_NOT_SUPP;
		goto done;
	}

done:
	if (status)
		length = enc_error_resp(ipdu[0], 0x0000, status, opdu,
							ATT_DEFAULT_LE_MTU);

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
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	uint16_t len;
	struct gatt_device *dev;

	DBG("");

	dev = find_device_by_addr(bdaddr);
	if (!dev) {
		error("gatt: Could not find device ?!");
		return;
	}

	if (handle == gap_srvc_data.dev_name) {
		const char *name = bt_get_adapter_name();

		len = enc_read_resp((uint8_t *)name, strlen(name),
							pdu, sizeof(pdu));
		goto done;
	}

	if (handle == gap_srvc_data.appear) {
		uint8_t val[2];
		put_le16(APPEARANCE_GENERIC_PHONE, val);
		len = enc_read_resp(val, sizeof(val), pdu, sizeof(pdu));
		goto done;
	}

	if (handle == gap_srvc_data.priv) {
		uint8_t val = PERIPHERAL_PRIVACY_DISABLE;
		len = enc_read_resp(&val, sizeof(val), pdu, sizeof(pdu));
		goto done;
	}

	error("gatt: Unknown handle 0x%02x", handle);
	len = enc_error_resp(ATT_OP_READ_REQ, handle,
					ATT_ECODE_UNLIKELY, pdu, sizeof(pdu));

done:
	g_attrib_send(dev->attrib, 0, pdu, len, NULL, NULL, NULL);
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
