/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __H_BLUEZ_DBUS_H__
#define __H_BLUEZ_DBUS_H__

#include <stdint.h>
#include <dbus/dbus.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include "list.h"
#include "glib-ectomy.h"

#define BASE_PATH		"/org/bluez"
#define BASE_INTERFACE		"org.bluez"

#define ADAPTER_INTERFACE	BASE_INTERFACE ".Adapter"

#define MANAGER_INTERFACE	BASE_INTERFACE ".Manager"

#define ERROR_INTERFACE		BASE_INTERFACE ".Error"

#define SECURITY_INTERFACE	BASE_INTERFACE ".Security"

#define RFCOMM_INTERFACE	BASE_INTERFACE ".RFCOMM"

#define SDP_INTERFACE		BASE_INTERFACE ".SDP"

#define INVALID_DEV_ID		0xFFFF

#define MAX_PATH_LENGTH		64

#define BONDING_TIMEOUT         45000 /* 45 sec */

typedef DBusHandlerResult (*service_handler_func_t) (DBusConnection *conn,
							DBusMessage *msg,
							void *user_data);

struct service_data {
	const char		*name;
	service_handler_func_t	handler_func;
};

typedef enum {
	STATE_IDLE,
	STATE_DISCOVER,
	STATE_RESOLVING_NAMES
} discover_state_t;

/* discover type  */
#define WITHOUT_NAME_RESOLVING		1 /* D-Bus and non D-Bus request */
#define RESOLVE_NAME			2	

typedef enum {
	NAME_ANY,
	NAME_PENDING,
	NAME_SENT
} name_status_t;

struct discovered_dev_info {
	bdaddr_t bdaddr;
	name_status_t name_status;
	int discover_type;
};

struct bonding_request_info {
	bdaddr_t bdaddr;
	DBusMessage *rq;
	DBusMessage *cancel;
	int disconnect; /* disconnect after finish */
};

struct active_conn_info {
	bdaddr_t bdaddr;
	uint16_t handle;
};

struct hci_dbus_data {
	uint16_t dev_id;
	int up;
	char address[18];		   /* adapter Bluetooth Address */
	uint32_t timeout_id;		   /* discoverable timeout id */
	uint32_t discoverable_timeout;	   /* discoverable time(msec) */
	uint8_t mode;		           /* scan mode */
	discover_state_t discover_state;   /* discover states */
	int discover_type;                 /* with/without name resolving */
	struct slist *disc_devices;
	char *discovery_requestor;		/* discovery requestor unique name */
	struct slist *passkey_agents;
	struct bonding_request_info *bonding;
	struct slist *active_conn;
	struct slist *pending_bondings;
};

struct passkey_agent {
	struct hci_dbus_data *pdata;
	DBusConnection *conn;
	char *addr;
	char *name;
	char *path;
	struct slist *pending_requests;
	int exited;
	guint timeout;
};

struct pending_agent_request {
	struct passkey_agent *agent;
	int dev;
	bdaddr_t sba;
	bdaddr_t bda;
	char *path;
	DBusPendingCall *call;
};

typedef int register_function_t(DBusConnection *conn, uint16_t id);
typedef int unregister_function_t(DBusConnection *conn, uint16_t id);

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data);
DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data);

const char *major_class_str(uint32_t class);
const char *minor_class_str(uint32_t class);
struct slist *service_classes_str(uint32_t class);

DBusHandlerResult bluez_new_failure_msg(DBusConnection *conn, DBusMessage *msg, const uint32_t ecode);

DBusMessage *dev_signal_factory(const int devid, const char *prop_name, const int first, ...);

int get_default_dev_id(void);

DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_not_ready(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_invalid_arguments(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_unknown_method(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_authorized(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_request_deferred(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_unsupported_major_class(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_bonding_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_not_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_authentication_canceled(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_discover_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_not_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_record_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_binding_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_search_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_canceled(DBusConnection *conn, DBusMessage *msg);

typedef void (*name_cb_t)(const char *name, void *user_data);

int name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult handle_rfcomm_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult handle_sdp_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult simple_introspect(DBusConnection *conn, DBusMessage *msg, void *data);

service_handler_func_t find_service_handler(struct service_data *services, DBusMessage *msg);

void create_bond_req_exit(const char *name, struct hci_dbus_data *pdata);

int handle_passkey_request(DBusConnection *conn, int dev, const char *path, bdaddr_t *sba, bdaddr_t *dba);
void release_default_agent(void);
void release_passkey_agents(struct hci_dbus_data *pdata, bdaddr_t *bda);
void cancel_passkey_agent_requests(struct slist *agents, const char *path, bdaddr_t *dba);

static inline DBusHandlerResult send_reply_and_unref(DBusConnection *conn, DBusMessage *reply)
{
	if (reply) {
		dbus_connection_send(conn, reply, NULL);

		dbus_message_unref(reply);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

int active_conn_find_by_bdaddr(const void *data, const void *user_data);
void bonding_request_free(struct bonding_request_info *dev);
int disc_device_append(struct slist **list, bdaddr_t *bdaddr, name_status_t name_status, int discover_type);
int disc_device_req_name(struct hci_dbus_data *dbus_data);

int discoverable_timeout_handler(void *data);

sdp_record_t *find_record_by_uuid(const char *address, uuid_t *uuid);
sdp_record_t *find_record_by_handle(const char *address, int handle);
uint16_t sdp_str2svclass(const char *str);

#endif /* __H_BLUEZ_DBUS_H__ */
