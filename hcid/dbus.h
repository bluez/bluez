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

#define TEST_INTERFACE		BASE_INTERFACE ".Test"

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

/* Discover types */
#define DISCOVER_TYPE_NONE	0x00
#define STD_INQUIRY		0x01
#define PERIODIC_INQUIRY	0x02

/* Actions executed after inquiry complete */
#define RESOLVE_NAME		0x10

typedef enum {
	NAME_ANY,
	NAME_NOT_REQUIRED, /* used by get remote name without name resolving */
	NAME_REQUIRED,      /* remote name needs be resolved       */
	NAME_REQUESTED,    /* HCI remote name request was sent    */
	NAME_SENT          /* D-Bus signal RemoteNameUpdated sent */
} name_status_t;

struct discovered_dev_info {
	bdaddr_t bdaddr;
	name_status_t name_status;
};

struct bonding_request_info {
	bdaddr_t bdaddr;
	DBusConnection *conn;
	DBusMessage *rq;
	GIOChannel *io;
	guint io_id;
	int hci_status;
	int cancel;
	int auth_active;
};

struct pending_pin_info {
	bdaddr_t bdaddr;
	int replied;	/* If we've already replied to the request */
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
	int disc_active;			/* standard discovery active: includes name resolution step */
	int pdisc_active;			/* periodic discovery active */
	int pinq_idle;				/* tracks the idle time for periodic inquiry */
	int discover_type;			/* type requested */
	struct slist *disc_devices;
	struct slist *oor_devices;		/* out of range device list */
	char *pdiscovery_requestor;		/* periodic discovery requestor unique name */
	char *discovery_requestor;		/* discovery requestor unique name */
	DBusMessage *discovery_cancel;		/* discovery cancel message request */
	struct slist *passkey_agents;
	struct slist *active_conn;
	struct bonding_request_info *bonding;
	struct slist *pin_reqs;
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

DBusMessage *new_authentication_return(DBusMessage *msg, uint8_t status);

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
DBusHandlerResult error_sdp_failed(DBusConnection *conn, DBusMessage *msg, int err);

typedef void (*name_cb_t)(const char *name, void *user_data);

int name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);

DBusHandlerResult handle_test_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult handle_rfcomm_method(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult handle_sdp_method(DBusConnection *conn, DBusMessage *msg, void *data);
DBusHandlerResult get_remote_svc_handles(DBusConnection *conn, DBusMessage *msg, void *data);
DBusHandlerResult get_remote_svc_rec(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult simple_introspect(DBusConnection *conn, DBusMessage *msg, void *data);

service_handler_func_t find_service_handler(struct service_data *services, DBusMessage *msg);
int str2uuid(uuid_t *uuid, const char *string);

void create_bond_req_exit(const char *name, struct hci_dbus_data *pdata);
void discover_devices_req_exit(const char *name, struct hci_dbus_data *pdata);
int cancel_discovery(struct hci_dbus_data *pdata);
void periodic_discover_req_exit(const char *name, struct hci_dbus_data *pdata);
int cancel_periodic_discovery(struct hci_dbus_data *pdata);
int pending_remote_name_cancel(struct hci_dbus_data *pdata);

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
int pin_req_cmp(const void *p1, const void *p2);
int disc_device_find(const struct discovered_dev_info *d1, const struct discovered_dev_info *d2);
int disc_device_append(struct slist **list, bdaddr_t *bdaddr, name_status_t name_status);
int disc_device_req_name(struct hci_dbus_data *dbus_data);

int discoverable_timeout_handler(void *data);

uint16_t sdp_str2svclass(const char *str);
typedef void get_record_cb_t(sdp_record_t *rec, void *data, int err);
int get_record_with_uuid(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			const uuid_t *uuid, get_record_cb_t *cb, void *data);
int get_record_with_handle(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			uint32_t handle, get_record_cb_t *cb, void *data);

#endif /* __H_BLUEZ_DBUS_H__ */
