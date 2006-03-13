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

#define BASE_PATH		"/org/bluez"
#define BASE_INTERFACE		"org.bluez"

#define ADAPTER_PATH		BASE_PATH "/Adapter"
#define ADAPTER_INTERFACE	BASE_INTERFACE ".Adapter"

#define MANAGER_PATH		BASE_PATH "/Manager"
#define MANAGER_INTERFACE	BASE_INTERFACE ".Manager"

#define ERROR_INTERFACE		BASE_INTERFACE ".Error"

#define SECURITY_INTERFACE	BASE_INTERFACE ".Security"

#define MANAGER_PATH_MASK	(1 << 15)
#define ADAPTER_PATH_MASK	(1 << 14)

/* /org/bluez/Manager */
#define MANAGER_ROOT_ID		MANAGER_PATH_MASK

/* /org/bluez/Adapter */
#define ADAPTER_ROOT_ID		ADAPTER_PATH_MASK

/* E.g. /org/bluez/Adapter/hci0 */
#define ADAPTER_PATH_ID		(ADAPTER_PATH_MASK | 0x0001)

#define INVALID_PATH_ID		0xFFFF
#define INVALID_DEV_ID		0xFFFF

#define MAX_PATH_LENGTH		64

typedef DBusHandlerResult (*service_handler_func_t) (DBusConnection *conn,
							DBusMessage *msg,
							void *user_data);

struct service_data {
	const char		*name;
	service_handler_func_t	handler_func;
};

typedef int (timeout_handler_func_t) (void *data);

struct hci_dbus_data {
	uint16_t dev_id;
	uint16_t path_id;
	uint32_t discoverable_timeout;
	uint32_t timeout_hits;
	timeout_handler_func_t *timeout_handler;
	uint8_t mode;		/* scan mode */
	uint8_t resolve_name;	/* send name on discover process */
	struct slist *discovered_devices;
	char *requestor_name;	/* requestor unique name */
};

struct passkey_agent {
	char *addr;
	char *name;
	char *path;
};

typedef int register_function_t(DBusConnection *conn, uint16_t id);
typedef int unregister_function_t(DBusConnection *conn, uint16_t id);

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data);
DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data);

DBusHandlerResult bluez_new_failure_msg(DBusConnection *conn, DBusMessage *msg, const uint32_t ecode);

DBusMessage *dev_signal_factory(const int devid, const char *prop_name, const int first, ...);

DBusConnection *get_dbus_connection(void);

int get_default_dev_id(void);

DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_invalid_arguments(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_implemented(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_authorized(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_unknown_address(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_unsupported_major_class(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_discover_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_record_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg);

typedef void (*name_cb_t)(const char *name, void *user_data);

int name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data);

service_handler_func_t find_service_handler(struct service_data *services, DBusMessage *msg);

int call_default_passkey_agent(int dev, const char *path, bdaddr_t *sba, bdaddr_t *dba);

static inline DBusHandlerResult send_reply_and_unref(DBusConnection *conn, DBusMessage *reply)
{
	if (reply) {
		dbus_connection_send(conn, reply, NULL);

		dbus_message_unref(reply);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

/*
 * Scanning modes, used by DEV_SET_MODE
 * off: remote devices are not allowed to find or connect to this device
 * connectable: remote devices are allowed to connect, but they are not
 *              allowed to find it.
 * discoverable: remote devices are allowed to connect and find this device
 * unknown: reserved to not allowed/future modes
 */
#define MODE_OFF		"off"
#define MODE_CONNECTABLE	"connectable"
#define MODE_DISCOVERABLE	"discoverable"
#define MODE_UNKNOWN		"unknown"

#define DFT_DISCOVERABLE_TIMEOUT	180	/* 3 seconds */
#define DISCOVERABLE_TIMEOUT_OFF	0

#endif /* __H_BLUEZ_DBUS_H__ */
