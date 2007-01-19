/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "dbus.h"
#include "logging.h"
#include "input-service.h"
#include "glib-ectomy.h"
#include "textfile.h"

#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define INPUT_SERVICE "org.bluez.input"
#define INPUT_PATH "/org/bluez/input"
#define INPUT_MANAGER_INTERFACE	"org.bluez.input.Manager"
#define INPUT_DEVICE_INTERFACE	"org.bluez.input.Device"
#define INPUT_ERROR_INTERFACE	"org.bluez.Error"

static DBusConnection *connection = NULL;

struct input_device {
	char addr[18];
};

struct pending_req {
	char *adapter_path;
	char peer[18];
	DBusConnection *conn;
	DBusMessage *msg;
};

struct pending_req *pending_req_new(DBusConnection *conn, DBusMessage *msg,
				const char *adapter_path, const char *peer)
{
	struct pending_req *pr;
	pr = malloc(sizeof(struct pending_req));
	if (!pr)
		return NULL;

	memset(pr, 0, sizeof(struct pending_req));
	pr->adapter_path = strdup(adapter_path);
	strncpy(pr->peer, peer, 18);
	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);

	return pr;
}

void pending_req_free(struct pending_req *pr)
{
	if (!pr)
		return;
	if (pr->adapter_path)
		free(pr->adapter_path);
	if (pr->conn)
		dbus_connection_unref(pr->conn);
	if (pr->msg)
		dbus_message_unref(pr->msg);
	free(pr);
}

struct input_device *input_device_new(const char *addr)
{
	struct input_device *idev;

	idev = malloc(sizeof(struct input_device));
	if (!idev)
		return NULL;

	memset(idev, 0, sizeof(struct input_device));

	memcpy(idev->addr, addr, 18);

	return idev;
}

/*
 * Common D-Bus BlueZ input error functions
 */
static DBusHandlerResult err_unknown_device(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".UnknownDevice",
				"Invalid device"));
}

static DBusHandlerResult err_unknown_method(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".UnknownMethod",
				"Unknown input method"));
}

static DBusHandlerResult err_failed(DBusConnection *conn, DBusMessage *msg,
				const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".Failed", str));
}

static DBusHandlerResult err_already_exists(DBusConnection *conn,
				DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".AlreadyExists", str));
}

static DBusHandlerResult err_generic(DBusConnection *conn, DBusMessage *msg,
				const char *name, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg, name, str));

}

static inline int create_filename(char *buf, size_t size,
			bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

static int has_hid_record(const char *local, const char *peer)
{
	char filename[PATH_MAX + 1], *str;

	create_name(filename, PATH_MAX, STORAGEDIR, local, "hidd");

	str = textfile_get(filename, peer);
	if (!str)
		return 0;

	free(str);
	return 1;
}

/*
 * Input Device methods
 */
static DBusHandlerResult device_connect(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_disconnect(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_unplug(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_is_connected(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_get_address(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_get_name(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_get_product_id(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_get_vendor_id(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_set_timeout(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult device_message(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Accept messages from the input interface only */
	if (strcmp(INPUT_DEVICE_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "Connect") == 0)
		return device_connect(conn, msg, data);

	if (strcmp(member, "Disconnect") == 0)
		return device_disconnect(conn, msg, data);

	if (strcmp(member, "Unplug") == 0)
		return device_unplug(conn, msg, data);

	if (strcmp(member, "IsConnected") == 0)
		return device_is_connected(conn, msg, data);

	if (strcmp(member, "GetAddress") == 0)
		return device_get_address(conn, msg, data);

	if (strcmp(member, "GetName") == 0)
		return device_get_name(conn, msg, data);

	if (strcmp(member, "GetProductId") == 0)
		return device_get_product_id(conn, msg, data);

	if (strcmp(member, "GetVendorId") == 0)
		return device_get_vendor_id(conn, msg, data);

	if (strcmp(member, "SetTimeout") == 0)
		return device_set_timeout(conn, msg, data);

	return err_unknown_method(conn, msg);
}

static DBusHandlerResult device_message(DBusConnection *conn,
				DBusMessage *msg, void *data);
/* Virtual table to handle device object path hierarchy */
static const DBusObjectPathVTable device_table = {
	.message_function = device_message,
};

/*
 * Input Manager methods
 */
struct input_manager {
	char adapter[18];
	char *adapter_path;
	GList *paths;
};

void input_manager_free(struct input_manager *mgr)
{
	if (!mgr)
		return;
	if (mgr->paths)
		g_list_foreach(mgr->paths, (GFunc) free, NULL);
	if (mgr->adapter_path)
		free(mgr->adapter_path);
	free(mgr);
}

static int path_addr_cmp(const char *path, const char *addr)
{
	struct input_device *idev;

	if (!dbus_connection_get_object_path_data(connection, path,
				(void *) &idev))
		return -1;

	if (!idev)
		return -1;

	return strcasecmp(idev->addr, addr);
}

static int get_handles(struct pending_req *pr, const char *uuid,
			DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *paddr;

	msg  = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	paddr = pr->peer;
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);
	
	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void hid_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	uint32_t *phandle;
	DBusError derr;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {

		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (len == 0) {
		err_failed(pr->conn, pr->msg, "SDP error");
		goto fail;
	} else {
		info("FIXME: request HID record");
	}

	goto done;
fail:
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void pnp_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	const char *hid_uuid = "00001124-0000-1000-8000-00805f9b34fb";
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {

		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (len == 0) {
		/* PnP is optional: Ignore it and request the HID handle  */
		if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
			err_failed(pr->conn, pr->msg, "SDP error");
			goto fail;
		}
	} else {
		/* Request PnP record */
		info("FIXME: Request PnP Record");
	}

	goto done;
fail:
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static DBusHandlerResult manager_create_device(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct input_manager *mgr = data;
	struct input_device *idev;
	DBusMessage *reply;
	DBusError derr;
	const char *addr;
	const char *keyb_path = "/org/bluez/input/keyboard0";
	const char *pnp_uuid = "00001200-0000-1000-8000-00805f9b34fb";
	GList *path;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID)) {
		err_generic(conn, msg, derr.name, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	path = g_list_find_custom(mgr->paths, addr,
			(GCompareFunc) path_addr_cmp);
	if (path)
		return err_already_exists(conn, msg, "Input Already exists");

	if (!has_hid_record(mgr->adapter, addr)) {
		struct pending_req *pr;
		pr = pending_req_new(conn, msg, mgr->adapter_path, addr);
		if (!pr)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (get_handles(pr, pnp_uuid, pnp_handle_reply) < 0) {
			pending_req_free(pr);
			return err_failed(conn, msg, "SDP error");
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	idev = input_device_new(addr);
	if (!idev)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(idev);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!dbus_connection_register_object_path(conn,
				keyb_path, &device_table, idev)) {
		error("Input device path registration failed");
		free(idev);
		return err_failed(conn, msg, "Path registration failed");
	}

	mgr->paths = g_list_append(mgr->paths, strdup(keyb_path));
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &keyb_path,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_remove_device(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult manager_list_devices(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct input_manager *mgr = data;
	DBusMessageIter iter, iter_array;
	DBusMessage *reply;
	GList *paths;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (paths = mgr->paths; paths != NULL; paths = paths->next) {
		const char *ppath = paths->data;
		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &ppath);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_message(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(INPUT_PATH, path) != 0)
		return err_unknown_device(conn, msg);

	/* Accept messages from the input manager interface only */
	if (strcmp(INPUT_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ListDevices") == 0)
		return manager_list_devices(conn, msg, data);

	if (strcmp(member, "CreateDevice") == 0)
		return manager_create_device(conn, msg, data);

	if (strcmp(member, "RemoveDevice") == 0)
		return manager_remove_device(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	struct input_manager *mgr = data;

	info("Unregistered manager path");

	input_manager_free(mgr);
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

int input_dbus_init(void)
{
	struct input_manager *mgr;
	DBusMessage *msg, *reply;
	DBusError derr;
	const char *adapter;

	connection = init_dbus(INPUT_SERVICE, NULL, NULL);
	if (!connection)
		return -1;

	dbus_connection_set_exit_on_disconnect(connection, TRUE);

	mgr = malloc(sizeof(struct input_manager));
	memset(mgr, 0, sizeof(struct input_manager));

	/* Get the default adapter path */
	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
			"org.bluez.Manager", "DefaultAdapter");

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
			msg, -1, &derr);
	dbus_message_unref(msg);

	if (!reply) {
		error("input init failed: %s (%s)", derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &adapter,
				DBUS_TYPE_INVALID)) {
		error("input init failed: %s (%s)", derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	mgr->adapter_path = strdup(adapter);
	dbus_message_unref(reply);

	/* Get the adapter address */
	msg = dbus_message_new_method_call("org.bluez", adapter,
			"org.bluez.Adapter", "GetAddress");

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
			msg, -1, &derr);
	dbus_message_unref(msg);

	if (!reply) {
		error("input init failed: %s (%s)", derr.name, derr.message);
		dbus_error_free(&derr);
		dbus_error_free(&derr);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &adapter,
				DBUS_TYPE_INVALID)) {
		error("input init failed: %s (%s)", derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	strncpy(mgr->adapter, adapter, 18);
	dbus_message_unref(reply);

	info("Default adapter: %s (%s)", mgr->adapter_path, mgr->adapter);

	/* Fallback to catch invalid device path */
	if (!dbus_connection_register_fallback(connection, INPUT_PATH,
						&manager_table, mgr)) {
		error("D-Bus failed to register %s path", INPUT_PATH);
		goto fail;
	}

	info("Registered input manager path:%s", INPUT_PATH);

	return 0;
fail:
	input_manager_free(mgr);

	return -1;
}

void input_dbus_exit(void)
{
	dbus_connection_unregister_object_path(connection, INPUT_PATH);

	dbus_connection_unref(connection);
}

