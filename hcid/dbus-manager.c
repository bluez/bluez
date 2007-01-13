/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-security.h"
#include "dbus-service.h"
#include "dbus-manager.h"
#include "dbus-hci.h"
#include "sdp-xml.h"

static int default_adapter_id = -1;
static int autostart = 1;

static uint32_t next_handle = 0x10000;

static DBusHandlerResult interface_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t version = 0;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &version,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult default_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	if (default_adapter_id < 0)
		return error_no_such_adapter(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, default_adapter_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult find_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char path[MAX_PATH_LENGTH], *path_ptr = path;
	const char *pattern;
	int dev_id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	dev_id = hci_devid(pattern);
	if (dev_id < 0)
		return error_no_such_adapter(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, dev_id);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_adapters(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, sk;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return error_failed(conn, msg, errno);

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		close(sk);
		return error_out_of_memory(conn, msg);
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		int err = errno;
		close(sk);
		free(dl);
		return error_failed(conn, msg, err);
	}

	dr = dl->dev_req;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		close(sk);
		free(dl);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (i = 0; i < dl->dev_num; i++, dr++) {
		char path[MAX_PATH_LENGTH], *path_ptr = path;
		struct hci_dev_info di;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", BASE_PATH, di.name);

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path_ptr);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	free(dl);

	close(sk);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	append_available_services(&array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static void autostart_reply(DBusPendingCall *pcall, void *udata)
{
	struct service_call *call = udata;
	DBusMessage *agent_reply = dbus_pending_call_steal_reply(pcall);
	DBusError err;

	dbus_error_init(&err);

	/* Ignore if the result is an error */
	if (dbus_set_error_from_message(&err, agent_reply)) {
		error("Service auto start failed: %s(%s)",
			err.message, call->agent->name);
		dbus_error_free(&err);
	} else {
		DBusMessage *message;

		if (!call->agent)
			goto fail;

		if (register_agent_records(call->agent->records) < 0)
			goto fail;

		/* Send a signal to indicate that the service started properly */
		message = dbus_message_new_signal(dbus_message_get_path(call->msg),
						"org.bluez.Service",
						"Started");

		send_message_and_unref(call->conn, message);

		call->agent->running = SERVICE_RUNNING;
	}
fail:
	dbus_message_unref(agent_reply);
	dbus_pending_call_unref(pcall);
}

static DBusHandlerResult register_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *name, *description;
	DBusHandlerResult result;
	DBusMessage *message;
	int err;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &description,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	err = register_service_agent(conn, dbus_message_get_sender(msg),
					path, name, description);

	if (err < 0) {
		if (err == -EADDRNOTAVAIL)
			return error_service_already_exists(conn, msg);

		return error_failed(conn, msg, -err);
	}

	/* Report that a new service was registered */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
					"ServiceRegistered");

	dbus_message_append_args(message, DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);

	send_message_and_unref(conn, message);

	result = send_message_and_unref(conn, dbus_message_new_method_return(msg));

	dbus_connection_flush(conn);

	/* If autostart feature is enabled: send the Start message to the service agent */
	if (autostart) {
		DBusPendingCall *pending;
		struct service_agent *agent;
		struct service_call *call;

		message = dbus_message_new_method_call(NULL, path,
				"org.bluez.ServiceAgent", "Start");

		dbus_message_set_destination(message, dbus_message_get_sender(msg));

		if (dbus_connection_send_with_reply(conn, message, &pending, START_REPLY_TIMEOUT) == FALSE) {
			dbus_message_unref(message);
			return result;
		}

		dbus_connection_flush(conn);

		dbus_connection_get_object_path_data(conn, path, (void *) &agent);

		call = service_call_new(conn, message, agent);
		dbus_message_unref(message);
		if (!call)
			return result;

		dbus_pending_call_set_notify(pending, autostart_reply, call, service_call_free);
	}

	return result;
}

static DBusHandlerResult unregister_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *message;
	const char *path;
	int err;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	err = unregister_service_agent(conn,
				dbus_message_get_sender(msg), path);
	if (err < 0) {
		/* Only the owner can unregister it */
		if (err == -EPERM)
			return error_not_authorized(conn, msg);

		return error_failed(conn, msg, -err);
	}

	/* Report that the service was unregistered */
	message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
					"ServiceUnregistered");
	dbus_message_append_args(message, DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);
	send_message_and_unref(conn, message);

	return send_message_and_unref(conn, dbus_message_new_method_return(msg));
}

static sdp_buf_t *service_record_extract(DBusMessageIter *iter)
{
	sdp_buf_t *sdp_buf;
	const uint8_t *buff;
	int len = -1;

	dbus_message_iter_get_fixed_array(iter, &buff, &len);
	if (len < 0)
		return NULL;

	sdp_buf = malloc(sizeof(sdp_buf_t));
	if (!sdp_buf)
		return NULL;

	memset(sdp_buf, 0, sizeof(sdp_buf_t));
	sdp_buf->data = malloc(len);
	sdp_buf->data_size = len;
	sdp_buf->buf_size = len;
	memcpy(sdp_buf->data, buff, len);

	return sdp_buf;
}

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service_agent *agent;
	DBusMessageIter iter, array_iter;
	DBusMessage *reply;
	struct binary_record *rec;
	const char *path;
	int err;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	/* Check if it is an array of bytes */
	if (strcmp(dbus_message_get_signature(msg), "say"))
		return error_invalid_arguments(conn, msg);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &path);

	if (!dbus_connection_get_object_path_data(conn, path,
						(void *) &agent)) {
		/* If failed the path is invalid! */
		return error_invalid_arguments(conn, msg);
	}

	if (!agent || strcmp(dbus_message_get_sender(msg), agent->id))
		return error_not_authorized(conn, msg);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array_iter);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	rec = binary_record_new();
	if (!rec)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	rec->buf = service_record_extract(&array_iter);
	if (!rec->buf) {
		binary_record_free(rec);
		dbus_message_unref(reply);
		return error_invalid_arguments(conn, msg);
	}

	/* Assign a new handle */
	rec->ext_handle = next_handle++;

	if (agent->running) {
		uint32_t handle = 0;

		if (register_sdp_record(rec->buf->data,	rec->buf->data_size, &handle) < 0) {
			err = errno;
			error("Service record registration failed: %s (%d)",
							strerror(err), err);
			goto fail;
		}

		rec->handle = handle;
	}

	agent->records = g_slist_append(agent->records, rec);

	dbus_message_append_args(reply,
				DBUS_TYPE_UINT32, &rec->ext_handle,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);

fail:
	binary_record_free(rec);
	dbus_message_unref(reply);

	return error_failed(conn, msg, err);
}

static DBusHandlerResult add_service_record_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service_agent *agent;
	DBusMessage *reply;
	struct binary_record *rec;
	sdp_record_t *sdp_rec;
	const char *path;
	const char *record;
	int err;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &record,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (!dbus_connection_get_object_path_data(conn, path,
						(void *) &agent)) {
		/* If failed the path is invalid! */
		return error_invalid_arguments(conn, msg);
	}

	if (!agent || strcmp(dbus_message_get_sender(msg), agent->id))
		return error_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	sdp_rec = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_rec) {
		error("Parsing of XML service record failed");
		dbus_message_unref(reply);
		return error_invalid_arguments(conn, msg);
	}

        /* TODO: Is this correct? We remove the record handle attribute
	   (if it exists) so SDP server assigns a new one */
        sdp_attr_remove(sdp_rec, 0x0);

	rec = binary_record_new();
	if (!rec) {
		sdp_record_free(sdp_rec);
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	rec->buf = malloc(sizeof(sdp_buf_t));

	if (!rec->buf) {
		sdp_record_free(sdp_rec);
		binary_record_free(rec);
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* Generate binary record */
	if (sdp_gen_record_pdu(sdp_rec, rec->buf) != 0) {
		sdp_record_free(sdp_rec);
		binary_record_free(rec);
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	sdp_record_free(sdp_rec);

	/* Assign a new handle */
	rec->ext_handle = next_handle++;

	if (agent->running) {
		uint32_t handle = 0;

		if (register_sdp_record(rec->buf->data,	rec->buf->data_size, &handle) < 0) {
			err = errno;
			error("Service record registration failed: %s (%d)",
							strerror(err), err);
			goto fail;
		}

		rec->handle = handle;
	}

	agent->records = g_slist_append(agent->records, rec);

	dbus_message_append_args(reply,
				DBUS_TYPE_UINT32, &rec->ext_handle,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);

fail:
	binary_record_free(rec);
	dbus_message_unref(reply);

	return error_failed(conn, msg, err);
}

static DBusHandlerResult remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service_agent *agent;
	struct binary_record *rec;
	DBusMessage *reply;
	GSList *l;
	const char *path;
	uint32_t handle;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_UINT32, &handle,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (!dbus_connection_get_object_path_data(conn, path,
						(void *) &agent)) {
		/* If failed the path is invalid! */
		return error_invalid_arguments(conn, msg);
	}

	if (!agent || strcmp(dbus_message_get_sender(msg), agent->id))
		return error_not_authorized(conn, msg);


	l = g_slist_find_custom(agent->records, &handle, (GCompareFunc) binary_record_cmp);
	if (!l)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	rec = l->data;
	agent->records = g_slist_remove(agent->records, rec);

	/* If the service agent is running: remove it from the from sdpd */
	if (agent->running && rec->handle != 0xffffffff) {
		if (unregister_sdp_record(rec->handle) < 0) {
			error("Service record unregistration failed: %s (%d)",
							strerror(errno), errno);
		}
	}

	binary_record_free(rec);

	return send_message_and_unref(conn, reply);
}

static struct service_data methods[] = {
	{ "InterfaceVersion",		interface_version		},
	{ "DefaultAdapter",		default_adapter			},
	{ "FindAdapter",		find_adapter			},
	{ "ListAdapters",		list_adapters			},
	{ "ListServices",		list_services			},
	{ "RegisterService",		register_service		},
	{ "UnregisterService",		unregister_service		},
	{ "AddServiceRecord",		add_service_record		},
	{ "AddServiceRecordFromXML", 	add_service_record_xml		},
	{ "RemoveServiceRecord",	remove_service_record		},
	{ NULL, NULL }
};

DBusHandlerResult handle_manager_method(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	service_handler_func_t handler;
	const char *iface, *path, *name;

	iface = dbus_message_get_interface(msg);
	path = dbus_message_get_path(msg);
	name = dbus_message_get_member(msg);

	if ((strcmp(BASE_PATH, path)) && !strcmp(iface, "org.bluez.ServiceAgent"))
		return error_unknown_method(conn, msg);

	if (strcmp(BASE_PATH, path))
		return error_no_such_adapter(conn, msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
					!strcmp("Introspect", name)) {
		return simple_introspect(conn, msg, data);
	} else if (!strcmp(iface, MANAGER_INTERFACE)) {
		handler = find_service_handler(methods, msg);
		if (handler)
			return handler(conn, msg, data);
		else
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(iface, SECURITY_INTERFACE))
		return handle_security_method(conn, msg, data);

	return error_unknown_method(conn, msg);
}

int get_default_adapter(void)
{
	return default_adapter_id;
}

void set_default_adapter(int new_default)
{
	default_adapter_id = new_default;
}
