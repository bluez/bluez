/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <gdbus.h>

#include "sdpd.h"
#include "sdp-xml.h"
#include "plugin.h"
#include "adapter.h"
#include "error.h"
#include "logging.h"

#define SERVICE_INTERFACE "org.bluez.Service"

static DBusConnection *connection = NULL;
static GSList *records = NULL;

struct record_data {
	uint32_t handle;
	char *sender;
	guint listener_id;
};

struct context_data {
	sdp_record_t *record;
	sdp_data_t attr_data;
	struct sdp_xml_data *stack_head;
	uint16_t attr_id;
};

static int compute_seq_size(sdp_data_t *data)
{
	int unit_size = data->unitSize;
	sdp_data_t *seq = data->val.dataseq;

	for (; seq; seq = seq->next)
		unit_size += seq->unitSize;

	return unit_size;
}

static void element_start(GMarkupParseContext *context,
		const gchar *element_name, const gchar **attribute_names,
		const gchar **attribute_values, gpointer user_data, GError **err)
{
	struct context_data *ctx_data = user_data;

	if (!strcmp(element_name, "record"))
		return;

	if (!strcmp(element_name, "attribute")) {
		int i;
		for (i = 0; attribute_names[i]; i++) {
			if (!strcmp(attribute_names[i], "id")) {
				ctx_data->attr_id = strtol(attribute_values[i], 0, 0);
				break;
			}
		}
		debug("New attribute 0x%04x", ctx_data->attr_id);
		return;
	}

	if (ctx_data->stack_head) {
		struct sdp_xml_data *newelem = sdp_xml_data_alloc();
		newelem->next = ctx_data->stack_head;
		ctx_data->stack_head = newelem;
	} else {
		ctx_data->stack_head = sdp_xml_data_alloc();
		ctx_data->stack_head->next = NULL;
	}

	if (!strcmp(element_name, "sequence"))
		ctx_data->stack_head->data = sdp_data_alloc(SDP_SEQ8, NULL);
	else if (!strcmp(element_name, "alternate"))
		ctx_data->stack_head->data = sdp_data_alloc(SDP_ALT8, NULL);
	else {
		int i;
		/* Parse value, name, encoding */
		for (i = 0; attribute_names[i]; i++) {
			if (!strcmp(attribute_names[i], "value")) {
				int curlen = strlen(ctx_data->stack_head->text);
				int attrlen = strlen(attribute_values[i]);

				/* Ensure we're big enough */
				while ((curlen + 1 + attrlen) > ctx_data->stack_head->size) {
					sdp_xml_data_expand(ctx_data->stack_head);
				}

				memcpy(ctx_data->stack_head->text + curlen,
						attribute_values[i], attrlen);
				ctx_data->stack_head->text[curlen + attrlen] = '\0';
			}

			if (!strcmp(attribute_names[i], "encoding")) {
				if (!strcmp(attribute_values[i], "hex"))
					ctx_data->stack_head->type = 1;
			}

			if (!strcmp(attribute_names[i], "name")) {
				ctx_data->stack_head->name = strdup(attribute_values[i]);
			}
		}

		ctx_data->stack_head->data = sdp_xml_parse_datatype(element_name,
				ctx_data->stack_head, ctx_data->record);

		if (ctx_data->stack_head->data == NULL)
			error("Can't parse element %s", element_name);
	}
}

static void element_end(GMarkupParseContext *context,
		const gchar *element_name, gpointer user_data, GError **err)
{
	struct context_data *ctx_data = user_data;
	struct sdp_xml_data *elem;

	if (!strcmp(element_name, "record"))
		return;

	if (!strcmp(element_name, "attribute")) {
		if (ctx_data->stack_head && ctx_data->stack_head->data) {
			int ret = sdp_attr_add(ctx_data->record, ctx_data->attr_id,
							ctx_data->stack_head->data);
			if (ret == -1)
				debug("Trouble adding attribute\n");

			ctx_data->stack_head->data = NULL;
			sdp_xml_data_free(ctx_data->stack_head);
			ctx_data->stack_head = NULL;
		} else {
			debug("No data for attribute 0x%04x\n", ctx_data->attr_id);
		}
		return;
	}

	if (!strcmp(element_name, "sequence")) {
		ctx_data->stack_head->data->unitSize = compute_seq_size(ctx_data->stack_head->data);

		if (ctx_data->stack_head->data->unitSize > USHRT_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint32_t);
			ctx_data->stack_head->data->dtd = SDP_SEQ32;
		} else if (ctx_data->stack_head->data->unitSize > UCHAR_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint16_t);
			ctx_data->stack_head->data->dtd = SDP_SEQ16;
		} else {
			ctx_data->stack_head->data->unitSize += sizeof(uint8_t);
		}
	} else if (!strcmp(element_name, "alternate")) {
		ctx_data->stack_head->data->unitSize = compute_seq_size(ctx_data->stack_head->data);

		if (ctx_data->stack_head->data->unitSize > USHRT_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint32_t);
			ctx_data->stack_head->data->dtd = SDP_ALT32;
		} else if (ctx_data->stack_head->data->unitSize > UCHAR_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint16_t);
			ctx_data->stack_head->data->dtd = SDP_ALT16;
		} else {
			ctx_data->stack_head->data->unitSize += sizeof(uint8_t);
		}
	}

	if (ctx_data->stack_head->next && ctx_data->stack_head->data &&
					ctx_data->stack_head->next->data) {
		switch (ctx_data->stack_head->next->data->dtd) {
		case SDP_SEQ8:
		case SDP_SEQ16:
		case SDP_SEQ32:
		case SDP_ALT8:
		case SDP_ALT16:
		case SDP_ALT32:
			ctx_data->stack_head->next->data->val.dataseq =
				sdp_seq_append(ctx_data->stack_head->next->data->val.dataseq,
								ctx_data->stack_head->data);
			ctx_data->stack_head->data = NULL;
			break;
		}

		elem = ctx_data->stack_head;
		ctx_data->stack_head = ctx_data->stack_head->next;

		sdp_xml_data_free(elem);
	}
}

static GMarkupParser parser = {
	element_start, element_end, NULL, NULL, NULL
};

static sdp_record_t *sdp_xml_parse_record(const char *data, int size)
{
	GMarkupParseContext *ctx;
	struct context_data *ctx_data;
	sdp_record_t *record;

	ctx_data = malloc(sizeof(*ctx_data));
	if (!ctx_data)
		return NULL;

	record = sdp_record_alloc();
	if (!record) {
		free(ctx_data);
		return NULL;
	}

	memset(ctx_data, 0, sizeof(*ctx_data));
	ctx_data->record = record;

	ctx = g_markup_parse_context_new(&parser, 0, ctx_data, NULL);

	if (g_markup_parse_context_parse(ctx, data, size, NULL) == FALSE) {
		error("XML parsing error");
		g_markup_parse_context_free(ctx);
		sdp_record_free(record);
		free(ctx_data);
		return NULL;
	}

	g_markup_parse_context_free(ctx);

	free(ctx_data);

	return record;
}

static struct record_data *find_record(uint32_t handle, const char *sender)
{
	GSList *list;

	for (list = records; list; list = list->next) {
		struct record_data *data = list->data;
		if (handle == data->handle && !strcmp(sender, data->sender))
			return data;
	}

	return NULL;
}

static void exit_callback(void *user_data)
{
	struct record_data *user_record = user_data;

	debug("remove record");

	records = g_slist_remove(records, user_record);

	remove_record_from_server(user_record->handle);

	g_free(user_record->sender);
	g_free(user_record);
}

static inline DBusMessage *invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
}

static inline DBusMessage *not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
							"Not Available");
}

static inline DBusMessage *failed(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "Failed");
}

static inline DBusMessage *failed_strerror(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
			strerror(err));
}

static int add_xml_record(DBusConnection *conn, const char *sender,
			bdaddr_t *src, const char *record,
			dbus_uint32_t *handle)
{
	struct record_data *user_record;
	sdp_record_t *sdp_record;

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		return -EIO;
	}

	if (add_record_to_server(src, sdp_record) < 0) {
		error("Failed to register service record");
		sdp_record_free(sdp_record);
		return -EIO;
	}

	user_record = g_new0(struct record_data, 1);

	user_record->handle = sdp_record->handle;

	user_record->sender = g_strdup(sender);

	records = g_slist_append(records, user_record);

	user_record->listener_id = g_dbus_add_disconnect_watch(conn, sender,
					exit_callback, user_record, NULL);

	debug("listener_id %d", user_record->listener_id);

	*handle = user_record->handle;

	return 0;
}

static DBusMessage *update_record(DBusConnection *conn, DBusMessage *msg,
		bdaddr_t *src, dbus_uint32_t handle, sdp_record_t *sdp_record)
{
	int err;

	if (remove_record_from_server(handle) < 0) {
		sdp_record_free(sdp_record);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAvailable",
				"Not Available");
	}

	sdp_record->handle = handle;
	err = add_record_to_server(src, sdp_record);
	if (err < 0) {
		sdp_record_free(sdp_record);
		error("Failed to update the service record");
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(EIO));
	}

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_xml_record(DBusConnection *conn,
				DBusMessage *msg, bdaddr_t *src)
{
	struct record_data *user_record;
	sdp_record_t *sdp_record;
	const char *record;
	dbus_uint32_t handle;
	int len;

	if (dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &handle,
				DBUS_TYPE_STRING, &record,
				DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	len = (record ? strlen(record) : 0);
	if (len == 0)
		return invalid_arguments(msg);

	user_record = find_record(handle, dbus_message_get_sender(msg));
	if (!user_record)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAvailable",
				"Not Available");

	sdp_record = sdp_xml_parse_record(record, len);
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		sdp_record_free(sdp_record);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(EIO));
	}

	return update_record(conn, msg, src, handle, sdp_record);
}

static int remove_record(DBusConnection *conn, const char *sender,
			dbus_uint32_t handle)
{
	struct record_data *user_record;

	debug("remove record 0x%x", handle);

	user_record = find_record(handle, sender);
	if (!user_record)
		return -1;

	debug("listner_id %d", user_record->listener_id);

	g_dbus_remove_watch(conn, user_record->listener_id);

	exit_callback(user_record);

	return 0;
}

static DBusMessage *add_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	DBusMessage *reply;
	const char *sender, *record;
	dbus_uint32_t handle;
	bdaddr_t src;
	int err;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	sender = dbus_message_get_sender(msg);
	str2ba(adapter_get_address(adapter), &src);
	err = add_xml_record(conn, sender, &src, record, &handle);
	if (err < 0)
		return failed_strerror(msg, err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &handle,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *update_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	bdaddr_t src;

	str2ba(adapter_get_address(adapter), &src);

	return update_xml_record(conn, msg, &src);
}

static DBusMessage *remove_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	dbus_uint32_t handle;
	const char *sender;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &handle,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	sender = dbus_message_get_sender(msg);

	if (remove_record(conn, sender, handle) < 0)
		return not_available(msg);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *request_authorization(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	/* FIXME implement the request */

	return NULL;
}

static DBusMessage *cancel_authorization(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	/* FIXME implement cancel request */

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable service_methods[] = {
	{ "AddRecord",		"s",	"u",	add_service_record	},
	{ "UpdateRecord",	"us",	"",	update_service_record	},
	{ "RemoveRecord",	"u",	"",	remove_service_record	},
	{ "RequestAuthorization","su",	"",	request_authorization,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelAuthorization", "",	"",	cancel_authorization	},
	{ }
};

static void path_unregister(void *data)
{
	g_slist_foreach(records, (GFunc) exit_callback, NULL);
}

static int service_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	if (!g_dbus_register_interface(connection, path,
					SERVICE_INTERFACE,
					service_methods, NULL, NULL,
					adapter, path_unregister)) {
		error("D-Bus failed to register %s interface",
				SERVICE_INTERFACE);
		return -1;
	}

	info("Registered interface %s on path %s", SERVICE_INTERFACE, path);

	return 0;
}

static void service_remove(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	g_dbus_unregister_interface(connection, path, SERVICE_INTERFACE);
}

static struct btd_adapter_driver service_driver = {
	.name	= "service",
	.probe	= service_probe,
	.remove	= service_remove,
};

static int service_init(void)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	return btd_register_adapter_driver(&service_driver);
}

static void service_exit(void)
{
	btd_unregister_adapter_driver(&service_driver);

	dbus_connection_unref(connection);
}

BLUETOOTH_PLUGIN_DEFINE("service", service_init, service_exit)
