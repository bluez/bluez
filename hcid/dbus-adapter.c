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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"

#include "textfile.h"
#include "oui.h"
#include "list.h"

static const char *service_cls[] = {
	"positioning",
	"networking",
	"rendering",
	"capturing",
	"object transfer",
	"audio",
	"telephony",
	"information"
};

static const char *computer_minor_cls[] = {
	"uncategorized",
	"desktop",
	"server",
	"laptop",
	"handheld",
	"palm",
	"wearable"
};

static const char *phone_minor_cls[] = {
	"uncategorized",
	"cellular",
	"cordless",
	"smart phone",
	"modem",
	"isdn"
};

static DBusHandlerResult handle_dev_get_address_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[18], *str_ptr = str;
	int err;

	err = get_device_address(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_version_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[20], *str_ptr = str;
	int err;

	err = get_device_version(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_revision_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	err = get_device_revision(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_manufacturer_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	err = get_device_manufacturer(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_company_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	err = get_device_company(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_mode_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	const uint8_t hci_mode = dbus_data->mode;
	const char *scan_mode;

	switch (hci_mode) {
	case SCAN_DISABLED:
		scan_mode = MODE_OFF;
		break;
	case SCAN_PAGE:
		scan_mode = MODE_CONNECTABLE;
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):
		scan_mode = MODE_DISCOVERABLE;
		break;
	case SCAN_INQUIRY:
	/* inquiry scan mode is not handled, return unknown */
	default:
		/* reserved */
		scan_mode = MODE_UNKNOWN;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_mode_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	const char* scan_mode;
	uint8_t hci_mode;
	const uint8_t current_mode = dbus_data->mode;
	int dd;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &scan_mode,
							DBUS_TYPE_INVALID);

	if (!scan_mode)
		return error_invalid_arguments(conn, msg);

	if (strcasecmp(MODE_OFF, scan_mode) == 0)
		hci_mode = SCAN_DISABLED;
	else if (strcasecmp(MODE_CONNECTABLE, scan_mode) == 0)
		hci_mode = SCAN_PAGE;
	else if (strcasecmp(MODE_DISCOVERABLE, scan_mode) == 0)
		hci_mode = (SCAN_PAGE | SCAN_INQUIRY);
	else
		return error_invalid_arguments(conn, msg);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	/* Check if the new requested mode is different from the current */
	if (current_mode != hci_mode) {
		struct hci_request rq;
		uint8_t status = 0;

		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_WRITE_SCAN_ENABLE;
		rq.cparam = &hci_mode;
		rq.clen   = sizeof(hci_mode);
		rq.rparam = &status;
		rq.rlen   = sizeof(status);

		if (hci_send_req(dd, &rq, 100) < 0) {
			error("Sending write scan enable command failed: %s (%d)",
							strerror(errno), errno);
			hci_close_dev(dd);
			return error_failed(conn, msg, errno);
		}

		if (status) {
			error("Setting scan enable failed with status 0x%02x", status);
			hci_close_dev(dd);
			return error_failed(conn, msg, status);
		}
	}

	hci_close_dev(dd);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_discoverable_to_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &dbus_data->discoverable_timeout,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_discoverable_to_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	uint32_t timeout;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &timeout);

	dbus_data->discoverable_timeout = timeout;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_is_connectable_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	const uint8_t hci_mode = dbus_data->mode;
	dbus_bool_t connectable = FALSE;

	if (hci_mode & SCAN_PAGE)
		connectable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connectable,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_is_discoverable_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	const uint8_t hci_mode = dbus_data->mode;
	dbus_bool_t discoverable = FALSE;

	if (hci_mode & SCAN_INQUIRY)
		discoverable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &discoverable,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_major_class_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *str_ptr = "computer";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	/*FIXME: Check the real device major class */
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_list_minor_classes_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const char **minor_ptr;
	uint8_t cls[3];
	uint8_t major_class;
	int dd, size, i;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	hci_close_dev(dd);

	major_class = cls[1] & 0x1F;

	switch (major_class) {
	case 1: /* computer */
		minor_ptr = computer_minor_cls;
		size = sizeof(computer_minor_cls) / sizeof(*computer_minor_cls);
		break;
	case 2: /* phone */
		minor_ptr = phone_minor_cls;
		size = sizeof(phone_minor_cls) / sizeof(*phone_minor_cls);
		break;
	default:
		return error_unsupported_major_class(conn, msg);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					 	DBUS_TYPE_STRING_AS_STRING, &array_iter);
	for (i = 0; i < size; i++)
		dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &minor_ptr[i]);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_minor_class_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	const char *str_ptr = "";
	uint8_t cls[3];
	uint8_t minor_class;
	int dd;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, -errno);
	}

	hci_close_dev(dd);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	/* FIXME: Currently, only computer major class is supported */
	if ((cls[1] & 0x1f) != 1)
		goto failed;

	minor_class = cls[0] >> 2;

	/* Validate computer minor class */
	if (minor_class > (sizeof(computer_minor_cls) / sizeof(*computer_minor_cls)))
		goto failed;

	str_ptr = computer_minor_cls[minor_class];

failed:
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_minor_class_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusConnection *connection = get_dbus_connection();
	DBusMessageIter iter;
	DBusMessage *reply, *signal;
	bdaddr_t bdaddr;
	const char *minor;
	uint8_t cls[3];
	uint32_t dev_class = 0xFFFFFFFF;
	int i, dd;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &minor);

	if (!minor)
		return error_invalid_arguments(conn, msg);

	/* FIXME: currently, only computer minor classes are allowed */
	for (i = 0; i < sizeof(computer_minor_cls) / sizeof(*computer_minor_cls); i++)
		if (!strcasecmp(minor, computer_minor_cls[i])) {
			/* Remove the format type */
			dev_class = i << 2;
			break;
		}

	/* Check if it's a valid minor class */
	if (dev_class == 0xFFFFFFFF)
		return error_invalid_arguments(conn, msg);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	dev_class |= (cls[2] << 16) | (cls[1] << 8);

	cls[2] = 0x00;	/* no service classes */
	cls[1] = 0x01;	/* major class computer */
	cls[0] = (dev_class & 0xff);

	hci_devba(dbus_data->dev_id, &bdaddr);

	write_local_class(&bdaddr, cls);

	if (hci_write_class_of_dev(dd, dev_class, 2000) < 0) {
		error("Can't write class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	signal = dev_signal_factory(dbus_data->dev_id, "MinorClassChange",
						DBUS_TYPE_STRING, &minor,
						DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(connection, signal, NULL);
		dbus_connection_flush(connection);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_service_classes_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const char *str_ptr;
	uint8_t cls[3];
	int dd, i;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		error("Can't read class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (i = 0; i < (sizeof(service_cls) / sizeof(*service_cls)); i++) {
		if (cls[2] & (1 << i)) {
			str_ptr = service_cls[i];
			dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &str_ptr);
		}
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_name_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[249], *str_ptr = str;
	int err;

	err = get_device_name(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_name_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char *str_ptr;
	int err;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_ptr);

	if (strlen(str_ptr) == 0) {
		error("Name change failed: Invalid parameter");
		return error_invalid_arguments(conn, msg);
	}

	hci_devba(dbus_data->dev_id, &bdaddr);

	write_local_name(&bdaddr, str_ptr);

	err = set_device_name(dbus_data->dev_id, str_ptr);
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_version_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	return error_not_implemented(conn, msg);
}

static DBusHandlerResult handle_dev_get_remote_revision_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	return error_not_implemented(conn, msg);
}

static DBusHandlerResult handle_dev_get_remote_manufacturer_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr, *str;
	int compid;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/manufacturers", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_failed(conn, msg, ENXIO);

	compid = atoi(str);

	free(str);

	str = bt_compidtostr(compid);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_company_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char oui[9], *str_bdaddr, *tmp;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str_bdaddr,
							DBUS_TYPE_INVALID);


	str2ba(str_bdaddr, &bdaddr);
	ba2oui(&bdaddr, oui);

	tmp = ouitocomp(oui);
	if (!tmp)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(tmp);
		return error_out_of_memory(conn, msg);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &tmp,
					DBUS_TYPE_INVALID);

	free(tmp);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_name_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1], addr[18];
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	const char *str_bdaddr;
	char *name;
	int err;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str_bdaddr,
							DBUS_TYPE_INVALID);

	err = get_device_address(dbus_data->dev_id, addr, sizeof(addr));
	if (err < 0)
		return error_failed(conn, msg, -err);

	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, addr);

	name = textfile_get(filename, str_bdaddr);

	if (!name)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(name);
		return error_out_of_memory(conn, msg);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	free(name);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_alias_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char str[249], *str_ptr = str, *addr_ptr;
	bdaddr_t bdaddr;
	int err;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str2ba(addr_ptr, &bdaddr);

	err = get_device_alias(dbus_data->dev_id, &bdaddr, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_remote_alias_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusConnection *connection = get_dbus_connection();
	DBusMessageIter iter;
	DBusMessage *reply, *signal;
	char *str_ptr, *addr_ptr;
	bdaddr_t bdaddr;
	int err;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &str_ptr);

	if (strlen(str_ptr) == 0) {
		error("Alias change failed: Invalid parameter");
		return error_invalid_arguments(conn, msg);
	}

	str2ba(addr_ptr, &bdaddr);

	err = set_device_alias(dbus_data->dev_id, &bdaddr, str_ptr);
	if (err < 0)
		return error_failed(conn, msg, -err);

	signal = dev_signal_factory(dbus_data->dev_id, "RemoteAliasChanged",
						DBUS_TYPE_STRING, &addr_ptr,
						DBUS_TYPE_STRING, &str_ptr,
						DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(connection, signal, NULL);
		dbus_connection_flush(connection);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return error_out_of_memory(conn, msg);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_last_seen_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr, *str;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_failed(conn, msg, ENXIO);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(str);
		return error_out_of_memory(conn, msg);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	free(str);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_last_used_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr, *str;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/lastused", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_failed(conn, msg, ENXIO);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(str);
		return error_out_of_memory(conn, msg);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	free(str);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_create_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	DBusMessage *reply;
	char *str_bdaddr;
	struct hci_dbus_data *dbus_data = data;
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int dd, dev_id;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str_bdaddr,
							DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0)
		return error_failed(conn, msg, ENOTCONN);

	if (dbus_data->dev_id != dev_id)
		return error_failed(conn, msg, ENOTCONN);

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		hci_close_dev(dd);
		return error_out_of_memory(conn, msg);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;

	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		hci_close_dev(dd);
		free(cr);
		return error_failed(conn, msg, errno);
	}

	memset(&cp, 0, sizeof(cp));
	cp.handle = cr->conn_info->handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Unable to send authentication request: %s (%d)",
							strerror(errno), errno);
		hci_close_dev(dd);
		free(cr);
		return error_failed(conn, msg, errno);
	}

	reply = dbus_message_new_method_return(msg);

	free(cr);

	close(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_remove_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusConnection *connection = get_dbus_connection();
	DBusMessageIter iter;
	DBusMessage *reply;
	DBusMessage *signal;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr;
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int dd;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	/* Delete the link key from storage */
	textfile_del(filename, addr_ptr);

	str2ba(addr_ptr, &bdaddr);

	/* Delete the link key from the Bluetooth chip */
	hci_delete_stored_link_key(dd, &bdaddr, 0, 1000);

	/* Close active connections for the remote device */
	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		error("Can't allocate memory");
		hci_close_dev(dd);
		return error_out_of_memory(conn, msg);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		/* Ignore when there isn't active connections, return success */
		hci_close_dev(dd);
		free(cr);
		return send_reply_and_unref(conn, dbus_message_new_method_return(msg));
	}

	/* Send the HCI disconnect command */
	if (hci_disconnect(dd, htobs(cr->conn_info->handle), HCI_OE_USER_ENDED_CONNECTION, 1000) < 0) {
		error("Disconnect failed");
		free(cr);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	/* FIXME: which condition must be verified before send the signal */
	signal = dev_signal_factory(dbus_data->dev_id, "BondingRemoved",
					DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(connection, signal, NULL);
		dbus_connection_flush(connection);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);

	free(cr);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_has_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr, *str;
	dbus_bool_t result;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str = textfile_get(filename, addr_ptr);
	if (str) {
		result = TRUE;
		free(str);
	} else
		result = FALSE;

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &result,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_list_bondings_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	void do_append(char *key, char *value, void *data)
	{
		DBusMessageIter *iter = data;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);
	}

	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18];

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, addr);

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	textfile_foreach(filename, do_append, &array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_pin_code_length_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	bdaddr_t local, peer;
	char addr[18], *addr_ptr;
	uint8_t length;
	int len;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	str2ba(addr, &local);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str2ba(addr_ptr, &peer);

	len = read_pin_length(&local, &peer);
	if (len < 0)
		return error_failed(conn, msg, -len);

	reply = dbus_message_new_method_return(msg);

	length = len;

	dbus_message_append_args(reply, DBUS_TYPE_BYTE, &length,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_encryption_key_size_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char *addr_ptr;
	uint8_t size;
	int val;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str2ba(addr_ptr, &bdaddr);

	val = get_encryption_key_size(dbus_data->dev_id, &bdaddr);
	if (val < 0)
		return error_failed(conn, msg, -val);

	reply = dbus_message_new_method_return(msg);

	size = val;

	dbus_message_append_args(reply, DBUS_TYPE_BYTE, &size,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_discover_devices_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	const char *requestor_name;
	const char *method;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	uint8_t length = 8, num_rsp = 0;
	uint32_t lap = 0x9e8b33;
	int dd;

	if (dbus_data->requestor_name)
		return error_discover_in_progress(conn, msg);

	method = dbus_message_get_member(msg);
	if (strcmp("DiscoverDevicesWithoutNameResolving", method) == 0)
		dbus_data->discover_state = DISCOVER_RUNNING;
	else 
		dbus_data->discover_state = DISCOVER_RUNNING_WITH_NAMES;
		
	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	memset(&cp, 0, sizeof(cp));
	cp.lap[0]  = lap & 0xff;
	cp.lap[1]  = (lap >> 8) & 0xff;
	cp.lap[2]  = (lap >> 16) & 0xff;
	cp.length  = length;
	cp.num_rsp = num_rsp;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY;
	rq.cparam = &cp;
	rq.clen   = INQUIRY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Unable to start inquiry: %s (%d)",
							strerror(errno), errno);
		dbus_data->discover_state = DISCOVER_OFF;
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	requestor_name = dbus_message_get_sender(msg);
	dbus_data->requestor_name = strdup(requestor_name);

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_cancel_discovery_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	const char *requestor_name;
	bdaddr_t *addr;
	struct hci_request rq;
	remote_name_req_cancel_cp cp;
	struct hci_dbus_data *dbus_data = data;
	uint8_t status = 0x00;
	int dd = -1;

	requestor_name = dbus_message_get_sender(msg);

	/* is there discover pending? */
	if (!dbus_data->requestor_name)
		return error_not_authorized(conn, msg);

	/* only the discover requestor can cancel the inquiry process */
	if (strcmp(dbus_data->requestor_name, requestor_name))
		return error_not_authorized(conn, msg);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	memset(&rq, 0, sizeof(rq));
	memset(&cp, 0, sizeof(cp));
	rq.ogf    = OGF_LINK_CTL;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	switch (dbus_data->discover_state) {
	case DISCOVER_OFF:
		/* FIXME: */
		break;
	case RESOLVING_NAMES:
		/* get the first element */
		addr = (bdaddr_t *) (dbus_data->discovered_devices)->data;

		memcpy(&cp.bdaddr, addr, sizeof(bdaddr_t));

		rq.ocf = OCF_REMOTE_NAME_REQ_CANCEL;
		rq.cparam = &cp;
		rq.clen = REMOTE_NAME_REQ_CANCEL_CP_SIZE;
		rq.event = EVT_CMD_STATUS;
		break;
	case DISCOVER_RUNNING:
	case DISCOVER_RUNNING_WITH_NAMES:
		rq.ocf = OCF_INQUIRY_CANCEL;
		break;
	}

	slist_foreach(dbus_data->discovered_devices, discovered_device_free, NULL);
	slist_free(dbus_data->discovered_devices);
	dbus_data->discovered_devices = NULL;

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Sending command failed: %s (%d)",
		      strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	hci_close_dev(dd);

	if (status) {
		error("Cancel failed with status 0x%02x", status);
		return error_failed(conn, msg, status);
	}

	free(dbus_data->requestor_name);
	dbus_data->requestor_name = NULL;

	reply = dbus_message_new_method_return(msg);

	return send_reply_and_unref(conn, reply);
}

static struct service_data dev_services[] = {
	{ "GetAddress",					handle_dev_get_address_req,		},
	{ "GetVersion",					handle_dev_get_version_req,		},
	{ "GetRevision",				handle_dev_get_revision_req,		},
	{ "GetManufacturer",				handle_dev_get_manufacturer_req,	},
	{ "GetCompany",					handle_dev_get_company_req,		},
	{ "GetMode",					handle_dev_get_mode_req,		},
	{ "SetMode",					handle_dev_set_mode_req,		},
	{ "GetDiscoverableTimeout",			handle_dev_get_discoverable_to_req,	},
	{ "SetDiscoverableTimeout",			handle_dev_set_discoverable_to_req,	},
	{ "IsConnectable",				handle_dev_is_connectable_req,		},
	{ "IsDiscoverable",				handle_dev_is_discoverable_req,		},
	{ "GetMajorClass",				handle_dev_get_major_class_req,		},
	{ "ListAvailableMinorClasses",			handle_dev_list_minor_classes_req,	},
	{ "GetMinorClass",				handle_dev_get_minor_class_req,		},
	{ "SetMinorClass",				handle_dev_set_minor_class_req,		},
	{ "GetServicesClasses",				handle_dev_get_service_classes_req,	},
	{ "GetName",					handle_dev_get_name_req,		},
	{ "SetName",					handle_dev_set_name_req,		},
	
	{ "GetRemoteVersion",				handle_dev_get_remote_version_req,	},
	{ "GetRemoteRevision",				handle_dev_get_remote_revision_req,	},
	{ "GetRemoteManufacturer",			handle_dev_get_remote_manufacturer_req,	},
	{ "GetRemoteCompany",				handle_dev_get_remote_company_req,	},
	{ "GetRemoteName",				handle_dev_get_remote_name_req,		},
	{ "GetRemoteAlias",				handle_dev_get_remote_alias_req,	},
	{ "SetRemoteAlias",				handle_dev_set_remote_alias_req,	},

	{ "LastSeen",					handle_dev_last_seen_req,		},
	{ "LastUsed",					handle_dev_last_used_req,		},

	{ "CreateBonding",				handle_dev_create_bonding_req,		},
	{ "RemoveBonding",				handle_dev_remove_bonding_req,		},
	{ "HasBonding",					handle_dev_has_bonding_req,		},
	{ "ListBondings",				handle_dev_list_bondings_req,		},
	{ "GetPinCodeLength",				handle_dev_get_pin_code_length_req,	},
	{ "GetEncryptionKeySize",			handle_dev_get_encryption_key_size_req,	},

	{ "DiscoverDevices",				handle_dev_discover_devices_req,	},
	{ "DiscoverDevicesWithoutNameResolving",	handle_dev_discover_devices_req	},
	{ "CancelDiscovery",				handle_dev_cancel_discovery_req,	},

	{ NULL, NULL }
};

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	const char *iface;

	iface = dbus_message_get_interface(msg);

	if (dbus_data->path_id == ADAPTER_ROOT_ID) {
		/* Adapter is down (path unregistered) or the path is wrong */
		return error_no_such_adapter(conn, msg);
	}

	if (!strcmp(ADAPTER_INTERFACE, iface)) {
		service_handler_func_t handler;

		handler = find_service_handler(dev_services, msg);

		if (handler)
			return handler(conn, msg, data);
	}
	else if (!strcmp(SECURITY_INTERFACE, iface))
		return handle_security_method(conn, msg, data);
	else if (!strcmp(RFCOMM_INTERFACE, iface))
		return handle_rfcomm_method(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
