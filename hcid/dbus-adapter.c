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
#include <ctype.h>
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

static const char *major_cls[] = {
	"miscellaneous",
	"computer",
	"phone",
	"access point",
	"audio/video",
	"peripheral",
	"imaging",
	"wearable",
	"toy",
	"uncategorized"
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

static int check_address(const char *addr)
{
	char tmp[18];
	char *ptr = tmp;

	if (!addr)
		return -1;

	if (strlen(addr) != 17)
		return -1;

	memcpy(tmp, addr, 18);

	while (*ptr) {

		*ptr = toupper(*ptr);
		if (*ptr < '0'|| (*ptr > '9' && *ptr < 'A') || *ptr > 'F')
			return -1;

		ptr++;
		*ptr = toupper(*ptr);
		if (*ptr < '0'|| (*ptr > '9' && *ptr < 'A') || *ptr > 'F')
			return -1;

		ptr++;
		*ptr = toupper(*ptr);
		if (*ptr == 0)
			break;

		if (*ptr != ':')
			return -1;

		ptr++;
	}

	return 0;
}

static struct bonding_request_info *bonding_request_new(bdaddr_t *peer)
{
	struct bonding_request_info *bonding;
	
	bonding = malloc(sizeof(*bonding));

	if (!bonding)
		return NULL;

	memset(bonding, 0, sizeof(*bonding));

	bacpy(&bonding->bdaddr, peer);

	return bonding;
}

static DBusHandlerResult handle_dev_get_address_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	const char *paddr = dbus_data->address;
	DBusMessage *reply;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_version_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[20], *str_ptr = str;
	int err;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	err = get_device_version(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	err = get_device_revision(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	err = get_device_manufacturer(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	err = get_device_company(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

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
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_mode_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	const char* scan_mode;
	uint8_t hci_mode;
	const uint8_t current_mode = dbus_data->mode;
	int dd;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &scan_mode,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

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
			return error_failed(conn, msg, bt_error(status));
		}
	}

	hci_close_dev(dd);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_discoverable_to_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &dbus_data->discoverable_timeout,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_discoverable_to_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	uint32_t timeout;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_UINT32, &timeout,
				DBUS_TYPE_INVALID);
 
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (dbus_data->timeout_id) {
		g_timeout_remove(dbus_data->timeout_id);
		dbus_data->timeout_id = 0;
	}

	if ((timeout != 0) && (dbus_data->mode & SCAN_INQUIRY))
		dbus_data->timeout_id = g_timeout_add(timeout * 1000, discoverable_timeout_handler, dbus_data);

	dbus_data->discoverable_timeout = timeout;

	write_discoverable_timeout(dbus_data->address, timeout);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_is_connectable_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	const uint8_t hci_mode = dbus_data->mode;
	dbus_bool_t connectable = FALSE;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	if (hci_mode & SCAN_PAGE)
		connectable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	if (hci_mode & SCAN_INQUIRY)
		discoverable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &discoverable,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_is_connected_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError err;
	dbus_bool_t connected = FALSE;

	struct hci_dbus_data *dbus_data = data;
	struct slist *l = dbus_data->active_conn;

	const char *peer_addr;
	bdaddr_t peer_bdaddr;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(peer_addr, &peer_bdaddr);

	l = slist_find(l, &peer_bdaddr, active_conn_find_by_bdaddr);
	if (l)
		connected = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_list_connections_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	struct hci_dbus_data *dbus_data = data;
	struct slist *l = dbus_data->active_conn;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array_iter);

	while (l) {
		char *peer_addr;
		bdaddr_t tmp;
		struct active_conn_info *dev = l->data;

		baswap(&tmp, &dev->bdaddr); peer_addr = batostr(&tmp);

		dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &peer_addr);
		bt_free(peer_addr);

		l = l->next;
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_major_class_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *str_ptr = "computer";

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
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
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

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
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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
	DBusMessage *reply, *signal;
	DBusError err;
	bdaddr_t bdaddr;
	const char *minor;
	uint8_t cls[3];
	uint32_t dev_class = 0xFFFFFFFF;
	int i, dd;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &minor,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	/* FIXME: check if the major class is computer. If not, return UnsupportedMajorClass */

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

	signal = dev_signal_factory(dbus_data->dev_id, "MinorClassChanged",
						DBUS_TYPE_STRING, &minor,
						DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(conn, signal, NULL);
		dbus_connection_flush(conn);
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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	err = get_device_name(dbus_data->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_name_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	bdaddr_t bdaddr;
	char *str_ptr;
	int ecode;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &str_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (strlen(str_ptr) == 0) {
		error("Name change failed: Invalid parameter");
		return error_invalid_arguments(conn, msg);
	}

	hci_devba(dbus_data->dev_id, &bdaddr);

	write_local_name(&bdaddr, str_ptr);

	ecode = set_device_name(dbus_data->dev_id, str_ptr);
	if (ecode < 0)
		return error_failed(conn, msg, -ecode);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_version_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	const char *str_ver;
	char info_array[64], *info = info_array;
	int compid, ver, subver;
	uint8_t features;

	dbus_error_init(&err);

	memset(info_array, 0, 64);

	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/manufacturers", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) != 3) {
		/* corrupted file data */
		free(str);
		goto failed;
	}

	free(str);

	str_ver = lmp_vertostr(ver);

	/* default value */
	snprintf(info, 64, "Bluetooth %s", str_ver);

	snprintf(filename, PATH_MAX, "%s/%s/features", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		goto failed;

	/* check if the data is not corrupted */
	if (strlen(str) == 16) {
		/* Getting the third byte */
		features  = ((str[6] - 48) << 4) | (str[7] - 48);
		if (features & (LMP_EDR_ACL_2M | LMP_EDR_ACL_3M))
			snprintf(info, 64, "Bluetooth %s + EDR", str_ver);
	}

	free(str);

failed:

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &info,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_revision_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	char info_array[16], *info = info_array;
	int compid, ver, subver;

	dbus_error_init(&err);

	memset(info_array, 0, 16);

	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(filename, PATH_MAX, "%s/%s/manufacturers", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) == 3)
		snprintf(info, 16, "HCI 0x%X", subver);

	free(str);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &info,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_manufacturer_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	char info_array[64], *info = info_array;
	int compid, ver, subver;
	dbus_error_init(&err);

	memset(info_array, 0, 64);

	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/manufacturers", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) == 3)
		info = bt_compidtostr(compid);

	free(str);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &info,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_company_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError err;
	bdaddr_t bdaddr;
	char oui[9], *str_bdaddr, *tmp;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &str_bdaddr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	str2ba(str_bdaddr, &bdaddr);
	ba2oui(&bdaddr, oui);

	tmp = ouitocomp(oui);
	if (!tmp)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(tmp);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &tmp,
					DBUS_TYPE_INVALID);

	free(tmp);

	return send_reply_and_unref(conn, reply);
}

static int get_remote_class(DBusConnection *conn, DBusMessage *msg, void *data, uint32_t *class)
{
	struct hci_dbus_data *dbus_data = data;
	char *addr_peer;
	DBusError err;
	bdaddr_t local, peer;
	int ecode;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_peer,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		error_invalid_arguments(conn, msg);
		return -1;
	}

	if (check_address(addr_peer) < 0) {
		error_invalid_arguments(conn, msg);
		return -1;
	}

	str2ba(addr_peer, &peer);
	str2ba(dbus_data->address, &local);

	ecode = read_remote_class(&local, &peer, class);
	if (ecode < 0) {
		error_not_available(conn, msg);
		return -1;
	}

	return 0;
}

static DBusHandlerResult handle_dev_get_remote_major_class_req(DBusConnection *conn,
								DBusMessage *msg,
								void *data)
{
	DBusMessage *reply;
	const char *major_class;
	uint32_t class;

	if (get_remote_class(conn, msg, data, &class) < 0)
		return DBUS_HANDLER_RESULT_HANDLED;

	major_class = major_class_str(class);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &major_class,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_minor_class_req(DBusConnection *conn,
								DBusMessage *msg,
								void *data)
{
	DBusMessage *reply;
	const char *major_class;
	uint32_t class;

	if (get_remote_class(conn, msg, data, &class) < 0)
		return DBUS_HANDLER_RESULT_HANDLED;

	major_class = minor_class_str(class);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &major_class,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static void append_class_string(const char *class, DBusMessageIter *iter)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &class);
}

static DBusHandlerResult handle_dev_get_remote_service_cls_req(DBusConnection *conn,
								DBusMessage *msg,
								void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	struct slist *service_classes;
	uint32_t class;

	if (get_remote_class(conn, msg, data, &class) < 0)
		return DBUS_HANDLER_RESULT_HANDLED;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	service_classes = service_classes_str(class);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
	 					DBUS_TYPE_STRING_AS_STRING, &array_iter);

	slist_foreach(service_classes, (slist_func_t)append_class_string, &array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	slist_free(service_classes);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_remote_name_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	DBusError err;
	const char *peer_addr;
	bdaddr_t peer_bdaddr;
	char *str;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg);

	/* check if it is a unknown address */
	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, peer_addr);

	if (!str)
		return error_unknown_address(conn, msg);

	free(str);

	/* check if it is in the cache */
	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, peer_addr);

	if (str) {
		reply = dbus_message_new_method_return(msg);
		if (!reply) {
			free(str);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		/* send the cached name */
		dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
						DBUS_TYPE_INVALID);

		free(str);
		return send_reply_and_unref(conn, reply);
	}

	/* put the request name in the queue to resolve name */
	str2ba(peer_addr, &peer_bdaddr);
	disc_device_append(&dbus_data->disc_devices, &peer_bdaddr, NAME_PENDING);

	/* 
	 * if there is a discover process running, just queue the request.
	 * Otherwise, send the HCI cmd to get the remote name
	 */
	if (dbus_data->discover_state == STATE_IDLE) {
		if (!disc_device_req_name(dbus_data))
			dbus_data->discover_state = STATE_RESOLVING_NAMES;
	}

	return error_request_deferred(conn, msg);
}

static DBusHandlerResult handle_dev_get_remote_alias_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char str[249], *str_ptr = str, *addr_ptr;
	bdaddr_t bdaddr;
	int ecode;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(addr_ptr, &bdaddr);

	ecode = get_device_alias(dbus_data->dev_id, &bdaddr, str, sizeof(str));
	if (ecode < 0)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_set_remote_alias_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply, *signal;
	DBusError err;
	char *str_ptr, *addr_ptr, *find_ptr;
	bdaddr_t bdaddr;
	int ecode;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_STRING, &str_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if ((strlen(str_ptr) == 0) || (check_address(addr_ptr) < 0)) {
		error("Alias change failed: Invalid parameter");
		return error_invalid_arguments(conn, msg);
	}

	/* check if it is a unknown address */
	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);

	find_ptr = textfile_get(filename, addr_ptr);

	if (!find_ptr)
		return error_unknown_address(conn, msg);

	free(find_ptr);

	str2ba(addr_ptr, &bdaddr);

	ecode = set_device_alias(dbus_data->dev_id, &bdaddr, str_ptr);
	if (ecode < 0)
		return error_failed(conn, msg, -ecode);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	signal = dev_signal_factory(dbus_data->dev_id, "RemoteAliasChanged",
						DBUS_TYPE_STRING, &addr_ptr,
						DBUS_TYPE_STRING, &str_ptr,
						DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(conn, signal, NULL);
		dbus_connection_flush(conn);
		dbus_message_unref(signal);
	}

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_clear_remote_alias_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply, *signal;
	DBusError err;
	char *addr_ptr;
	bdaddr_t bdaddr;
	int ecode, had_alias = 1;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message argument:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0) {
		error("Alias clear failed: Invalid parameter");
		return error_invalid_arguments(conn, msg);
	}

	str2ba(addr_ptr, &bdaddr);

	ecode = get_device_alias(dbus_data->dev_id, &bdaddr, NULL, 0);
	if (ecode == -ENXIO) 
		had_alias = 0;

	ecode = set_device_alias(dbus_data->dev_id, &bdaddr, NULL);
	if (ecode < 0)
		return error_failed(conn, msg, -ecode);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (had_alias) {
		signal = dev_signal_factory(dbus_data->dev_id, "RemoteAliasCleared",
							DBUS_TYPE_STRING, &addr_ptr,
							DBUS_TYPE_INVALID);
		if (signal) {
			dbus_connection_send(conn, signal, NULL);
			dbus_connection_flush(conn);
			dbus_message_unref(signal);
		}
	}

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_last_seen_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(str);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	free(str);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_last_used_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/lastused", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(str);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	free(str);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_disconnect_remote_device_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError err;

	struct hci_dbus_data *dbus_data = data;
	struct slist *l = dbus_data->active_conn;

	const char *peer_addr;
	bdaddr_t peer_bdaddr;
	int dd;
	struct active_conn_info *dev;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(peer_addr, &peer_bdaddr);

	l = slist_find(l, &peer_bdaddr, active_conn_find_by_bdaddr);
	if (!l)
		return error_not_connected(conn, msg);

	dev = l->data;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	/* Send the HCI disconnect command */
	if (hci_disconnect(dd, dev->handle, HCI_OE_USER_ENDED_CONNECTION, 100) < 0) {
		error("Disconnect failed");
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	hci_close_dev(dd);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_reply_and_unref(conn, reply);

}

static DBusHandlerResult handle_dev_create_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct hci_request rq;
	create_conn_cp cc_cp;
	auth_requested_cp ar_cp;
	evt_cmd_status rp;
	DBusError err;
	char *peer_addr = NULL;
	char *str;
	struct hci_dbus_data *dbus_data = data;
	struct slist *l;
	bdaddr_t peer_bdaddr;
	int dd, disconnect;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(peer_addr, &peer_bdaddr);

	/* check if there is a pending bonding request */
	if (dbus_data->bonding)
		return error_bonding_in_progress(conn, msg);

	/* check if there is a pending discover */
	if (dbus_data->discover_state != STATE_IDLE || dbus_data->requestor_name)
		return error_discover_in_progress(conn, msg); 

	/* check if a link key already exists */
	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, peer_addr);
	if (str) {
		free(str);
		return error_bonding_already_exists(conn, msg);
	}

	/* check if the address belongs to the last seen cache */
	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);
	str = textfile_get(filename, peer_addr);
	if (!str)
		return error_unknown_address(conn, msg);

	free(str);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	memset(&rq, 0, sizeof(rq));
	memset(&rp, 0, sizeof(rp));

	rq.ogf    = OGF_LINK_CTL;
	rq.event = EVT_CMD_STATUS;
	rq.rparam = &rp;
	rq.rlen = EVT_CMD_STATUS_SIZE;

	/* check if there is an active connection */
	l = slist_find(dbus_data->active_conn, &peer_bdaddr, active_conn_find_by_bdaddr);

	if (!l) {
		memset(&cc_cp, 0, sizeof(cc_cp));
		/* create a new connection */
		bacpy(&cc_cp.bdaddr, &peer_bdaddr);
		cc_cp.pkt_type       = htobs(HCI_DM1);
		cc_cp.pscan_rep_mode = 0x02;
		cc_cp.clock_offset   = htobs(0x0000);
		cc_cp.role_switch    = 0x01;

		rq.ocf    = OCF_CREATE_CONN;
		rq.cparam = &cc_cp;
		rq.clen   = CREATE_CONN_CP_SIZE;
		disconnect = 1;
	} else {
		struct active_conn_info *dev = l->data;

		memset(&ar_cp, 0, sizeof(ar_cp));

		ar_cp.handle = dev->handle;
		rq.ocf    = OCF_AUTH_REQUESTED;
		rq.cparam = &ar_cp;
		rq.clen   = AUTH_REQUESTED_CP_SIZE;
		disconnect = 0;
	}

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Unable to send the HCI request: %s (%d)",
				strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	if (rp.status) {
		error("Failed with status 0x%02x", rp.status);
		hci_close_dev(dd);
		return error_failed(conn, msg, bt_error(rp.status));
	}

	dbus_data->bonding = bonding_request_new(&peer_bdaddr);
	dbus_data->bonding->disconnect = disconnect;
	dbus_data->bonding->rq = dbus_message_ref(msg);

	dbus_data->requestor_name = strdup(dbus_message_get_sender(msg));

	hci_close_dev(dd);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_dev_cancel_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct slist *l;
	DBusMessage *reply = NULL;
	DBusError err;
	bdaddr_t peer_bdaddr;
	const char *peer_addr;
	int dd = -1;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(peer_addr, &peer_bdaddr);

	/* check if there is a pending bonding request */
	if (!dbus_data->bonding || bacmp(&dbus_data->bonding->bdaddr, &peer_bdaddr)) {
		error("No bonding request pending.");
		return error_unknown_address(conn, msg);
	}

	if (strcmp(dbus_data->requestor_name, dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	l = slist_find(dbus_data->active_conn, &peer_bdaddr, active_conn_find_by_bdaddr);

	if (!l) {
		/* connection request is pending */
		struct hci_request rq;
		create_conn_cancel_cp cp;
		evt_cmd_status rp;

		memset(&rq, 0, sizeof(rq));
		memset(&cp, 0, sizeof(cp));
		memset(&rp, 0, sizeof(rp));

		bacpy(&cp.bdaddr, &dbus_data->bonding->bdaddr);

		rq.ogf     = OGF_LINK_CTL;
		rq.ocf     = OCF_CREATE_CONN_CANCEL;
		rq.rparam  = &rp;
		rq.rlen    = EVT_CMD_STATUS_SIZE;
		rq.event   = EVT_CMD_STATUS;
		rq.cparam  = &cp;
		rq.clen    = CREATE_CONN_CANCEL_CP_SIZE;

		if (hci_send_req(dd, &rq, 100) < 0) {
			error("Cancel bonding - unable to send the HCI request: %s (%d)",
			      strerror(errno), errno);
			hci_close_dev(dd);
			return error_failed(conn, msg, errno);
		}

		if (rp.status) {
			error("Cancel bonding - Failed with status 0x%02x", rp.status);
			hci_close_dev(dd);
			return error_failed(conn, msg, bt_error(rp.status));
		}

		dbus_data->bonding->cancel = dbus_message_ref(msg);
	} else {
		struct active_conn_info *cinfo = l->data;
		/* FIXME: if waiting remote PIN, which HCI cmd must be sent? */

		/* reply to cancel bonding */
		reply = dbus_message_new_method_return(msg);
		send_reply_and_unref(conn, reply);

		/* Reply to the create bonding request */
		error_authentication_canceled(conn, dbus_data->bonding->rq);

		/* disconnect from the remote device */
		if (dbus_data->bonding->disconnect) {
			if (hci_disconnect(dd, htobs(cinfo->handle), HCI_OE_USER_ENDED_CONNECTION, 1000) < 0)
				error("Disconnect failed");
		}

		bonding_request_free(dbus_data->bonding);
		dbus_data->bonding = NULL;
	}

	hci_close_dev(dd);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_dev_remove_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct slist *l;
	DBusMessage *reply;
	DBusMessage *signal;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	bdaddr_t bdaddr;
	int dd;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, dbus_data->address);

	/* textfile_del doesn't return an error when the key is not found */
	str = textfile_get(filename, addr_ptr);
	if (!str) {
		hci_close_dev(dd);
		return error_bonding_does_not_exist(conn, msg);
	}

	free(str);

	/* Delete the link key from storage */
	if (textfile_del(filename, addr_ptr) < 0) {
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	str2ba(addr_ptr, &bdaddr);

	/* Delete the link key from the Bluetooth chip */
	hci_delete_stored_link_key(dd, &bdaddr, 0, 1000);

	/* find the connection */
	l = slist_find(dbus_data->active_conn, &bdaddr, active_conn_find_by_bdaddr);
	if (l) {
		struct active_conn_info *con = l->data;
		/* Send the HCI disconnect command */
		if (hci_disconnect(dd, htobs(con->handle), HCI_OE_USER_ENDED_CONNECTION, 1000) < 0) {
			error("Disconnect failed");
			hci_close_dev(dd);
			return error_failed(conn, msg, errno);
		}
	}

	/* FIXME: which condition must be verified before send the signal */
	signal = dev_signal_factory(dbus_data->dev_id, "BondingRemoved",
					DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(conn, signal, NULL);
		dbus_connection_flush(conn);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_has_bonding_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	dbus_bool_t result;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, dbus_data->address);

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

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, dbus_data->address);

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
	DBusMessage *reply;
	DBusError err;
	bdaddr_t local, peer;
	char *addr_ptr;
	uint8_t length;
	int len;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

	str2ba(dbus_data->address, &local);

	str2ba(addr_ptr, &peer);

	len = read_pin_length(&local, &peer);
	if (len < 0)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);

	length = len;

	dbus_message_append_args(reply, DBUS_TYPE_BYTE, &length,
					DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_get_encryption_key_size_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusError err;
	bdaddr_t bdaddr;
	char *addr_ptr;
	uint8_t size;
	int val;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg);

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
	const char *method;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	uint8_t length = 8, num_rsp = 0;
	uint32_t lap = 0x9e8b33;
	int dd;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	if (dbus_data->discover_state != STATE_IDLE)
		return error_discover_in_progress(conn, msg);

	if (dbus_data->bonding)
		return error_bonding_in_progress(conn, msg);

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
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	if (rp.status) {
		error("Failed with status 0x%02x", rp.status);
		hci_close_dev(dd);
		return error_failed(conn, msg, bt_error(rp.status));
	}

	method = dbus_message_get_member(msg);
	if (strcmp("DiscoverDevicesWithoutNameResolving", method) == 0)
		dbus_data->discover_type = WITHOUT_NAME_RESOLVING;
	else 
		dbus_data->discover_type = RESOLVE_NAMES;
		
	dbus_data->requestor_name = strdup(dbus_message_get_sender(msg));

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult handle_dev_cancel_discovery_req(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	const char *requestor_name;
	const struct discovered_dev_info *dev;
	struct hci_request rq;
	remote_name_req_cancel_cp cp;
	struct hci_dbus_data *dbus_data = data;
	uint8_t status = 0x00;
	int dd = -1;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg);

	requestor_name = dbus_message_get_sender(msg);

	/* is there discover pending? */
	if (dbus_data->discover_state != STATE_DISCOVER &&
		dbus_data->discover_state != STATE_RESOLVING_NAMES)
		return error_not_authorized(conn, msg); /* FIXME: find a better error name */

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
	case STATE_RESOLVING_NAMES:
		/* get the first element */
		dev = (struct discovered_dev_info *) (dbus_data->disc_devices)->data;

		bacpy(&cp.bdaddr, &dev->bdaddr);

		rq.ocf = OCF_REMOTE_NAME_REQ_CANCEL;
		rq.cparam = &cp;
		rq.clen = REMOTE_NAME_REQ_CANCEL_CP_SIZE;
		rq.event = EVT_CMD_STATUS;
		break;
	default: /* STATE_DISCOVER */
		rq.ocf = OCF_INQUIRY_CANCEL;
		break;
	}

	if (hci_send_req(dd, &rq, 100) < 0) {
		error("Sending command failed: %s (%d)", strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed(conn, msg, errno);
	}

	hci_close_dev(dd);

	if (status) {
		error("Cancel failed with status 0x%02x", status);
		return error_failed(conn, msg, bt_error(status));
	}

	slist_foreach(dbus_data->disc_devices, disc_device_info_free, NULL);
	slist_free(dbus_data->disc_devices);
	dbus_data->disc_devices = NULL;

	if (dbus_data->requestor_name) {
		free(dbus_data->requestor_name);
		dbus_data->requestor_name = NULL;
	}

	reply = dbus_message_new_method_return(msg);

	return send_reply_and_unref(conn, reply);
}

const char *major_class_str(uint32_t class)
{
	uint8_t index = (class >> 8) & 0x1F;

	if (index > 8)
		return major_cls[9]; /* uncategorized */

	return major_cls[index];
}

const char *minor_class_str(uint32_t class)
{
	uint8_t major_index = (class >> 8) & 0x1F;
	uint8_t minor_index = (class >> 2) & 0x3F;

	switch (major_index) {
	case 1: /* computer */
		return computer_minor_cls[minor_index];
	case 2: /* phone */
		return phone_minor_cls[minor_index];
	}

	return "";
}

struct slist *service_classes_str(uint32_t class)
{
	uint8_t services = class >> 16;
	struct slist *l = NULL;
	int i;

	for (i = 0; i < (sizeof(service_cls) / sizeof(*service_cls)); i++) {
		if (!(services & (1 << i)))
			continue;

		l = slist_append(l, (void *)service_cls[i]);
	}

	return l;
}

static struct service_data dev_services[] = {
	{ "GetAddress",					handle_dev_get_address_req		},
	{ "GetVersion",					handle_dev_get_version_req		},
	{ "GetRevision",				handle_dev_get_revision_req		},
	{ "GetManufacturer",				handle_dev_get_manufacturer_req		},
	{ "GetCompany",					handle_dev_get_company_req		},
	{ "GetMode",					handle_dev_get_mode_req			},
	{ "SetMode",					handle_dev_set_mode_req			},
	{ "GetDiscoverableTimeout",			handle_dev_get_discoverable_to_req	},
	{ "SetDiscoverableTimeout",			handle_dev_set_discoverable_to_req	},
	{ "IsConnectable",				handle_dev_is_connectable_req		},
	{ "IsDiscoverable",				handle_dev_is_discoverable_req		},
	{ "IsConnected",				handle_dev_is_connected_req		},
	{ "ListConnections",				handle_dev_list_connections_req		},
	{ "GetMajorClass",				handle_dev_get_major_class_req		},
	{ "ListAvailableMinorClasses",			handle_dev_list_minor_classes_req	},
	{ "GetMinorClass",				handle_dev_get_minor_class_req		},
	{ "SetMinorClass",				handle_dev_set_minor_class_req		},
	{ "GetServiceClasses",				handle_dev_get_service_classes_req	},
	{ "GetName",					handle_dev_get_name_req			},
	{ "SetName",					handle_dev_set_name_req			},
	
	{ "GetRemoteVersion",				handle_dev_get_remote_version_req	},
	{ "GetRemoteRevision",				handle_dev_get_remote_revision_req	},
	{ "GetRemoteManufacturer",			handle_dev_get_remote_manufacturer_req	},
	{ "GetRemoteCompany",				handle_dev_get_remote_company_req	},
	{ "GetRemoteMajorClass",			handle_dev_get_remote_major_class_req	},
	{ "GetRemoteMinorClass",			handle_dev_get_remote_minor_class_req	},
	{ "GetRemoteServiceClasses",			handle_dev_get_remote_service_cls_req	},
	{ "GetRemoteName",				handle_dev_get_remote_name_req		},
	{ "GetRemoteAlias",				handle_dev_get_remote_alias_req		},
	{ "SetRemoteAlias",				handle_dev_set_remote_alias_req		},
	{ "ClearRemoteAlias",				handle_dev_clear_remote_alias_req	},

	{ "LastSeen",					handle_dev_last_seen_req		},
	{ "LastUsed",					handle_dev_last_used_req		},

	{ "DisconnectRemoteDevice",			handle_dev_disconnect_remote_device_req	},

	{ "CreateBonding",				handle_dev_create_bonding_req		},
	{ "CancelBonding",				handle_dev_cancel_bonding_req		},
	{ "RemoveBonding",				handle_dev_remove_bonding_req		},
	{ "HasBonding",					handle_dev_has_bonding_req		},
	{ "ListBondings",				handle_dev_list_bondings_req		},
	{ "GetPinCodeLength",				handle_dev_get_pin_code_length_req	},
	{ "GetEncryptionKeySize",			handle_dev_get_encryption_key_size_req	},

	{ "DiscoverDevices",				handle_dev_discover_devices_req		},
	{ "DiscoverDevicesWithoutNameResolving",	handle_dev_discover_devices_req		},
	{ "CancelDiscovery",				handle_dev_cancel_discovery_req		},

	{ NULL, NULL }
};

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const char *iface, *name;

	iface = dbus_message_get_interface(msg);
	name = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
					!strcmp("Introspect", name)) {
		return simple_introspect(conn, msg, data);
	} else if (!strcmp(ADAPTER_INTERFACE, iface)) {
		service_handler_func_t handler;

		handler = find_service_handler(dev_services, msg);

		if (handler)
			return handler(conn, msg, data);
		else
			return error_unknown_method(conn, msg);
	} else if (!strcmp(SECURITY_INTERFACE, iface))
		return handle_security_method(conn, msg, data);
	else if (!strcmp(RFCOMM_INTERFACE, iface))
		return handle_rfcomm_method(conn, msg, data);
	else if (!strcmp(SDP_INTERFACE, iface))
		return handle_sdp_method(conn, msg, data);
	else
		return error_unknown_method(conn, msg);
}
