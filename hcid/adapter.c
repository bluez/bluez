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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"

#include "adapter.h"
#include "device.h"

#include "textfile.h"
#include "oui.h"
#include "dbus-common.h"
#include "dbus-helper.h"
#include "dbus-hci.h"
#include "dbus-sdp.h"
#include "dbus-database.h"
#include "dbus-error.h"
#include "error.h"
#include "glib-helper.h"
#include "logging.h"
#include "agent.h"

#define NUM_ELEMENTS(table) (sizeof(table)/sizeof(const char *))

struct create_device_req {
	char		address[18];	/* Destination address */
	DBusConnection	*conn;		/* Connection reference */
	DBusMessage	*msg;		/* Message reference */
	guint		id;		/* Listener id */
	char		*agent_path;	/* Agent object path */
};

struct mode_req {
	struct adapter	*adapter;
	DBusConnection	*conn;		/* Connection reference */
	DBusMessage	*msg;		/* Message reference */
	char		*mode;		/* Requested mode */
};

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

static const char *access_point_minor_cls[] = {
	"fully",
	"1-17 percent",
	"17-33 percent",
	"33-50 percent",
	"50-67 percent",
	"67-83 percent",
	"83-99 percent",
	"not available"
};

static const char *audio_video_minor_cls[] = {
	"uncategorized",
	"headset",
	"handsfree",
	"unknown",
	"microphone",
	"loudspeaker",
	"headphones",
	"portable audio",
	"car audio",
	"set-top box",
	"hifi audio",
	"vcr",
	"video camera",
	"camcorder",
	"video monitor",
	"video display and loudspeaker",
	"video conferencing",
	"unknown",
	"gaming/toy"
};

static const char *peripheral_minor_cls[] = {
	"uncategorized",
	"keyboard",
	"pointing",
	"combo"
};

#if 0
static const char *peripheral_2_minor_cls[] = {
	"uncategorized",
	"joystick",
	"gamepad",
	"remote control",
	"sensing",
	"digitizer tablet",
	"card reader"
};
#endif

static const char *imaging_minor_cls[] = {
	"display",
	"camera",
	"scanner",
	"printer"
};

static const char *wearable_minor_cls[] = {
	"wrist watch",
	"pager",
	"jacket",
	"helmet",
	"glasses"
};

static const char *toy_minor_cls[] = {
	"robot",
	"vehicle",
	"doll",
	"controller",
	"game"
};

int pending_remote_name_cancel(struct adapter *adapter)
{
	struct remote_dev_info *dev, match;
	GSList *l;
	int dd, err = 0;

	/* find the pending remote name request */
	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, BDADDR_ANY);
	match.name_status = NAME_REQUESTED;

	l = g_slist_find_custom(adapter->found_devices, &match,
			(GCompareFunc) found_device_cmp);
	if (!l) /* no pending request */
		return 0;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return -ENODEV;

	dev = l->data;

	if (hci_read_remote_name_cancel(dd, &dev->bdaddr, 1000) < 0) {
		error("Remote name cancel failed: %s(%d)", strerror(errno), errno);
		err = -errno;
	}

	/* free discovered devices list */
	g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
	g_slist_free(adapter->found_devices);
	adapter->found_devices = NULL;

	hci_close_dev(dd);
	return err;
}

static struct bonding_request_info *bonding_request_new(bdaddr_t *peer,
							DBusConnection *conn,
							DBusMessage *msg)
{
	struct bonding_request_info *bonding;

	bonding = g_new0(struct bonding_request_info, 1);

	bacpy(&bonding->bdaddr, peer);

	bonding->conn = dbus_connection_ref(conn);
	bonding->rq = dbus_message_ref(msg);

	return bonding;
}

const char *mode2str(uint8_t mode)
{
	switch(mode) {
	case MODE_OFF:
		return "off";
	case MODE_CONNECTABLE:
		return "connectable";
	case MODE_DISCOVERABLE:
		return "discoverable";
	case MODE_LIMITED:
		return "limited";
	default:
		return "unknown";
	}
}

static uint8_t on_mode(const char *addr)
{
	char mode[14];
	bdaddr_t sba;

	str2ba(addr, &sba);

	if (read_on_mode(&sba, mode, sizeof(mode)) < 0)
		return MODE_CONNECTABLE;

	return str2mode(addr, mode);
}

uint8_t str2mode(const char *addr, const char *mode)
{
	if (strcasecmp("off", mode) == 0)
		return MODE_OFF;
	else if (strcasecmp("connectable", mode) == 0)
		return MODE_CONNECTABLE;
	else if (strcasecmp("discoverable", mode) == 0)
		return MODE_DISCOVERABLE;
	else if (strcasecmp("limited", mode) == 0)
		return MODE_LIMITED;
	else if (strcasecmp("on", mode) == 0)
		return on_mode(addr);
	else
		return MODE_UNKNOWN;
}

static DBusHandlerResult adapter_get_info(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *property;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t ba;
	char str[249];
	uint8_t cls[3];

	if (check_address(adapter->address) < 0)
		return error_not_ready(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	property = adapter->address;
	dbus_message_iter_append_dict_entry(&dict, "address",
			DBUS_TYPE_STRING, &property);

	memset(str, 0, sizeof(str));
	property = str;
	str2ba(adapter->address, &ba);

	if (!read_local_name(&ba, str))
		dbus_message_iter_append_dict_entry(&dict, "name",
			DBUS_TYPE_STRING, &property);

	get_device_version(adapter->dev_id, str, sizeof(str));
	dbus_message_iter_append_dict_entry(&dict, "version",
			DBUS_TYPE_STRING, &property);

	get_device_revision(adapter->dev_id, str, sizeof(str));
	dbus_message_iter_append_dict_entry(&dict, "revision",
			DBUS_TYPE_STRING, &property);

	get_device_manufacturer(adapter->dev_id, str, sizeof(str));
	dbus_message_iter_append_dict_entry(&dict, "manufacturer",
			DBUS_TYPE_STRING, &property);

	get_device_company(adapter->dev_id, str, sizeof(str));
	dbus_message_iter_append_dict_entry(&dict, "company",
			DBUS_TYPE_STRING, &property);

	property = mode2str(adapter->mode);

	dbus_message_iter_append_dict_entry(&dict, "mode",
			DBUS_TYPE_STRING, &property);

	dbus_message_iter_append_dict_entry(&dict, "discoverable_timeout",
				DBUS_TYPE_UINT32, &adapter->discov_timeout);

	if (!read_local_class(&ba, cls)) {
		uint32_t class;

		memcpy(&class, cls, 3);
		dbus_message_iter_append_dict_entry(&dict, "class",
			DBUS_TYPE_UINT32, &class);

		property = major_class_str(class);
		dbus_message_iter_append_dict_entry(&dict, "major_class",
			DBUS_TYPE_STRING, &property);

		property = minor_class_str(class);
		dbus_message_iter_append_dict_entry(&dict, "minor_class",
			DBUS_TYPE_STRING, &property);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_address(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *paddr = adapter->address;
	DBusMessage *reply;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(paddr) < 0)
		return error_not_ready(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[20], *str_ptr = str;
	int err;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	err = get_device_version(adapter->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed_errno(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_revision(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	err = get_device_revision(adapter->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed_errno(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_manufacturer(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	err = get_device_manufacturer(adapter->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed_errno(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_company(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;
	int err;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	err = get_device_company(adapter->dev_id, str, sizeof(str));
	if (err < 0)
		return error_failed_errno(conn, msg, -err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_list_modes(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const char *mode_ptr[] = { "off", "connectable", "discoverable", "limited" };
	int i;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING, &array_iter);
	for (i = 0; i < 4; i++)
		dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING,
								&mode_ptr[i]);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_mode(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply = NULL;
	const char *mode;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	mode = mode2str(adapter->mode);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_mode(DBusConnection *conn, DBusMessage *msg,
				const char *mode, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	uint8_t scan_enable;
	uint8_t new_mode, current_scan = adapter->scan_enable;
	bdaddr_t local;
	gboolean limited;
	int err, dd;

	new_mode = str2mode(adapter->address, mode);
	switch(new_mode) {
	case MODE_OFF:
		scan_enable = SCAN_DISABLED;
		break;
	case MODE_CONNECTABLE:
		scan_enable = SCAN_PAGE;
		break;
	case MODE_DISCOVERABLE:
	case MODE_LIMITED:
		scan_enable = (SCAN_PAGE | SCAN_INQUIRY);
		break;
	default:
		return error_invalid_arguments(conn, msg, NULL);
	}

	/* Do reverse resolution in case of "on" mode */
	mode = mode2str(new_mode);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	if (!adapter->up &&
			(hcid.offmode == HCID_OFFMODE_NOSCAN ||
			 (hcid.offmode == HCID_OFFMODE_DEVDOWN &&
			  scan_enable != SCAN_DISABLED))) {
		/* Start HCI device */
		if (ioctl(dd, HCIDEVUP, adapter->dev_id) == 0)
			goto done; /* on success */

		if (errno != EALREADY) {
			err = errno;
			error("Can't init device hci%d: %s (%d)\n",
				adapter->dev_id, strerror(errno), errno);

			hci_close_dev(dd);
			return error_failed_errno(conn, msg, err);
		}
	}

	if (adapter->up && scan_enable == SCAN_DISABLED &&
			hcid.offmode == HCID_OFFMODE_DEVDOWN) {
		if (ioctl(dd, HCIDEVDOWN, adapter->dev_id) < 0) {
			hci_close_dev(dd);
			return error_failed_errno(conn, msg, errno);
		}

		goto done;
	}

	limited = (new_mode == MODE_LIMITED ? TRUE : FALSE);
	err = set_limited_discoverable(dd, adapter->class, limited);
	if (err < 0) {
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, -err);
	}

	if (current_scan != scan_enable) {
		struct hci_request rq;
		uint8_t status = 0;

		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_WRITE_SCAN_ENABLE;
		rq.cparam = &scan_enable;
		rq.clen   = sizeof(scan_enable);
		rq.rparam = &status;
		rq.rlen   = sizeof(status);
		rq.event = EVT_CMD_COMPLETE;

		if (hci_send_req(dd, &rq, 1000) < 0) {
			err = errno;
			error("Sending write scan enable command failed: %s (%d)",
					strerror(errno), errno);
			hci_close_dev(dd);
			return error_failed_errno(conn, msg, err);
		}

		if (status) {
			error("Setting scan enable failed with status 0x%02x",
					status);
			hci_close_dev(dd);
			return error_failed_errno(conn, msg, bt_error(status));
		}
	} else {
		/* discoverable or limited */
		if ((scan_enable & SCAN_INQUIRY) && (new_mode != adapter->mode)) {
			dbus_connection_emit_signal(conn,
					dbus_message_get_path(msg),
					ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

			if (adapter->timeout_id)
				g_source_remove(adapter->timeout_id);

			if (adapter->discov_timeout != 0)
				adapter->timeout_id = g_timeout_add(adapter->discov_timeout * 1000,
						discov_timeout_handler, adapter);
		}
	}
done:
	str2ba(adapter->address, &local);
	write_device_mode(&local, mode);

	hci_close_dev(dd);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	adapter->mode = new_mode;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_mode(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *mode;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (!mode)
		return error_invalid_arguments(conn, msg, NULL);

	return set_mode(conn, msg, mode, data);
}

static DBusHandlerResult adapter_get_discoverable_to(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &adapter->discov_timeout,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void resolve_paths(DBusMessage *msg, char **old_path, char **new_path)
{
	const char *path = dbus_message_get_path(msg);

	if (!path)
		return;

	if (old_path)
		*old_path = NULL;

	if (new_path)
		*new_path = NULL;

	/* old path calls */
	if (g_str_has_prefix(path, BASE_PATH)) {
		if (old_path)
			*old_path = g_strdup(path);

		if (hcid_dbus_use_experimental() && new_path)
			*new_path = g_strdup(path + ADAPTER_PATH_INDEX);

		return;
	}

	if (old_path)
		*old_path = g_strconcat(BASE_PATH, path, NULL);

	if (new_path)
		*new_path = g_strdup(path);
}

static DBusHandlerResult set_discoverable_timeout(DBusConnection *conn,
							DBusMessage *msg,
							uint32_t timeout,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char *old_path, *new_path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (adapter->timeout_id) {
		g_source_remove(adapter->timeout_id);
		adapter->timeout_id = 0;
	}

	if ((timeout != 0) && (adapter->scan_enable & SCAN_INQUIRY))
		adapter->timeout_id = g_timeout_add(timeout * 1000,
						discov_timeout_handler,
						adapter);

	adapter->discov_timeout = timeout;

	str2ba(adapter->address, &bdaddr);
	write_discoverable_timeout(&bdaddr, timeout);

	resolve_paths(msg, &old_path, &new_path);

	dbus_connection_emit_signal(conn, old_path,
					ADAPTER_INTERFACE,
					"DiscoverableTimeoutChanged",
					DBUS_TYPE_UINT32, &timeout,
					DBUS_TYPE_INVALID);
	if (new_path) {
		dbus_connection_emit_property_changed(conn, new_path,
						ADAPTER_INTERFACE,
						"DiscoverableTimeout",
						DBUS_TYPE_UINT32, &timeout);
	}

	g_free(old_path);
	g_free(new_path);
	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_discoverable_to(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	uint32_t timeout;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &timeout,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	return set_discoverable_timeout(conn, msg, timeout, data);
}

static DBusHandlerResult adapter_is_connectable(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply;
	const uint8_t scan_enable = adapter->scan_enable;
	dbus_bool_t connectable = FALSE;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	if (scan_enable & SCAN_PAGE)
		connectable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connectable,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_is_discoverable(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply;
	const uint8_t scan_enable = adapter->scan_enable;
	dbus_bool_t discoverable = FALSE;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	if (scan_enable & SCAN_INQUIRY)
		discoverable = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &discoverable,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_is_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_bool_t connected = FALSE;

	struct adapter *adapter = data;
	GSList *l = adapter->active_conn;

	const char *peer_addr;
	bdaddr_t peer_bdaddr;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(peer_addr, &peer_bdaddr);

	l = g_slist_find_custom(l, &peer_bdaddr, active_conn_find_by_bdaddr);
	if (l)
		connected = TRUE;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_list_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	struct adapter *adapter = data;
	GSList *l = adapter->active_conn;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array_iter);

	while (l) {
		char peer_addr[18];
		const char *paddr = peer_addr;
		struct active_conn_info *dev = l->data;

		ba2str(&dev->bdaddr, peer_addr);

		dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING,
						&paddr);

		l = l->next;
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_major_class(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply;
	const char *str_ptr = "computer";

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* FIXME: Currently, only computer major class is supported */
	if ((adapter->class[1] & 0x1f) != 1)
		return error_unsupported_major_class(conn, msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_list_minor_classes(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const struct adapter *adapter = data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const char **minor_ptr;
	uint8_t major_class;
	int size, i;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	major_class = adapter->class[1] & 0x1F;

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
		dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING,
						&minor_ptr[i]);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_minor_class(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	const char *str_ptr = "";
	uint8_t minor_class;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	/* FIXME: Currently, only computer major class is supported */
	if ((adapter->class[1] & 0x1f) != 1)
		return error_unsupported_major_class(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	minor_class = adapter->class[0] >> 2;

	/* Validate computer minor class */
	if (minor_class > (sizeof(computer_minor_cls) / sizeof(*computer_minor_cls)))
		goto failed;

	str_ptr = computer_minor_cls[minor_class];

failed:
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_minor_class(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	const char *minor;
	uint32_t dev_class = 0xFFFFFFFF;
	int i, dd;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &minor,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (!minor)
		return error_invalid_arguments(conn, msg, NULL);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	/* Currently, only computer major class is supported */
	if ((adapter->class[1] & 0x1f) != 1) {
		hci_close_dev(dd);
		return error_unsupported_major_class(conn, msg);
	}
	for (i = 0; i < sizeof(computer_minor_cls) / sizeof(*computer_minor_cls); i++)
		if (!strcasecmp(minor, computer_minor_cls[i])) {
			/* Remove the format type */
			dev_class = i << 2;
			break;
		}

	/* Check if it's a valid minor class */
	if (dev_class == 0xFFFFFFFF) {
		hci_close_dev(dd);
		return error_invalid_arguments(conn, msg, NULL);
	}

	/* set the service class and major class  */
	dev_class |= (adapter->class[2] << 16) | (adapter->class[1] << 8);

	if (hci_write_class_of_dev(dd, dev_class, 2000) < 0) {
		int err = errno;
		error("Can't write class of device on hci%d: %s(%d)",
				adapter->dev_id, strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, err);
	}

	dbus_connection_emit_signal(conn, dbus_message_get_path(msg),
					ADAPTER_INTERFACE, "MinorClassChanged",
					DBUS_TYPE_STRING, &minor,
					DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_service_classes(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const char *str_ptr;
	int i;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (i = 0; i < (sizeof(service_cls) / sizeof(*service_cls)); i++) {
		if (adapter->class[2] & (1 << i)) {
			str_ptr = service_cls[i];
			dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &str_ptr);
		}
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[249], *str_ptr = str;
	int err;
	bdaddr_t ba;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(adapter->address, &ba);

	err = read_local_name(&ba, str);
	if (err < 0) {
		if (!adapter->up)
			return error_not_ready(conn, msg);

		err = get_device_name(adapter->dev_id, str, sizeof(str));
		if (err < 0)
			return error_failed_errno(conn, msg, -err);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static int set_name(DBusConnection *conn, DBusMessage *msg, const char *name,
			void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t bdaddr;
	int ecode;
	char *new_path;

	if (!g_utf8_validate(name, -1, NULL)) {
		error("Name change failed: the supplied name isn't valid UTF-8");
		return error_invalid_arguments(conn, msg, NULL);
	}

	str2ba(adapter->address, &bdaddr);

	write_local_name(&bdaddr, (char *) name);

	if (!adapter->up)
		goto done;

	ecode = set_device_name(adapter->dev_id, name);
	if (ecode < 0)
		return error_failed_errno(conn, msg, -ecode);

done:
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	resolve_paths(msg, NULL, &new_path);

	if (new_path) {
		dbus_connection_emit_property_changed(conn, new_path,
						ADAPTER_INTERFACE,
						"Name", DBUS_TYPE_STRING,
						&name);
	}

	g_free(new_path);
	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *str_ptr;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &str_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	return set_name(conn, msg, str_ptr, data);
}

static DBusHandlerResult adapter_get_remote_info(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t src, dst;
	const char *addr_ptr;
	char filename[PATH_MAX + 1];
	char buf[64];
	const char *ptr;
	char *str;
	dbus_bool_t boolean;
	uint32_t class;
	int compid, ver, subver;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Name */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "names");
	str = textfile_caseget(filename, addr_ptr);
	if (str) {
		dbus_message_iter_append_dict_entry(&dict, "name",
				DBUS_TYPE_STRING, &str);
		free(str);
	}

	str2ba(adapter->address, &src);
	str2ba(addr_ptr, &dst);

	/* Remote device class */
	if (read_remote_class(&src, &dst, &class) == 0) {

		dbus_message_iter_append_dict_entry(&dict, "class",
				DBUS_TYPE_UINT32, &class);

		ptr = major_class_str(class);
		dbus_message_iter_append_dict_entry(&dict, "major_class",
				DBUS_TYPE_STRING, &ptr);

		ptr = minor_class_str(class);
		dbus_message_iter_append_dict_entry(&dict, "minor_class",
				DBUS_TYPE_STRING, &ptr);
	}

	/* Alias */
	if (get_device_alias(adapter->dev_id, &dst, buf, sizeof(buf)) > 0) {
		ptr = buf;
		dbus_message_iter_append_dict_entry(&dict, "alias",
				DBUS_TYPE_STRING, &ptr);
	}

	/* Bonded */
	create_name(filename, PATH_MAX, STORAGEDIR,
			adapter->address, "linkkeys");
	str = textfile_caseget(filename, addr_ptr);
	if (str) {
		boolean = TRUE;
		free(str);
	} else {
		boolean = FALSE;
	}

	dbus_message_iter_append_dict_entry(&dict, "bonded",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Trusted */
	boolean = read_trust(&src, addr_ptr, GLOBAL_TRUST);
	dbus_message_iter_append_dict_entry(&dict, "trusted",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Connected */
	if (g_slist_find_custom(adapter->active_conn, &dst,
				active_conn_find_by_bdaddr))
		boolean = TRUE;
	else
		boolean = FALSE;

	dbus_message_iter_append_dict_entry(&dict, "connected",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* HCI Revision/Manufacturer/Version */
	create_name(filename, PATH_MAX, STORAGEDIR,
			adapter->address, "manufacturers");

	str = textfile_caseget(filename, addr_ptr);
	if (!str)
		goto done;

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) != 3) {
		/* corrupted file data */
		free(str);
		goto done;
	}

	free(str);

	ptr = buf;
	snprintf(buf, 16, "HCI 0x%X", subver);
	dbus_message_iter_append_dict_entry(&dict, "revision",
			DBUS_TYPE_STRING, &ptr);

	ptr = bt_compidtostr(compid);
	dbus_message_iter_append_dict_entry(&dict, "manufacturer",
			DBUS_TYPE_STRING, &ptr);

	str = lmp_vertostr(ver);
	snprintf(buf, 64, "Bluetooth %s", str);
	bt_free(str);

	create_name(filename, PATH_MAX, STORAGEDIR,
			adapter->address, "features");

	str = textfile_caseget(filename, addr_ptr);
	if (str) {
		if (strlen(str) == 16) {
			uint8_t features;
			/* Getting the third byte */
			features  = ((str[6] - 48) << 4) | (str[7] - 48);
			if (features & (LMP_EDR_ACL_2M | LMP_EDR_ACL_3M))
				snprintf(buf, 64, "Bluetooth %s + EDR", ptr);

		}
		free(str);
	}
	ptr = buf;
	dbus_message_iter_append_dict_entry(&dict, "version",
			DBUS_TYPE_STRING, &ptr);

done:
	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_svc(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return get_remote_svc_rec(conn, msg, data, SDP_FORMAT_BINARY);
}

static DBusHandlerResult adapter_get_remote_svc_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return get_remote_svc_rec(conn, msg, data, SDP_FORMAT_XML);
}

static DBusHandlerResult adapter_get_remote_svc_handles(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	return get_remote_svc_handles(conn, msg, data);
}

static DBusHandlerResult adapter_get_remote_svc_identifiers(DBusConnection *conn,
								DBusMessage *msg,
								void *data)
{
	return get_remote_svc_identifiers(conn, msg, data);
}

static DBusHandlerResult adapter_finish_sdp_transact(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	return finish_remote_svc_transact(conn, msg, data);
}

static DBusHandlerResult adapter_get_remote_version(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	char *str_ver = NULL;
	char info_array[64], *info = info_array;
	int compid, ver, subver;

	memset(info_array, 0, 64);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"manufacturers");

	str = textfile_caseget(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) != 3) {
		/* corrupted file data */
		free(str);
		goto failed;
	}

	free(str);

	str_ver = lmp_vertostr(ver);

	/* Default value */
	snprintf(info, 64, "Bluetooth %s", str_ver);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"features");

	str = textfile_caseget(filename, addr_ptr);
	if (!str)
		goto failed;

	/* Check if the data is not corrupted */
	if (strlen(str) == 16) {
		uint8_t features;
		/* Getting the third byte */
		features  = ((str[6] - 48) << 4) | (str[7] - 48);
		if (features & (LMP_EDR_ACL_2M | LMP_EDR_ACL_3M))
			snprintf(info, 64, "Bluetooth %s + EDR", str_ver);
	}

	free(str);

failed:
	if (str_ver)
		bt_free(str_ver);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &info,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_revision(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	char info_array[16], *info = info_array;
	int compid, ver, subver;

	memset(info_array, 0, 16);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"manufacturers");

	str = textfile_caseget(filename, addr_ptr);
	if (!str)
		return error_not_available(conn, msg);

	if (sscanf(str, "%d %d %d", &compid, &ver, &subver) == 3)
		snprintf(info, 16, "HCI 0x%X", subver);

	free(str);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &info,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_manufacturer(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	char info_array[64], *info = info_array;
	int compid, ver, subver;

	memset(info_array, 0, 64);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"manufacturers");

	str = textfile_caseget(filename, addr_ptr);
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

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_company(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char oui[9], *str_bdaddr, *tmp;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &str_bdaddr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

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

	return send_message_and_unref(conn, reply);
}

static int get_remote_class(DBusConnection *conn, DBusMessage *msg, void *data,
				uint32_t *class)
{
	struct adapter *adapter = data;
	char *addr_peer;
	bdaddr_t local, peer;
	int ecode;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_peer,
				DBUS_TYPE_INVALID)) {
		error_invalid_arguments(conn, msg, NULL);
		return -1;
	}

	if (check_address(addr_peer) < 0) {
		error_invalid_arguments(conn, msg, NULL);
		return -1;
	}

	str2ba(addr_peer, &peer);
	str2ba(adapter->address, &local);

	ecode = read_remote_class(&local, &peer, class);
	if (ecode < 0) {
		error_not_available(conn, msg);
		return -1;
	}

	return 0;
}

static DBusHandlerResult adapter_get_remote_major_class(DBusConnection *conn,
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

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_minor_class(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusMessage *reply;
	const char *minor_class;
	uint32_t class;

	if (get_remote_class(conn, msg, data, &class) < 0)
		return DBUS_HANDLER_RESULT_HANDLED;

	minor_class = minor_class_str(class);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &minor_class,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void append_class_string(const char *class, DBusMessageIter *iter)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &class);
}

static DBusHandlerResult adapter_get_remote_service_cls(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	GSList *service_classes;
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

	g_slist_foreach(service_classes, (GFunc) append_class_string,
			&array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	g_slist_free(service_classes);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_class(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	uint32_t class;

	if (get_remote_class(conn, msg, data, &class) < 0)
		return DBUS_HANDLER_RESULT_HANDLED;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &class,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_features(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct adapter *adapter = data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, array_iter;
	uint8_t features[8], *ptr = features;
	const char *addr;
	char *str;
	int i;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "features");

	str = textfile_caseget(filename, addr);
	if (!str)
		return error_not_available(conn, msg);

	memset(features, 0, sizeof(features));
	for (i = 0; i < sizeof(features); i++) {
		char tmp[3];

		memcpy(tmp, str + (i * 2), 2);
		tmp[2] = '\0';

		features[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		free(str);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE_AS_STRING, &array_iter);

	dbus_message_iter_append_fixed_array(&array_iter,
				DBUS_TYPE_BYTE, &ptr, sizeof(features));

	dbus_message_iter_close_container(&iter, &array_iter);

	free(str);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_remote_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct adapter *adapter = data;
	DBusMessage *reply = NULL;
	const char *peer_addr;
	bdaddr_t peer_bdaddr;
	char *str;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	/* check if it is in the cache */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "names");

	str = textfile_caseget(filename, peer_addr);

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
		return send_message_and_unref(conn, reply);
	}

	if (!adapter->up)
		return error_not_ready(conn, msg);

	/* If the discover process is not running, return an error */
	if (!adapter->discov_active && !adapter->pdiscov_active)
		return error_not_available(conn, msg);

	/* Queue the request when there is a discovery running */
	str2ba(peer_addr, &peer_bdaddr);
	found_device_add(&adapter->found_devices, &peer_bdaddr, 0, NAME_REQUIRED);

	return error_request_deferred(conn, msg);
}

static DBusHandlerResult adapter_get_remote_alias(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char str[249], *str_ptr = str, *addr_ptr;
	bdaddr_t bdaddr;
	int ecode;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(addr_ptr, &bdaddr);

	ecode = get_device_alias(adapter->dev_id, &bdaddr, str, sizeof(str));
	if (ecode < 0)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_remote_alias(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char *alias, *addr, *old_path, *new_path;
	bdaddr_t bdaddr;
	int ecode;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &alias,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if ((strlen(alias) == 0) || (check_address(addr) < 0)) {
		error("Alias change failed: Invalid parameter");
		return error_invalid_arguments(conn, msg, NULL);
	}

	str2ba(addr, &bdaddr);

	ecode = set_device_alias(adapter->dev_id, &bdaddr, alias);
	if (ecode < 0)
		return error_failed_errno(conn, msg, -ecode);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	resolve_paths(msg, &old_path, &new_path);

	dbus_connection_emit_signal(conn, old_path,
					ADAPTER_INTERFACE, "RemoteAliasChanged",
					DBUS_TYPE_STRING, &addr,
					DBUS_TYPE_STRING, &alias,
					DBUS_TYPE_INVALID);

	if (new_path) {
		struct device *device;

		device = adapter_get_device(adapter, addr);
		if (device) {
			dbus_connection_emit_property_changed(conn,
					device->path, DEVICE_INTERFACE,
					"Alias", DBUS_TYPE_STRING, &alias);
		}
	}

	g_free(old_path);
	g_free(new_path);
	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_clear_remote_alias(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char *addr_ptr;
	bdaddr_t bdaddr;
	int ecode, had_alias = 1;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0) {
		error("Alias clear failed: Invalid parameter");
		return error_invalid_arguments(conn, msg, NULL);
	}

	str2ba(addr_ptr, &bdaddr);

	ecode = get_device_alias(adapter->dev_id, &bdaddr, NULL, 0);
	if (ecode == -ENXIO)
		had_alias = 0;

	ecode = set_device_alias(adapter->dev_id, &bdaddr, NULL);
	if (ecode < 0)
		return error_failed_errno(conn, msg, -ecode);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (had_alias)
		dbus_connection_emit_signal(conn, dbus_message_get_path(msg),
						ADAPTER_INTERFACE,
						"RemoteAliasCleared",
						DBUS_TYPE_STRING, &addr_ptr,
						DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_last_seen(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"lastseen");

	str = textfile_caseget(filename, addr_ptr);
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

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_last_used(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"lastused");

	str = textfile_caseget(filename, addr_ptr);
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

	return send_message_and_unref(conn, reply);
}


gboolean dc_pending_timeout_handler(void *data)
{
	int dd;
	struct adapter *adapter = data;
	struct pending_dc_info *pending_dc = adapter->pending_dc;
	DBusMessage *reply;

	dd = hci_open_dev(adapter->dev_id);

	if (dd < 0) {
		error_no_such_adapter(pending_dc->conn,
				      pending_dc->msg);
		dc_pending_timeout_cleanup(adapter);
		return FALSE;
	}

	/* Send the HCI disconnect command */
	if (hci_disconnect(dd, pending_dc->conn_handle,
				HCI_OE_USER_ENDED_CONNECTION,
				500) < 0) {
		int err = errno;
		error("Disconnect failed");
		error_failed_errno(pending_dc->conn, pending_dc->msg, err);
	} else {
		reply = dbus_message_new_method_return(pending_dc->msg);
		if (!reply)
			error("Failed to allocate disconnect reply");
		else
			send_message_and_unref(pending_dc->conn, reply);
	}

	hci_close_dev(dd);
	dc_pending_timeout_cleanup(adapter);

	return FALSE;
}

void dc_pending_timeout_cleanup(struct adapter *adapter)
{
	dbus_connection_unref(adapter->pending_dc->conn);
	dbus_message_unref(adapter->pending_dc->msg);
	g_free(adapter->pending_dc);
	adapter->pending_dc = NULL;
}

static DBusHandlerResult adapter_dc_remote_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	GSList *l = adapter->active_conn;
	const char *peer_addr;
	bdaddr_t peer_bdaddr;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(peer_addr, &peer_bdaddr);

	l = g_slist_find_custom(l, &peer_bdaddr, active_conn_find_by_bdaddr);
	if (!l)
		return error_not_connected(conn, msg);

	if (adapter->pending_dc)
		return error_disconnect_in_progress(conn, msg);

	adapter->pending_dc = g_new0(struct pending_dc_info, 1);

	/* Start waiting... */
	adapter->pending_dc->timeout_id =
		g_timeout_add(DC_PENDING_TIMEOUT,
			      dc_pending_timeout_handler,
			      adapter);

	if (!adapter->pending_dc->timeout_id) {
		g_free(adapter->pending_dc);
		adapter->pending_dc = NULL;
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	adapter->pending_dc->conn = dbus_connection_ref(conn);
	adapter->pending_dc->msg = dbus_message_ref(msg);
	adapter->pending_dc->conn_handle =
		((struct active_conn_info *) l->data)->handle;

	dbus_connection_emit_signal(conn, dbus_message_get_path(msg),
					ADAPTER_INTERFACE,
					"RemoteDeviceDisconnectRequested",
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_INVALID);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void reply_authentication_failure(struct bonding_request_info *bonding)
{
	DBusMessage *reply;
	int status;

	status = bonding->hci_status ?
			bonding->hci_status : HCI_AUTHENTICATION_FAILURE;

	reply = new_authentication_return(bonding->rq, status);
	if (reply)
		send_message_and_unref(bonding->conn, reply);
}

static void create_device_req_free(struct create_device_req *create)
{
	dbus_connection_unref(create->conn);
	dbus_message_unref(create->msg);
	g_free(create->agent_path);
	g_free(create);
}

struct device *adapter_get_device(struct adapter *adapter, const char *dest)
{
	struct device *device;
	GSList *l;

	if (!adapter)
		return NULL;

	l = g_slist_find_custom(adapter->devices,
				dest, (GCompareFunc) device_address_cmp);
	if (!l)
		return NULL;

	device = l->data;

	return device;
}

static gboolean create_bonding_conn_complete(GIOChannel *io, GIOCondition cond,
						struct adapter *adapter)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	struct l2cap_conninfo cinfo;
	socklen_t len;
	int sk, dd, ret;

	if (!adapter->bonding) {
		/* If we come here it implies a bug somewhere */
		debug("create_bonding_conn_complete: no pending bonding!");
		g_io_channel_close(io);
		g_io_channel_unref(io);
		return FALSE;
	}

	if (cond & G_IO_NVAL) {
		error_authentication_canceled(adapter->bonding->conn,
						adapter->bonding->rq);
		goto cleanup;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		debug("Hangup or error on bonding IO channel");

		if (!adapter->bonding->auth_active)
			error_connection_attempt_failed(adapter->bonding->conn,
							adapter->bonding->rq,
							ENETDOWN);
		else
			reply_authentication_failure(adapter->bonding);

		goto failed;
	}

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		error("Can't get socket error: %s (%d)",
				strerror(errno), errno);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->rq,
				errno);
		goto failed;
	}

	if (ret != 0) {
		if (adapter->bonding->auth_active)
			reply_authentication_failure(adapter->bonding);
		else
			error_connection_attempt_failed(adapter->bonding->conn,
							adapter->bonding->rq,
							ret);
		goto failed;
	}

	len = sizeof(cinfo);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_CONNINFO, &cinfo, &len) < 0) {
		error("Can't get connection info: %s (%d)",
				strerror(errno), errno);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->rq,
				errno);
		goto failed;
	}

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error_no_such_adapter(adapter->bonding->conn,
					adapter->bonding->rq);
		goto failed;
	}

	memset(&rp, 0, sizeof(rp));

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(cinfo.hci_handle);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 500) < 0) {
		error("Unable to send HCI request: %s (%d)",
					strerror(errno), errno);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->rq,
				errno);
		hci_close_dev(dd);
		goto failed;
	}

	if (rp.status) {
		error("HCI_Authentication_Requested failed with status 0x%02x",
				rp.status);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->rq,
				bt_error(rp.status));
		hci_close_dev(dd);
		goto failed;
	}

	hci_close_dev(dd);

	adapter->bonding->auth_active = 1;

	adapter->bonding->io_id = g_io_add_watch(io,
						G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						(GIOFunc) create_bonding_conn_complete,
						adapter);

	return FALSE;

failed:
	g_io_channel_close(io);

cleanup:
	name_listener_remove(adapter->bonding->conn,
				dbus_message_get_sender(adapter->bonding->rq),
				(name_cb_t) create_bond_req_exit, adapter);

	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;

	if (adapter->create) {
		name_listener_id_remove(adapter->create->id);
		create_device_req_free(adapter->create);
		adapter->create = NULL;
	}

	return FALSE;
}

static DBusHandlerResult create_bonding(DBusConnection *conn, DBusMessage *msg,
				const char *address, const char *agent_path,
				void *data)
{
	char filename[PATH_MAX + 1];
	char *str;
	struct adapter *adapter = data;
	bdaddr_t bdaddr;
	int sk;

	str2ba(address, &bdaddr);

	/* check if there is a pending discover: requested by D-Bus/non clients */
	if (adapter->discov_active || (adapter->pdiscov_active && !adapter->pinq_idle))
		return error_discover_in_progress(conn, msg);

	pending_remote_name_cancel(adapter);

	if (adapter->bonding)
		return error_bonding_in_progress(conn, msg);

	if (g_slist_find_custom(adapter->pin_reqs, &bdaddr, pin_req_cmp))
		return error_bonding_in_progress(conn, msg);

	/* check if a link key already exists */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	str = textfile_caseget(filename, address);
	if (str) {
		free(str);
		return error_bonding_already_exists(conn, msg);
	}

	sk = l2raw_connect(adapter->address, &bdaddr);
	if (sk < 0)
		return error_connection_attempt_failed(conn, msg, 0);

	adapter->bonding = bonding_request_new(&bdaddr, conn, msg);
	if (!adapter->bonding) {
		close(sk);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	adapter->bonding->io = g_io_channel_unix_new(sk);
	adapter->bonding->io_id = g_io_add_watch(adapter->bonding->io,
						G_IO_OUT | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						(GIOFunc) create_bonding_conn_complete,
						adapter);

	name_listener_add(conn, dbus_message_get_sender(msg),
			(name_cb_t) create_bond_req_exit, adapter);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult adapter_create_bonding(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	char *address;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	return create_bonding(conn, msg, address, NULL, data);
}

static DBusHandlerResult adapter_cancel_bonding(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t peer_bdaddr;
	const char *peer_addr;
	GSList *l;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(peer_addr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(peer_addr, &peer_bdaddr);

	if (!adapter->bonding || bacmp(&adapter->bonding->bdaddr, &peer_bdaddr))
		return error_bonding_not_in_progress(conn, msg);

	if (strcmp(dbus_message_get_sender(adapter->bonding->rq),
				dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	adapter->bonding->cancel = 1;

	l = g_slist_find_custom(adapter->pin_reqs, &peer_bdaddr, pin_req_cmp);
	if (l) {
		struct pending_pin_info *pin_req = l->data;

		if (pin_req->replied) {
			/*
			 * If disconnect can't be applied and the PIN code
			 * request was already replied it doesn't make sense
			 * cancel the remote passkey: return not authorized.
			 */
			g_io_channel_close(adapter->bonding->io);
			return error_not_authorized(conn, msg);
		} else {
			int dd = hci_open_dev(adapter->dev_id);
			if (dd < 0) {
				error("Can't open hci%d: %s (%d)",
					adapter->dev_id, strerror(errno), errno);
				return DBUS_HANDLER_RESULT_HANDLED;
			}

			hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY,
					6, &peer_bdaddr);

			hci_close_dev(dd);
		}

		adapter->pin_reqs = g_slist_remove(adapter->pin_reqs, pin_req);
		g_free(pin_req);
	}

	g_io_channel_close(adapter->bonding->io);

	reply = dbus_message_new_method_return(msg);
	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult adapter_remove_bonding(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	GSList *l;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str, *old_path, *new_path;
	bdaddr_t bdaddr;
	int dd;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	/* textfile_del doesn't return an error when the key is not found */
	str = textfile_caseget(filename, addr_ptr);
	if (!str) {
		hci_close_dev(dd);
		return error_bonding_does_not_exist(conn, msg);
	}

	free(str);

	/* Delete the link key from storage */
	if (textfile_casedel(filename, addr_ptr) < 0) {
		int err = errno;
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, err);
	}

	str2ba(addr_ptr, &bdaddr);

	/* Delete the link key from the Bluetooth chip */
	hci_delete_stored_link_key(dd, &bdaddr, 0, 1000);

	/* find the connection */
	l = g_slist_find_custom(adapter->active_conn, &bdaddr,
			active_conn_find_by_bdaddr);
	if (l) {
		struct active_conn_info *con = l->data;
		/* Send the HCI disconnect command */
		if (hci_disconnect(dd, htobs(con->handle),
					HCI_OE_USER_ENDED_CONNECTION, 500) < 0) {
			int err = errno;
			error("Disconnect failed");
			hci_close_dev(dd);
			return error_failed_errno(conn, msg, err);
		}
	}

	resolve_paths(msg, &old_path, &new_path);

	dbus_connection_emit_signal(conn, dbus_message_get_path(msg),
					ADAPTER_INTERFACE, "BondingRemoved",
					DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);

	if (new_path) {
		struct device *device;
		gboolean paired = FALSE;

		device = adapter_get_device(adapter, addr_ptr);
		if (device) {
			dbus_connection_emit_property_changed(conn,
					device->path, DEVICE_INTERFACE,
					"Paired", DBUS_TYPE_BOOLEAN, &paired);
		}
	}

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_has_bonding(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char *addr_ptr, *str;
	dbus_bool_t result;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	str = textfile_caseget(filename, addr_ptr);
	if (str) {
		result = TRUE;
		free(str);
	} else
		result = FALSE;

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &result,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void list_bondings_do_append(char *key, char *value, void *data)
{
	DBusMessageIter *iter = data;
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);
}

static DBusHandlerResult adapter_list_bondings(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	textfile_foreach(filename, list_bondings_do_append, &array_iter);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_pin_code_length(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t local, peer;
	char *addr_ptr;
	uint8_t length;
	int len;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(adapter->address, &local);

	str2ba(addr_ptr, &peer);

	len = read_pin_length(&local, &peer);
	if (len < 0)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);

	length = len;

	dbus_message_append_args(reply, DBUS_TYPE_BYTE, &length,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_encryption_key_size(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t bdaddr;
	char *addr_ptr;
	uint8_t size;
	int val;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr_ptr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(addr_ptr) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(addr_ptr, &bdaddr);

	val = get_encryption_key_size(adapter->dev_id, &bdaddr);
	if (val < 0)
		return error_failed_errno(conn, msg, -val);

	reply = dbus_message_new_method_return(msg);

	size = val;

	dbus_message_append_args(reply, DBUS_TYPE_BYTE, &size,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_start_periodic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	periodic_inquiry_cp cp;
	struct hci_request rq;
	struct adapter *adapter = data;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	uint8_t status;
	int dd;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
				"StartPeriodicDiscovery")) {
		if (!dbus_message_has_signature(msg,
					DBUS_TYPE_INVALID_AS_STRING))
			return error_invalid_arguments(conn, msg, NULL);
	}

	if (adapter->discov_active || adapter->pdiscov_active)
		return error_discover_in_progress(conn, msg);

	pending_remote_name_cancel(adapter);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.lap, lap, 3);
	cp.max_period = htobs(24);
	cp.min_period = htobs(16);
	cp.length  = 0x08;
	cp.num_rsp = 0x00;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_PERIODIC_INQUIRY;
	rq.cparam = &cp;
	rq.clen   = PERIODIC_INQUIRY_CP_SIZE;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);
	rq.event  = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, 1000) < 0) {
		int err = errno;
		error("Unable to start periodic inquiry: %s (%d)",
				strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, err);
	}

	if (status) {
		error("HCI_Periodic_Inquiry_Mode failed with status 0x%02x",
				status);
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, bt_error(status));
	}

	adapter->pdiscov_requestor = g_strdup(dbus_message_get_sender(msg));

	if (adapter->pdiscov_resolve_names)
		adapter->discov_type = PERIODIC_INQUIRY | RESOLVE_NAME;
	else
		adapter->discov_type = PERIODIC_INQUIRY;

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	/* track the request owner to cancel it automatically if the owner
	 * exits */
	name_listener_add(conn, dbus_message_get_sender(msg),
				(name_cb_t) periodic_discover_req_exit,
				adapter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_stop_periodic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter = data;
	int err;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
				"StopPeriodicDiscovery")) {
		if (!dbus_message_has_signature(msg,
					DBUS_TYPE_INVALID_AS_STRING))
			return error_invalid_arguments(conn, msg, NULL);
	}

	if (!adapter->pdiscov_active)
		return error_not_authorized(conn, msg);

	/*
	 * Cleanup the discovered devices list and send the cmd to exit
	 * from periodic inquiry mode or cancel remote name request.
	 */
	err = cancel_periodic_discovery(adapter);
	if (err < 0) {
		if (err == -ENODEV)
			return error_no_such_adapter(conn, msg);
		else
			return error_failed_errno(conn, msg, -err);
	}

	reply = dbus_message_new_method_return(msg);
	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_is_periodic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter = data;
	dbus_bool_t active = adapter->pdiscov_active;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &active,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_set_pdiscov_resolve(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusMessage *reply;
	struct adapter *adapter = data;
	dbus_bool_t resolve;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_BOOLEAN, &resolve,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	debug("SetPeriodicDiscoveryNameResolving(%s)",
			resolve ? "TRUE" : "FALSE");

	adapter->pdiscov_resolve_names = resolve;

	if (adapter->pdiscov_active) {
		if (resolve)
			adapter->discov_type |= RESOLVE_NAME;
		else
			adapter->discov_type &= ~RESOLVE_NAME;
	}

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_get_pdiscov_resolve(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusMessage *reply;
	struct adapter *adapter = data;
	dbus_bool_t resolve = adapter->pdiscov_resolve_names;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &resolve,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_discover_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *method;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct adapter *adapter = data;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int dd;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	if (adapter->discov_active)
		return error_discover_in_progress(conn, msg);

	pending_remote_name_cancel(adapter);

	if (adapter->bonding)
		return error_bonding_in_progress(conn, msg);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return error_no_such_adapter(conn, msg);

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.lap, lap, 3);
	cp.length  = 0x08;
	cp.num_rsp = 0x00;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY;
	rq.cparam = &cp;
	rq.clen   = INQUIRY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 500) < 0) {
		int err = errno;
		error("Unable to start inquiry: %s (%d)",
				strerror(errno), errno);
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, err);
	}

	if (rp.status) {
		error("HCI_Inquiry command failed with status 0x%02x",
				rp.status);
		hci_close_dev(dd);
		return error_failed_errno(conn, msg, bt_error(rp.status));
	}

	method = dbus_message_get_member(msg);
	if (strcmp("DiscoverDevicesWithoutNameResolving", method) == 0)
		adapter->discov_type |= STD_INQUIRY;
	else
		adapter->discov_type |= (STD_INQUIRY | RESOLVE_NAME);

	adapter->discov_requestor = g_strdup(dbus_message_get_sender(msg));

	reply = dbus_message_new_method_return(msg);

	hci_close_dev(dd);

	/* track the request owner to cancel it automatically if the owner
	 * exits */
	name_listener_add(conn, dbus_message_get_sender(msg),
				(name_cb_t) discover_devices_req_exit, adapter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_cancel_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	int err;

	if (!adapter->up)
		return error_not_ready(conn, msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	/* is there discover pending? or discovery cancel was requested
	 * previously */
	if (!adapter->discov_active || adapter->discovery_cancel)
		return error_not_authorized(conn, msg);

	/* only the discover requestor can cancel the inquiry process */
	if (!adapter->discov_requestor ||
			strcmp(adapter->discov_requestor, dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	/* Cleanup the discovered devices list and send the cmd to cancel
	 * inquiry or cancel remote name request */
	err = cancel_discovery(adapter);
	if (err < 0) {
		if (err == -ENODEV)
			return error_no_such_adapter(conn, msg);
		else
			return error_failed_errno(conn, msg, -err);
	}

	/* Reply before send DiscoveryCompleted */
	adapter->discovery_cancel = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

struct remote_device_list_t {
	GSList *list;
	time_t time;
};

static void list_remote_devices_do_append(char *key, char *value, void *data)
{
	struct remote_device_list_t *param = data;
	char *address;
	struct tm date;

	if (g_slist_find_custom(param->list, key, (GCompareFunc) strcasecmp))
		return;

	if (param->time){
		strptime(value, "%Y-%m-%d %H:%M:%S %Z", &date);
		if (difftime(mktime(&date), param->time) < 0)
			return;
	}

	address = g_strdup(key);

	param->list = g_slist_append(param->list, address);
}

static void remote_devices_do_append(void *data, void *user_data)
{
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &data);
}

static DBusHandlerResult adapter_list_remote_devices(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	struct adapter *adapter = data;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	struct remote_device_list_t param = { NULL, 0 };

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	/* Add Bonded devices to the list */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "linkkeys");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	/* Add Trusted devices to the list */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "trusts");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	/* Add Last Used devices to the list */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "lastused");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	g_slist_foreach(param.list, remote_devices_do_append, &array_iter);

	g_slist_foreach(param.list, (GFunc) free, NULL);
	g_slist_free(param.list);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static void append_connected(struct active_conn_info *dev, GSList *list)
{
	char address[18];

	ba2str(&dev->bdaddr, address);
	if (g_slist_find_custom(list, address, (GCompareFunc) strcasecmp))
		return;

	list = g_slist_append(list, g_strdup(address));
}

static DBusHandlerResult adapter_list_recent_remote_devices(DBusConnection *conn,
								DBusMessage *msg,
								void *data)
{
	struct adapter *adapter = data;
	struct tm date;
	const char *string;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	struct remote_device_list_t param = { NULL, 0 };
	int len;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &string,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	/* Date format is "YYYY-MM-DD HH:MM:SS GMT" */
	len = strlen(string);
	if (len && (strptime(string, "%Y-%m-%d %H:%M:%S", &date) == NULL))
		return error_invalid_arguments(conn, msg, NULL);

	/* Bonded and trusted: mandatory entries(no matter the date/time) */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "linkkeys");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "trusts");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	/* Last seen/used: append devices since the date informed */
	if (len)
		param.time = mktime(&date);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "lastseen");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "lastused");
	textfile_foreach(filename, list_remote_devices_do_append, &param);

	/* connected: force appending connected devices, lastused might not match */
	g_slist_foreach(adapter->active_conn, (GFunc) append_connected, param.list);

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	g_slist_foreach(param.list, remote_devices_do_append, &array_iter);

	g_slist_foreach(param.list, (GFunc) free, NULL);
	g_slist_free(param.list);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}


static DBusHandlerResult adapter_set_trusted(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	bdaddr_t local;
	const char *address;
	char *old_path, *new_path;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(adapter->address, &local);

	write_trust(&local, address, GLOBAL_TRUST, TRUE);

	resolve_paths(msg, &old_path, &new_path);

	dbus_connection_emit_signal(conn, old_path,
					ADAPTER_INTERFACE, "TrustAdded",
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);

	if (new_path) {
		struct device *device;
		gboolean trust = TRUE;

		device = adapter_get_device(adapter, address);
		if (device) {
			dbus_connection_emit_property_changed(conn,
					device->path, DEVICE_INTERFACE,
					"Trusted", DBUS_TYPE_BOOLEAN, &trust);
		}
	}

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_is_trusted(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	const char *address;
	dbus_bool_t trusted;
	bdaddr_t local;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(adapter->address, &local);

	trusted = read_trust(&local, address, GLOBAL_TRUST);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
				DBUS_TYPE_BOOLEAN, &trusted,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_remove_trust(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	const char *address;
	bdaddr_t local;
	char *old_path, *new_path;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(adapter->address, &local);

	write_trust(&local, address, GLOBAL_TRUST, FALSE);

	resolve_paths(msg, &old_path, &new_path);

	dbus_connection_emit_signal(conn, old_path,
					ADAPTER_INTERFACE, "TrustRemoved",
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);

	if (new_path) {
		struct device *device;
		gboolean trust = FALSE;

		device = adapter_get_device(adapter, address);
		if (device) {
			dbus_connection_emit_property_changed(conn,
					device->path, DEVICE_INTERFACE,
					"Trusted", DBUS_TYPE_BOOLEAN, &trust);
		}
	}

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult adapter_list_trusts(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	GSList *trusts, *l;
	char **addrs;
	bdaddr_t local;
	int len;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(adapter->address, &local);

	trusts = list_trusts(&local, GLOBAL_TRUST);

	addrs = g_new(char *, g_slist_length(trusts));

	for (l = trusts, len = 0; l; l = l->next, len++)
		addrs[len] = l->data;

	dbus_message_append_args(reply,
			DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
			&addrs, len,
			DBUS_TYPE_INVALID);

	g_free(addrs);
	g_slist_foreach(trusts, (GFunc) g_free, NULL);
	g_slist_free(trusts);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *property;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t ba;
	char str[249];

	if (check_address(adapter->address) < 0)
		return error_not_ready(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	property = adapter->address;
	dbus_message_iter_append_dict_entry(&dict, "Address",
			DBUS_TYPE_STRING, &property);

	/* Name */
	memset(str, 0, sizeof(str));
	property = str;
	str2ba(adapter->address, &ba);

	if (!read_local_name(&ba, str))
		dbus_message_iter_append_dict_entry(&dict, "Name",
			DBUS_TYPE_STRING, &property);

	/* Mode */
	property = mode2str(adapter->mode);

	dbus_message_iter_append_dict_entry(&dict, "Mode",
			DBUS_TYPE_STRING, &property);

	/* DiscoverableTimeout */
	dbus_message_iter_append_dict_entry(&dict, "DiscoverableTimeout",
				DBUS_TYPE_UINT32, &adapter->discov_timeout);

	/* PeriodicDiscovery */
	dbus_message_iter_append_dict_entry(&dict, "PeriodicDiscovery",
				DBUS_TYPE_BOOLEAN, &adapter->pdiscov_active);

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return error_invalid_arguments(conn, msg, NULL);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return error_invalid_arguments(conn, msg, NULL);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return error_invalid_arguments(conn, msg, NULL);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Name", property)) {
		const char *name;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return error_invalid_arguments(conn, msg, NULL);
		dbus_message_iter_get_basic(&sub, &name);

		return set_name(conn, msg, name, data);
	} else if (g_str_equal("DiscoverableTimeout", property)) {
		uint32_t timeout;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32)
			return error_invalid_arguments(conn, msg, NULL);
		dbus_message_iter_get_basic(&sub, &timeout);

		return set_discoverable_timeout(conn, msg, timeout, data);
	} else if (g_str_equal("PeriodicDiscovery", property)) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return error_invalid_arguments(conn, msg, NULL);
		dbus_message_iter_get_basic(&sub, &value);

		if (value)
			return adapter_start_periodic(conn, msg, data);
		else
			return adapter_stop_periodic(conn, msg, data);
	} else if (g_str_equal("Mode", property)) {
		const char *mode;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return error_invalid_arguments(conn, msg, NULL);
		dbus_message_iter_get_basic(&sub, &mode);

		return set_mode(conn, msg, mode, data);
	}

	return error_invalid_arguments(conn, msg, NULL);
}

void request_mode_cb(struct agent *agent, DBusError *err, void *data)
{
	struct mode_req *req = data;
	DBusMessage *derr;

	if (err && dbus_error_is_set(err)) {
		derr = dbus_message_new_error(req->msg, err->name, err->message);
		dbus_connection_send_and_unref(req->conn, derr);
		goto cleanup;
	}

	set_mode(req->conn, req->msg, req->mode, req->adapter);

cleanup:
	dbus_connection_unref(req->conn);
	dbus_message_unref(req->msg);
	g_free(req->mode);
	g_free(req);
}

static DBusHandlerResult request_mode(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *mode;
	struct adapter *adapter = data;
	DBusMessage *reply;
	struct mode_req *req;
	uint8_t new_mode;
	int ret;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &mode,
						DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	new_mode = str2mode(adapter->address, mode);
	if (new_mode != MODE_CONNECTABLE && new_mode != MODE_DISCOVERABLE)
		return error_invalid_arguments(conn, msg, NULL);

	/* No need to change mode */
	if (adapter->mode >= new_mode) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		return send_message_and_unref(conn, reply);
	}

	if (!adapter->agent)
		return error_failed(conn, msg, "No agent registered");

	req = g_new0(struct mode_req, 1);
	req->adapter = adapter;
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->mode = g_strdup(mode);
	ret = agent_confirm_mode_change(adapter->agent, mode, request_mode_cb,
					req);
	if (ret < 0) {
		dbus_connection_unref(req->conn);
		dbus_message_unref(req->msg);
		g_free(req->mode);
		g_free(req);
		return error_invalid_arguments(conn, msg, NULL);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult list_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	GSList *l;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapter->devices; l; l = l->next) {
		struct device *device = l->data;
		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_OBJECT_PATH, &device->path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static void create_device_exit(const char *name, struct adapter *adapter)
{
	create_device_req_free(adapter->create);
	adapter->create = NULL;
}

static void discover_services_cb(gpointer user_data, sdp_list_t *recs, int err)
{
	sdp_list_t *seq, *next, *svcclass;
	struct adapter *adapter = user_data;
	struct device *device;
	DBusMessage *reply;
	GSList *uuids;
	bdaddr_t src, dst;

	/* Onwer exitted? */
	if  (!adapter->create) {
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);
		return;
	}

	if (err < 0) {
		error_connection_attempt_failed(adapter->create->conn,
						adapter->create->msg, -err);
		goto failed;
	}

	uuids = NULL;
	for (seq = recs; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;

		if (!rec)
			break;

		svcclass = NULL;
		if (sdp_get_service_classes(rec, &svcclass) == 0) {
			/* Extract the first element and skip the remainning */
			gchar *uuid_str = bt_uuid2string(svcclass->data);
			if (uuid_str) {
				if (!g_slist_find_custom(uuids, uuid_str,
							(GCompareFunc) strcmp))
					uuids = g_slist_insert_sorted(uuids,
						uuid_str, (GCompareFunc) strcmp);
				else
					g_free(uuid_str);
			}
			sdp_list_free(svcclass, free);
		}

		next = seq->next;
	}

	sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	device = device_create(adapter->create->conn, adapter,
				adapter->create->address, uuids);
	if (!device)
		goto failed;

	/* Reply create device request */
	reply = dbus_message_new_method_return(adapter->create->msg);
	if (!reply)
		goto failed;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &device->path,
					DBUS_TYPE_INVALID);
	send_message_and_unref(adapter->create->conn, reply);

	dbus_connection_emit_signal(adapter->create->conn,
				dbus_message_get_path(adapter->create->msg),
				ADAPTER_INTERFACE,
				"DeviceCreated",
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);

	adapter->devices = g_slist_append(adapter->devices, device);

	/* Store the device's profiles in the filesystem */
	str2ba(adapter->address, &src);
	str2ba(adapter->create->address, &dst);
	if (uuids) {
		gchar *str = bt_list2string(uuids);
		write_device_profiles(&src, &dst, str);
		g_free(str);
	} else
		write_device_profiles(&src, &dst, "");

	if (adapter->create->agent_path)
		create_bonding(adapter->create->conn, adapter->create->msg,
				adapter->create->address,
				adapter->create->agent_path, adapter);

failed:
	name_listener_id_remove(adapter->create->id);
	create_device_req_free(adapter->create);
	adapter->create = NULL;
}

static DBusHandlerResult discover_services(DBusConnection *conn,
				DBusMessage *msg, const char *address,
				const char *agent_path, void *data)
{
	struct adapter *adapter = data;
	struct create_device_req *create;
	bdaddr_t src, dst;
	int err;
	GSList *l;

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	l = g_slist_find_custom(adapter->devices, address,
			(GCompareFunc) device_address_cmp);
	if (l && agent_path)
		return create_bonding(conn, msg, address, agent_path, data);
	else if (l && !agent_path)
		return error_already_exists(conn, msg, "Device already exists");

	if (adapter->create) {
		adapter->create->agent_path = g_strdup(agent_path);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(adapter->address, &src);
	str2ba(address, &dst);
	err = bt_discover_services(&src, &dst,
			discover_services_cb, adapter, NULL);
	if (err < 0) {
		error("Discover services failed!");
		return error_connection_attempt_failed(conn, msg, -err);
	}

	create = g_new0(struct create_device_req, 1);
	create->conn = dbus_connection_ref(conn);
	create->msg = dbus_message_ref(msg);
	create->id = name_listener_add(conn,
			dbus_message_get_sender(msg),
			(name_cb_t) create_device_exit, adapter);
	strcpy(create->address, address);
	create->agent_path = g_strdup(agent_path);
	adapter->create = create;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const gchar *address;

	if (adapter->create)
		return error_in_progress(conn, msg, "CreateDevice in progress");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg, NULL);

	return discover_services(conn, msg, address, NULL, data);
}

static DBusHandlerResult create_paired_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const gchar *address, *agent_path;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_OBJECT_PATH,
						&agent_path,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg, NULL);

	return discover_services(conn, msg, address, agent_path, data);
}

static gint device_path_cmp(struct device *device, const gchar *path)
{
	return strcasecmp(device->path, path);
}

static DBusHandlerResult remove_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	DBusMessage *reply;
	const char *path;
	GSList *l;
	bdaddr_t src;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg, NULL);

	l = g_slist_find_custom(adapter->devices,
			path, (GCompareFunc) device_path_cmp);
	if (!l)
		return error_device_does_not_exist(conn, msg);

	device = l->data;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(adapter->address, &src);
	delete_entry(&src, "profiles", device->address);
	delete_entry(&src, "linkkey", device->address);

	dbus_connection_emit_signal(conn,
			dbus_message_get_path(msg),
			ADAPTER_INTERFACE,
			"DeviceRemoved",
			DBUS_TYPE_OBJECT_PATH, &device->path,
			DBUS_TYPE_INVALID);

	device_destroy(device, conn);
	adapter->devices = g_slist_remove(adapter->devices, device);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult find_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	DBusMessage *reply;
	const gchar *address;
	GSList *l;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	l = g_slist_find_custom(adapter->devices,
			address, (GCompareFunc) device_address_cmp);
	if (!l)
		return error_device_does_not_exist(conn, msg);

	device = l->data;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void agent_exited(const char *name, struct adapter *adapter)
{
	debug("Agent %s exited without calling Unregister", name);

	agent_destroy(adapter->agent, TRUE);

	adapter->agent = NULL;
}

static void agent_removed(struct agent *agent, struct adapter *adapter)
{
	if (adapter->agent == agent)
		adapter->agent = NULL;
}

static DBusHandlerResult register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *name;
	struct agent *agent;
	struct adapter *adapter = data;
	DBusMessage *reply;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (adapter->agent)
		return error_already_exists(conn, msg, "Agent already exists");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	name = dbus_message_get_sender(msg);

	agent = agent_create(adapter, name, path, NULL,
				(agent_remove_cb) agent_removed, adapter);
	if (!agent) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, "Failed to create a new agent");
	}

	adapter->agent = agent;

	name_listener_add(conn, name, (name_cb_t) agent_exited, adapter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *name;
	struct adapter *adapter = data;
	DBusMessage *reply;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	name = dbus_message_get_sender(msg);

	if (!adapter->agent || !agent_matches(adapter->agent, name, path))
		return error_does_not_exist(conn, msg, "No such agent");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	name_listener_remove(conn, name, (name_cb_t) agent_exited,
				adapter);

	agent_destroy(adapter->agent, FALSE);
	adapter->agent = NULL;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	const char *sender, *record;
	dbus_uint32_t handle;
	bdaddr_t src;
	int err;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg, NULL);

	sender = dbus_message_get_sender(msg);
	str2ba(adapter->address, &src);
	err = add_xml_record(conn, sender, &src, record, &handle);
	if (err < 0)
		return error_failed_errno(conn, msg, err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &handle,
							DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult update_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	bdaddr_t src;

	str2ba(adapter->address, &src);

	return update_xml_record(conn, msg, &src);
}

static DBusHandlerResult remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t handle;
	const char *sender;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &handle,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg, NULL);

	sender = dbus_message_get_sender(msg);

	if (remove_record(conn, sender, handle) < 0)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
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
	uint8_t minor_index;

	switch (major_index) {
	case 1: /* computer */
		minor_index = (class >> 2) & 0x3F;
		if (minor_index < NUM_ELEMENTS(computer_minor_cls))
			return computer_minor_cls[minor_index];
		else
			return "";
	case 2: /* phone */
		minor_index = (class >> 2) & 0x3F;
		if (minor_index < NUM_ELEMENTS(phone_minor_cls))
			return phone_minor_cls[minor_index];
		return "";
	case 3: /* access point */
		minor_index = (class >> 5) & 0x07;
		if (minor_index < NUM_ELEMENTS(access_point_minor_cls))
			return access_point_minor_cls[minor_index];
		else
			return "";
	case 4: /* audio/video */
		minor_index = (class >> 2) & 0x3F;
		if (minor_index < NUM_ELEMENTS(audio_video_minor_cls))
			return audio_video_minor_cls[minor_index];
		else
			return "";
	case 5: /* peripheral */
		minor_index = (class >> 6) & 0x03;
		if (minor_index < NUM_ELEMENTS(peripheral_minor_cls))
			return peripheral_minor_cls[minor_index];
		else
			return "";
	case 6: /* imaging */
		{
			uint8_t shift_minor = 0;

			minor_index = (class >> 4) & 0x0F;
			while (shift_minor < (sizeof(imaging_minor_cls) / sizeof(*imaging_minor_cls))) {
				if (((minor_index >> shift_minor) & 0x01) == 0x01)
					return imaging_minor_cls[shift_minor];
				shift_minor++;
			}
		}
		break;
	case 7: /* wearable */
		minor_index = (class >> 2) & 0x3F;
		if (minor_index < NUM_ELEMENTS(wearable_minor_cls))
			return wearable_minor_cls[minor_index];
		else
			return "";
	case 8: /* toy */
		minor_index = (class >> 2) & 0x3F;
		if (minor_index < NUM_ELEMENTS(toy_minor_cls))
			return toy_minor_cls[minor_index];
		else
			return "";
	}

	return "";
}

GSList *service_classes_str(uint32_t class)
{
	uint8_t services = class >> 16;
	GSList *l = NULL;
	int i;

	for (i = 0; i < (sizeof(service_cls) / sizeof(*service_cls)); i++) {
		if (!(services & (1 << i)))
			continue;

		l = g_slist_append(l, (void *) service_cls[i]);
	}

	return l;
}

/* BlueZ 4.0 API */
static DBusMethodVTable adapter_methods[] = {
	{ "GetProperties",	get_properties,		"",	"a{sv}" },
	{ "SetProperty",	set_property,		"sv",	""	},
	{ "RequestMode",	request_mode,		"s",	""	},
	{ "DiscoverDevices",	adapter_discover_devices, "",	""	},
	{ "CancelDiscovery",	adapter_cancel_discovery, "",	""	},
	{ "ListDevices",	list_devices,		"",	"ao"	},
	{ "CreateDevice",	create_device,		"s",	"o"	},
	{ "CreatePairedDevice",	create_paired_device,	"so",	"o"	},
	{ "RemoveDevice",	remove_device,		"o",	""	},
	{ "FindDevice",		find_device,		"s",	"o"	},
	{ "RegisterAgent",	register_agent,		"o",	""	},
	{ "UnregisterAgent",	unregister_agent,	"o",	""	},
	{ "AddServiceRecord",	add_service_record,	"s",	"u"	},
	{ "UpdateServiceRecord",update_service_record,	"us",	""	},
	{ "RemoveServiceRecord",remove_service_record,	"u",	""	},
	{ NULL,			NULL,			NULL, NULL	}
};

/* Deprecated */
static DBusMethodVTable old_adapter_methods[] = {
	{ "GetInfo",				adapter_get_info,
		"",	"a{sv}"	},
	{ "GetAddress",				adapter_get_address,
		"",	"s"	},
	{ "GetVersion",				adapter_get_version,
		"",	"s"	},
	{ "GetRevision",			adapter_get_revision,
		"",	"s"	},
	{ "GetManufacturer",			adapter_get_manufacturer,
		"",	"s"	},
	{ "GetCompany",				adapter_get_company,
		"",	"s"	},
	{ "ListAvailableModes",			adapter_list_modes,
		"",	"as"	},
	{ "GetMode",				adapter_get_mode,
		"",	"s"	},
	{ "SetMode",				adapter_set_mode,
		"s",	""	},
	{ "GetDiscoverableTimeout",		adapter_get_discoverable_to,
		"",	"u"	},
	{ "SetDiscoverableTimeout",		adapter_set_discoverable_to,
		"u",	""	},
	{ "IsConnectable",			adapter_is_connectable,
		"",	"b"	},
	{ "IsDiscoverable",			adapter_is_discoverable,
		"",	"b"	},
	{ "IsConnected",			adapter_is_connected,
		"s",	"b"	},
	{ "ListConnections",			adapter_list_connections,
		"",	"as"	},
	{ "GetMajorClass",			adapter_get_major_class,
		"",	"s"	},
	{ "ListAvailableMinorClasses",		adapter_list_minor_classes,
		"",	"as"	},
	{ "GetMinorClass",			adapter_get_minor_class,
		"",	"s"	},
	{ "SetMinorClass",			adapter_set_minor_class,
		"s",	""	},
	{ "GetServiceClasses",			adapter_get_service_classes,
		"",	"as"	},
	{ "GetName",				adapter_get_name,
		"",	"s"	},
	{ "SetName",				adapter_set_name,
		"s",	""	},

	{ "GetRemoteInfo",			adapter_get_remote_info,
		"s",	"a{sv}"	},
	{ "GetRemoteServiceRecord",		adapter_get_remote_svc,
		"su",	"ay"	},
	{ "GetRemoteServiceRecordAsXML",	adapter_get_remote_svc_xml,
		"su",	"s"	},
	{ "GetRemoteServiceHandles",		adapter_get_remote_svc_handles,
		"ss",	"au"	},
	{ "GetRemoteServiceIdentifiers",	adapter_get_remote_svc_identifiers,
		"s",	"as"	},
	{ "FinishRemoteServiceTransaction",	adapter_finish_sdp_transact,
		"s",	""	},

	{ "GetRemoteVersion",			adapter_get_remote_version,
		"s",	"s"	},
	{ "GetRemoteRevision",			adapter_get_remote_revision,
		"s",	"s"	},
	{ "GetRemoteManufacturer",		adapter_get_remote_manufacturer,
		"s",	"s"	},
	{ "GetRemoteCompany",			adapter_get_remote_company,
		"s",	"s"	},
	{ "GetRemoteMajorClass",		adapter_get_remote_major_class,
		"s",	"s"	},
	{ "GetRemoteMinorClass",		adapter_get_remote_minor_class,
		"s",	"s"	},
	{ "GetRemoteServiceClasses",		adapter_get_remote_service_cls,
		"s",	"as"	},
	{ "GetRemoteClass",			adapter_get_remote_class,
		"s",	"u"	},
	{ "GetRemoteFeatures",			adapter_get_remote_features,
		"s",	"ay"	},
	{ "GetRemoteName",			adapter_get_remote_name,
		"s",	"s"	},
	{ "GetRemoteAlias",			adapter_get_remote_alias,
		"s",	"s"	},
	{ "SetRemoteAlias",			adapter_set_remote_alias,
		"ss",	""	},
	{ "ClearRemoteAlias",			adapter_clear_remote_alias,
		"s",	""	},

	{ "LastSeen",				adapter_last_seen,
		"s",	"s"	},
	{ "LastUsed",				adapter_last_used,
		"s",	"s"	},

	{ "DisconnectRemoteDevice",		adapter_dc_remote_device,
		"s",	""	},

	{ "CreateBonding",			adapter_create_bonding,
		"s",	""	},
	{ "CancelBondingProcess",		adapter_cancel_bonding,
		"s",	""	},
	{ "RemoveBonding",			adapter_remove_bonding,
		"s",	""	},
	{ "HasBonding",				adapter_has_bonding,
		"s",	"b"	},
	{ "ListBondings",			adapter_list_bondings,
		"",	"as"	},
	{ "GetPinCodeLength",			adapter_get_pin_code_length,
		"s",	"y"	},
	{ "GetEncryptionKeySize",		adapter_get_encryption_key_size,
		"s",	"y"	},

	{ "StartPeriodicDiscovery",		adapter_start_periodic,
		"",	""	},
	{ "StopPeriodicDiscovery",		adapter_stop_periodic,
		"",	""	},
	{ "IsPeriodicDiscovery",		adapter_is_periodic,
		"",	"b"	},
	{ "SetPeriodicDiscoveryNameResolving",	adapter_set_pdiscov_resolve,
		"b",	""	},
	{ "GetPeriodicDiscoveryNameResolving",	adapter_get_pdiscov_resolve,
		"",	"b"	},
	{ "DiscoverDevicesWithoutNameResolving",	adapter_discover_devices,
		"",	""	},
	{ "ListRemoteDevices",			adapter_list_remote_devices,
		"",	"as"	},
	{ "ListRecentRemoteDevices",		adapter_list_recent_remote_devices,
		"s",	"as"	},

	{ "SetTrusted",				adapter_set_trusted,
		"s",	""	},
	{ "IsTrusted",				adapter_is_trusted,
		"s",	"b"	},
	{ "RemoveTrust",			adapter_remove_trust,
		"s",	""	},
	{ "ListTrusts",				adapter_list_trusts,
		"",	"as"	},

	{ NULL, NULL, NULL, NULL }
};

/* BlueZ 4.X */
static DBusSignalVTable adapter_signals[] = {
	{ "DiscoveryStarted",		""		},
	{ "DiscoveryCompleted",		""		},
	{ "DeviceCreated",		"o"		},
	{ "DeviceRemoved",		"o"		},
	{ "DeviceFound",		"sa{sv}"	},
	{ "PropertyChanged",		"sv"		},
	{ "DeviceDisappeared",		"s"		},
	{ NULL,				NULL		}
};

/* Deprecated */
static DBusSignalVTable old_adapter_signals[] = {
	{ "DiscoveryStarted",			""	},
	{ "DiscoveryCompleted",			""	},
	{ "ModeChanged",			"s"	},
	{ "DiscoverableTimeoutChanged",		"u"	},
	{ "MinorClassChanged",			"s"	},
	{ "NameChanged",			"s"	},
	{ "PeriodicDiscoveryStarted",		""	},
	{ "PeriodicDiscoveryStopped",		""	},
	{ "RemoteDeviceFound",			"sun"	},
	{ "RemoteDeviceDisappeared",		"s"	},
	{ "RemoteClassUpdated",			"su"	},
	{ "RemoteNameUpdated",			"ss"	},
	{ "RemoteNameFailed",			"s"	},
	{ "RemoteNameRequested",		"s"	},
	{ "RemoteAliasChanged",			"ss"	},
	{ "RemoteAliasCleared",			"s"	},
	{ "RemoteDeviceConnected",		"s"	},
	{ "RemoteDeviceDisconnectRequested",	"s"	},
	{ "RemoteDeviceDisconnected",		"s"	},
	{ "RemoteIdentifiersUpdated",		"sas"	},
	{ "BondingCreated",			"s"	},
	{ "BondingRemoved",			"s"	},
	{ "TrustAdded",				"s"	},
	{ "TrustRemoved",			"s"	},
	{ NULL, NULL }
};

dbus_bool_t adapter_init(DBusConnection *conn, const char *path)
{
	if (hcid_dbus_use_experimental())
		dbus_connection_register_interface(conn,
					path + ADAPTER_PATH_INDEX, ADAPTER_INTERFACE,
					adapter_methods, adapter_signals, NULL);

	return dbus_connection_register_interface(conn,
			path, ADAPTER_INTERFACE,
			old_adapter_methods, old_adapter_signals, NULL);
}
