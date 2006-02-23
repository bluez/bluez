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

static const char *computer_minor_cls[] = {
	"uncategorized",
	"desktop",
	"server",
	"laptop",
	"handheld",
	"palm",
	"wearable"
};

static char *get_peer_name(const bdaddr_t *local, const bdaddr_t *peer)
{
	char filename[PATH_MAX + 1], addr[18];

	ba2str(local, addr);
	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, addr);

	ba2str(peer, addr);
	return textfile_get(filename, addr);
}

static DBusMessage* handle_dev_get_address_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[18], *str_ptr = str;

	get_device_address(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_version_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[20], *str_ptr = str;

	get_device_version(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_revision_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;

	get_device_revision(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_major_class_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *str_ptr = "computer";

	reply = dbus_message_new_method_return(msg);

	/*FIXME: Check the real device major class */
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_manufacturer_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;

	get_device_manufacturer(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_company_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[64], *str_ptr = str;

	get_device_company(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_features_req(DBusMessage *msg, void *data)
{
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_get_name_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	char str[249], *str_ptr = str;

	get_device_name(dbus_data->dev_id, str, sizeof(str));

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_set_name_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *str_ptr;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_ptr);

	if (strlen(str_ptr) == 0) {
		syslog(LOG_ERR, "Name change failed: Invalid parameter");
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
	}

	set_device_name(dbus_data->dev_id, str_ptr);

	reply = dbus_message_new_method_return(msg);

	return reply;
}

static DBusMessage* handle_dev_get_remote_alias_req(DBusMessage *msg, void *data)
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
		return bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET | -err);

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &str_ptr,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_set_remote_alias_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusConnection *connection = get_dbus_connection();
	DBusMessageIter iter;
	DBusMessage *reply, *signal;
	char *str_ptr, *addr_ptr;
	bdaddr_t bdaddr;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &str_ptr);

	if (strlen(str_ptr) == 0) {
		syslog(LOG_ERR, "Alias change failed: Invalid parameter");
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
	}

	str2ba(addr_ptr, &bdaddr);

	set_device_alias(dbus_data->dev_id, &bdaddr, str_ptr);

	signal = dev_signal_factory(dbus_data->dev_id, DEV_SIG_REMOTE_ALIAS_CHANGED,
						DBUS_TYPE_STRING, &addr_ptr,
						DBUS_TYPE_STRING, &str_ptr,
						DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(connection, signal, NULL);
		dbus_connection_flush(connection);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);

	return reply;
}

static DBusMessage* handle_dev_get_discoverable_to_req(DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &dbus_data->discoverable_timeout,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_get_mode_req(DBusMessage *msg, void *data)
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

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_is_connectable_req(DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	const uint8_t hci_mode = dbus_data->mode;
	dbus_bool_t connectable = FALSE;

	if (hci_mode & SCAN_PAGE)
		connectable = TRUE;

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connectable,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_is_discoverable_req(DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	const uint8_t hci_mode = dbus_data->mode;
	dbus_bool_t discoverable = FALSE;

	if (hci_mode & SCAN_INQUIRY)
		discoverable = TRUE;

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &discoverable,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_set_class_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_set_discoverable_to_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	uint32_t timeout;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &timeout);

	dbus_data->discoverable_timeout = timeout;

	reply = dbus_message_new_method_return(msg);

	return reply;
}

static DBusMessage* handle_dev_set_minor_class_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	const char *minor;
	uint8_t cls[3];
	uint32_t dev_class = 0xFFFFFFFF;
	int i, dd;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &minor);

	if (!minor)
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);

	/* FIXME: currently, only computer minor classes are allowed */
	for (i = 0; i < sizeof(computer_minor_cls) / sizeof(*computer_minor_cls); i++)
		if (!strcasecmp(minor, computer_minor_cls[i])) {
			/* Remove the format type */
			dev_class = i << 2;
			break;
		}

	/* Check if it's a valid minor class */
	if (dev_class == 0xFFFFFFFF)
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", dbus_data->dev_id);
		return bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
	}

	if (hci_read_class_of_dev(dd, cls, 1000) < 0) {
		syslog(LOG_ERR, "Can't read class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET | errno);
		goto failed;
	}

	dev_class |= (cls[2] << 16) | (cls[1] << 8);

	if (hci_write_class_of_dev(dd, dev_class, 2000) < 0) {
		syslog(LOG_ERR, "Can't write class of device on hci%d: %s(%d)",
				dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET | errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	hci_close_dev(dd);

	return reply;
}

static DBusMessage* handle_dev_set_mode_req(DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	struct hci_request rq;
	int dd = -1;
	const char* scan_mode;
	uint8_t hci_mode;
	uint8_t status = 0;
	const uint8_t current_mode = dbus_data->mode;

	dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &scan_mode,
					DBUS_TYPE_INVALID);

	if (!scan_mode)
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);

	if (strcasecmp(MODE_OFF, scan_mode) == 0)
		hci_mode = SCAN_DISABLED;
	else if (strcasecmp(MODE_CONNECTABLE, scan_mode) == 0)
		hci_mode = SCAN_PAGE;
	else if (strcasecmp(MODE_DISCOVERABLE, scan_mode) == 0)
		hci_mode = (SCAN_PAGE | SCAN_INQUIRY);
	else
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", dbus_data->dev_id);
		return bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
	}

	/* Check if the new requested mode is different from the current */
	if (current_mode != hci_mode) {
		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_WRITE_SCAN_ENABLE;
		rq.cparam = &hci_mode;
		rq.clen   = sizeof(hci_mode);
		rq.rparam = &status;
		rq.rlen   = sizeof(status);

		if (hci_send_req(dd, &rq, 100) < 0) {
			syslog(LOG_ERR, "Sending write scan enable command failed: %s (%d)",
							strerror(errno), errno);
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET | errno);
			goto failed;
		}
		if (status) {
			syslog(LOG_ERR, "Setting scan enable failed with status 0x%02x", status);
			reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET | status);
			goto failed;
		}

	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	return reply;
}

static DBusMessage* handle_dev_discover_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	int dd = -1;
	uint8_t length = 8, num_rsp = 0;
	uint32_t lap = 0x9e8b33;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

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
		syslog(LOG_ERR, "Unable to start inquiry: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return reply;

}

static DBusMessage* handle_dev_discover_cache_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_discover_cancel_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	uint8_t status;
	int dd = -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY_CANCEL;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending cancel inquiry failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (status) {
		syslog(LOG_ERR, "Cancel inquiry failed with status 0x%02x", status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return reply;
}

static DBusMessage* handle_dev_discover_service_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_last_seen_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_last_used_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_get_remote_name_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	const char *str_bdaddr;
	char *name;
	bdaddr_t bdaddr;
	struct hci_dev_info di;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str_bdaddr,
							DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	if (hci_devinfo(dbus_data->dev_id, &di) < 0) {
		syslog(LOG_ERR, "Can't get device info");
		return bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
	}

	name = get_peer_name(&di.bdaddr, &bdaddr);
	if (!name)
		return bluez_new_failure_msg(msg, BLUEZ_EDBUS_RECORD_NOT_FOUND);

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	free(name);

	return reply;
}

static DBusMessage* handle_dev_get_remote_version_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_create_bonding_req(DBusMessage *msg, void *data)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	DBusMessage *reply = NULL;
	char *str_bdaddr = NULL;
	struct hci_dbus_data *dbus_data = data;
	struct hci_conn_info_req *cr = NULL;
	bdaddr_t bdaddr;
	int dev_id = -1;
	int dd = -1;

	dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &str_bdaddr,
					DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	if (dbus_data->dev_id != dev_id) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_NO_MEM);
		goto failed;
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;

	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
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
		syslog(LOG_ERR, "Unable to send authentication request: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	if (cr)
		free(cr);

	return reply;
}

static DBusMessage* handle_dev_list_bondings_req(DBusMessage *msg, void *data)
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

	return reply;
}

static DBusMessage* handle_dev_has_bonding_req(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char filename[PATH_MAX + 1];
	char addr[18], *addr_ptr, *str;
	dbus_bool_t result = FALSE;

	get_device_address(dbus_data->dev_id, addr, sizeof(addr));

	snprintf(filename, PATH_MAX, "%s/%s/linkkeys", STORAGEDIR, addr);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &addr_ptr);

	str = textfile_get(filename, addr_ptr);
	result = str ? TRUE : FALSE;
	free(str);

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &result,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage* handle_dev_remove_bonding_req(DBusMessage *msg, void *data)
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
		return bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);

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
		syslog(LOG_ERR, "Can't allocate memory");
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_NO_MEM);
		goto failed;
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		/* Ignore when there isn't active connections, return success */
		reply = dbus_message_new_method_return(msg);
		goto failed;
	}

	/* Send the HCI disconnect command */
	if (hci_disconnect(dd, htobs(cr->conn_info->handle), HCI_OE_USER_ENDED_CONNECTION, 1000) < 0) {
		syslog(LOG_ERR, "Disconnect failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET | errno);
		goto failed;
	}

	/* FIXME: which condition must be verified before send the signal */
	signal = dev_signal_factory(dbus_data->dev_id,
					DEV_SIG_BONDING_REMOVED,
					DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);
	if (signal) {
		dbus_connection_send(connection, signal, NULL);
		dbus_connection_flush(connection);
		dbus_message_unref(signal);
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	if (cr)
		free(cr);

	return reply;
}

static DBusMessage* handle_dev_pin_code_length_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static DBusMessage* handle_dev_encryption_key_size_req(DBusMessage *msg, void *data)
{
	/*FIXME: */
	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

static const struct service_data dev_services[] = {
	{ DEV_GET_ADDRESS,		handle_dev_get_address_req,		DEV_GET_ADDRESS_SIGNATURE		},
	{ DEV_GET_COMPANY,		handle_dev_get_company_req,		DEV_GET_COMPANY_SIGNATURE		},
	{ DEV_GET_DISCOVERABLE_TO,	handle_dev_get_discoverable_to_req,	DEV_GET_DISCOVERABLE_TO_SIGNATURE	},
	{ DEV_GET_FEATURES,		handle_dev_get_features_req,		DEV_GET_FEATURES_SIGNATURE		},
	{ DEV_GET_MAJOR_CLASS,		handle_dev_get_major_class_req,		DEV_GET_MAJOR_CLASS_SIGNATURE		},
	{ DEV_GET_MANUFACTURER,		handle_dev_get_manufacturer_req,	DEV_GET_MANUFACTURER_SIGNATURE		},
	{ DEV_GET_MODE,			handle_dev_get_mode_req,		DEV_GET_MODE_SIGNATURE			},
	{ DEV_GET_NAME,			handle_dev_get_name_req,		DEV_GET_NAME_SIGNATURE			},
	{ DEV_GET_REVISION,		handle_dev_get_revision_req,		DEV_GET_REVISION_SIGNATURE		},
	{ DEV_GET_VERSION,		handle_dev_get_version_req,		DEV_GET_VERSION_SIGNATURE		},

	{ DEV_IS_CONNECTABLE,		handle_dev_is_connectable_req,		DEV_IS_CONNECTABLE_SIGNATURE		},
	{ DEV_IS_DISCOVERABLE,		handle_dev_is_discoverable_req,		DEV_IS_DISCOVERABLE_SIGNATURE		},

	{ DEV_SET_CLASS,		handle_dev_set_class_req,		DEV_SET_CLASS_SIGNATURE			},
	{ DEV_SET_DISCOVERABLE_TO,	handle_dev_set_discoverable_to_req,	DEV_SET_DISCOVERABLE_TO_SIGNATURE	},
	{ DEV_SET_MINOR_CLASS,		handle_dev_set_minor_class_req,		DEV_SET_MINOR_CLASS_SIGNATURE		},
	{ DEV_SET_MODE,			handle_dev_set_mode_req,		DEV_SET_MODE_SIGNATURE			},
	{ DEV_SET_NAME,			handle_dev_set_name_req,		DEV_SET_NAME_SIGNATURE			},

	{ DEV_DISCOVER,			handle_dev_discover_req,		DEV_DISCOVER_SIGNATURE			},
	{ DEV_DISCOVER_CACHE,		handle_dev_discover_cache_req,		DEV_DISCOVER_CACHE_SIGNATURE		},
	{ DEV_DISCOVER_CANCEL,		handle_dev_discover_cancel_req,		DEV_DISCOVER_CANCEL_SIGNATURE		},
	{ DEV_DISCOVER_SERVICE,		handle_dev_discover_service_req,	DEV_DISCOVER_SERVICE_SIGNATURE		},

	{ DEV_LAST_SEEN,		handle_dev_last_seen_req,		DEV_LAST_SEEN_SIGNATURE			},
	{ DEV_LAST_USED,		handle_dev_last_used_req,		DEV_LAST_USED_SIGNATURE			},

	{ DEV_SET_REMOTE_ALIAS,		handle_dev_set_remote_alias_req,	DEV_SET_REMOTE_ALIAS_SIGNATURE		},
	{ DEV_GET_REMOTE_ALIAS,		handle_dev_get_remote_alias_req,	DEV_GET_REMOTE_ALIAS_SIGNATURE		},
	{ DEV_GET_REMOTE_NAME,		handle_dev_get_remote_name_req,		DEV_GET_REMOTE_NAME_SIGNATURE		},
	{ DEV_GET_REMOTE_VERSION,	handle_dev_get_remote_version_req,	DEV_GET_REMOTE_VERSION_SIGNATURE	},

	{ DEV_CREATE_BONDING,		handle_dev_create_bonding_req,		DEV_CREATE_BONDING_SIGNATURE		},
	{ DEV_LIST_BONDINGS,		handle_dev_list_bondings_req,		DEV_LIST_BONDINGS_SIGNATURE		},
	{ DEV_HAS_BONDING_NAME,		handle_dev_has_bonding_req,		DEV_HAS_BONDING_SIGNATURE		},
	{ DEV_REMOVE_BONDING,		handle_dev_remove_bonding_req,		DEV_REMOVE_BONDING_SIGNATURE		},

	{ DEV_PIN_CODE_LENGTH,		handle_dev_pin_code_length_req,		DEV_PIN_CODE_LENGTH_SIGNATURE		},
	{ DEV_ENCRYPTION_KEY_SIZE,	handle_dev_encryption_key_size_req,	DEV_ENCRYPTION_KEY_SIZE_SIGNATURE	},

	{ NULL, NULL, NULL}
};

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *handlers = dev_services;
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	const char *method;
	const char *signature;
	const char *iface;
	uint32_t error = BLUEZ_EDBUS_UNKNOWN_METHOD;

	method = dbus_message_get_member(msg);
	signature = dbus_message_get_signature(msg);
	iface = dbus_message_get_interface(msg);

	syslog(LOG_INFO, "[%s,%d] path:%s, method:%s", __PRETTY_FUNCTION__, __LINE__, dbus_message_get_path(msg), method);

	if (strcmp(DEVICE_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_data->path_id == DEVICE_ROOT_ID) {
		/* Device is down(path unregistered) or the path is wrong */
		error = BLUEZ_EDBUS_UNKNOWN_PATH;
		goto failed;
	}

	/* It's a device path id */
	for (; handlers->name != NULL; handlers++) {
		if (strcmp(handlers->name, method))
			continue;

		if (!strcmp(handlers->signature, signature)) {
			reply = handlers->handler_func(msg, data);
			error = 0;
			break;
		} else {
			/* Set the error, but continue looping incase there is
			 * another method with the same name but a different
			 * signature */
			error = BLUEZ_EDBUS_WRONG_SIGNATURE;
			continue;
		}
	}

failed:
	if (error)
		reply = bluez_new_failure_msg(msg, error);

	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL))
			syslog(LOG_ERR, "Can't send reply message!");
		dbus_message_unref(reply);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}
