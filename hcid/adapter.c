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
#include <gdbus.h>

#include "hcid.h"

#include "adapter.h"
#include "device.h"

#include "textfile.h"
#include "oui.h"
#include "dbus-common.h"
#include "dbus-hci.h"
#include "dbus-sdp.h"
#include "dbus-database.h"
#include "dbus-service.h"
#include "dbus-security.h"
#include "dbus-error.h"
#include "error.h"
#include "glib-helper.h"
#include "logging.h"
#include "agent.h"

#define NUM_ELEMENTS(table) (sizeof(table)/sizeof(const char *))

#define IO_CAPABILITY_DISPLAYONLY	0x00
#define IO_CAPABILITY_DISPLAYYESNO	0x01
#define IO_CAPABILITY_KEYBOARDONLY	0x02
#define IO_CAPABILITY_NOINPUTOUTPUT	0x03
#define IO_CAPABILITY_INVALID		0xFF

struct mode_req {
	struct adapter	*adapter;
	DBusConnection	*conn;		/* Connection reference */
	DBusMessage	*msg;		/* Message reference */
	uint8_t		mode;		/* Requested mode */
	guint		id;		/* Listener id */
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

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
			"Not Available");
}

static inline DBusMessage *adapter_not_ready(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotReady",
			"Adapter is not ready");
}

static inline DBusMessage *no_such_adapter(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
							"No such adapter");
}

static inline DBusMessage *failed_strerror(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
			strerror(err));
}

static inline DBusMessage *in_progress(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress", str);
}

static inline DBusMessage *not_in_progress(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotInProgress", str);
}

static inline DBusMessage *not_authorized(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAuthorized",
			"Not authorized");
}

static inline DBusMessage *unsupported_major_class(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".UnsupportedMajorClass",
			"Unsupported Major Class");
}

static int auth_req_cmp(const void *p1, const void *p2)
{
	const struct pending_auth_info *pb1 = p1;
	const bdaddr_t *bda = p2;

	return bda ? bacmp(&pb1->bdaddr, bda) : -1;
}

void adapter_auth_request_replied(struct adapter *adapter, bdaddr_t *dba)
{
	GSList *l;
	struct pending_auth_info *auth;

	l = g_slist_find_custom(adapter->auth_reqs, dba, auth_req_cmp);
	if (!l)
		return;

	auth = l->data;

	auth->replied = TRUE;
}

struct pending_auth_info *adapter_find_auth_request(struct adapter *adapter,
							bdaddr_t *dba)
{
	GSList *l;

	l = g_slist_find_custom(adapter->auth_reqs, dba, auth_req_cmp);
	if (l)
		return l->data;

	return NULL;
}

void adapter_remove_auth_request(struct adapter *adapter, bdaddr_t *dba)
{
	GSList *l;
	struct pending_auth_info *auth;

	l = g_slist_find_custom(adapter->auth_reqs, dba, auth_req_cmp);
	if (!l)
		return;

	auth = l->data;

	adapter->auth_reqs = g_slist_remove(adapter->auth_reqs, auth);

	g_free(auth);
}

struct pending_auth_info *adapter_new_auth_request(struct adapter *adapter,
							bdaddr_t *dba,
							auth_type_t type)
{
	struct pending_auth_info *info;

	debug("hcid_dbus_new_auth_request");

	info = g_new0(struct pending_auth_info, 1);

	bacpy(&info->bdaddr, dba);
	info->type = type;
	adapter->auth_reqs = g_slist_append(adapter->auth_reqs, info);

	if (adapter->bonding && !bacmp(dba, &adapter->bonding->bdaddr))
		adapter->bonding->auth_active = 1;

	return info;
}

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

static int auth_info_agent_cmp(const void *a, const void *b)
{
	const struct pending_auth_info *auth = a;
	const struct agent *agent = b;

	if (auth->agent == agent)
		return 0;

	return -1;
}

static void device_agent_removed(struct agent *agent, void *user_data)
{
	struct device *device = user_data;
	struct pending_auth_info *auth;
	GSList *l;

	device->agent = NULL;

	l = g_slist_find_custom(device->adapter->auth_reqs, agent,
					auth_info_agent_cmp);
	if (!l)
		return;

	auth = l->data;
	auth->agent = NULL;
}

static struct bonding_request_info *bonding_request_new(DBusConnection *conn,
							DBusMessage *msg,
							struct adapter *adapter,
							const char *address,
							const char *agent_path,
							uint8_t capability)
{
	struct bonding_request_info *bonding;
	struct device *device;
	const char *name = dbus_message_get_sender(msg);

	debug("bonding_request_new(%s)", address);

	device = adapter_get_device(conn, adapter, address);
	if (!device)
		return NULL;

	device->agent = agent_create(adapter, name, agent_path,
				capability, device_agent_removed, device);
	debug("Temporary agent registered for hci%d/%s at %s:%s",
			adapter->dev_id, device->address, name,
			agent_path);

	bonding = g_new0(struct bonding_request_info, 1);

	bonding->conn = dbus_connection_ref(conn);
	bonding->msg = dbus_message_ref(msg);
	bonding->adapter = adapter;

	str2ba(address, &bonding->bdaddr);

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

static DBusMessage *set_mode(DBusConnection *conn, DBusMessage *msg,
				uint8_t new_mode, void *data)
{
	struct adapter *adapter = data;
	uint8_t scan_enable;
	uint8_t current_scan = adapter->scan_enable;
	bdaddr_t local;
	gboolean limited;
	int err, dd;
	const char *mode;

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
		return invalid_args(msg);
	}

	/* Do reverse resolution in case of "on" mode */
	mode = mode2str(new_mode);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return no_such_adapter(msg);

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
			return failed_strerror(msg, err);
		}
	}

	if (adapter->up && scan_enable == SCAN_DISABLED &&
			hcid.offmode == HCID_OFFMODE_DEVDOWN) {
		if (ioctl(dd, HCIDEVDOWN, adapter->dev_id) < 0) {
			hci_close_dev(dd);
			return failed_strerror(msg, errno);
		}

		goto done;
	}

	limited = (new_mode == MODE_LIMITED ? TRUE : FALSE);
	err = set_limited_discoverable(dd, adapter->class, limited);
	if (err < 0) {
		hci_close_dev(dd);
		return failed_strerror(msg, -err);
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
			return failed_strerror(msg, err);
		}

		if (status) {
			error("Setting scan enable failed with status 0x%02x",
					status);
			hci_close_dev(dd);
			return failed_strerror(msg, bt_error(status));
		}
	} else {
		/* discoverable or limited */
		if ((scan_enable & SCAN_INQUIRY) && (new_mode != adapter->mode)) {
			g_dbus_emit_signal(conn,
					dbus_message_get_path(msg),
					ADAPTER_INTERFACE,
					"ModeChanged",
					DBUS_TYPE_STRING, &mode,
					DBUS_TYPE_INVALID);

			if (adapter->timeout_id)
				g_source_remove(adapter->timeout_id);

			if (!adapter->sessions && !adapter->discov_timeout)
				adapter->timeout_id = g_timeout_add(adapter->discov_timeout * 1000,
						discov_timeout_handler, adapter);
		}
	}
done:
	str2ba(adapter->address, &local);
	write_device_mode(&local, mode);

	hci_close_dev(dd);

	adapter->mode = new_mode;

	return dbus_message_new_method_return(msg);
}

gint find_session(struct mode_req *req, DBusMessage *msg)
{
	const char *name = dbus_message_get_sender(req->msg);
	const char *sender = dbus_message_get_sender(msg);

	return strcmp(name, sender);
}

static void confirm_mode_cb(struct agent *agent, DBusError *err, void *data)
{
	struct mode_req *req = data;
	DBusMessage *reply;

	if (err && dbus_error_is_set(err)) {
		reply = dbus_message_new_error(req->msg, err->name, err->message);
		dbus_connection_send(req->conn, reply, NULL);
		dbus_message_unref(reply);
		goto cleanup;
	}

	reply = set_mode(req->conn, req->msg, req->mode, req->adapter);
	dbus_connection_send(req->conn, reply, NULL);
	dbus_message_unref(reply);

	if (!g_slist_find_custom(req->adapter->sessions, req->msg,
			(GCompareFunc) find_session))
		goto cleanup;

	return;

cleanup:
	dbus_message_unref(req->msg);
	if (req->id)
		g_dbus_remove_watch(req->conn, req->id);
	dbus_connection_unref(req->conn);
	g_free(req);
}

static DBusMessage *confirm_mode(DBusConnection *conn, DBusMessage *msg,
					const char *mode, void *data)
{
	struct adapter *adapter = data;
	struct mode_req *req;
	int ret;

	if (!adapter->agent)
		return dbus_message_new_method_return(msg);

	req = g_new0(struct mode_req, 1);
	req->adapter = adapter;
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->mode = str2mode(adapter->address, mode);

	ret = agent_confirm_mode_change(adapter->agent, mode, confirm_mode_cb,
					req);
	if (ret < 0) {
		dbus_connection_unref(req->conn);
		dbus_message_unref(req->msg);
		g_free(req);
		return invalid_args(msg);
	}

	return NULL;
}

static DBusMessage *set_discoverable_timeout(DBusConnection *conn,
							DBusMessage *msg,
							uint32_t timeout,
							void *data)
{
	struct adapter *adapter = data;
	bdaddr_t bdaddr;
	const char *path;

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

	path = dbus_message_get_path(msg);

	dbus_connection_emit_property_changed(conn, path,
					ADAPTER_INTERFACE,
					"DiscoverableTimeout",
					DBUS_TYPE_UINT32, &timeout);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_name(DBusConnection *conn, DBusMessage *msg,
					const char *name, void *data)
{
	struct adapter *adapter = data;
	bdaddr_t bdaddr;
	int ecode;
	const char *path;

	if (!g_utf8_validate(name, -1, NULL)) {
		error("Name change failed: the supplied name isn't valid UTF-8");
		return invalid_args(msg);
	}

	str2ba(adapter->address, &bdaddr);

	write_local_name(&bdaddr, (char *) name);

	if (!adapter->up)
		goto done;

	ecode = set_device_name(adapter->dev_id, name);
	if (ecode < 0)
		return failed_strerror(msg, -ecode);
done:
	path = dbus_message_get_path(msg);

	dbus_connection_emit_property_changed(conn, path,
					ADAPTER_INTERFACE,
					"Name", DBUS_TYPE_STRING,
					&name);

	return dbus_message_new_method_return(msg);
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
	if (hci_disconnect(dd, htobs(pending_dc->conn_handle),
				HCI_OE_USER_ENDED_CONNECTION,
				500) < 0) {
		int err = errno;
		error("Disconnect failed");
		error_failed_errno(pending_dc->conn, pending_dc->msg, err);
	} else {
		reply = dbus_message_new_method_return(pending_dc->msg);
		if (reply) {
			dbus_connection_send(pending_dc->conn, reply, NULL);
			dbus_message_unref(reply);
		} else
			error("Failed to allocate disconnect reply");
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


static void reply_authentication_failure(struct bonding_request_info *bonding)
{
	DBusMessage *reply;
	int status;

	status = bonding->hci_status ?
			bonding->hci_status : HCI_AUTHENTICATION_FAILURE;

	reply = new_authentication_return(bonding->msg, status);
	if (reply) {
		dbus_connection_send(bonding->conn, reply, NULL);
		dbus_message_unref(reply);
	}
}

struct device *adapter_find_device(struct adapter *adapter, const char *dest)
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

struct device *adapter_create_device(DBusConnection *conn,
				struct adapter *adapter, const char *address)
{
	struct device *device;

	debug("adapter_create_device(%s)", address);

	device = device_create(conn, adapter, address);
	if (!device)
		return NULL;

	device->temporary = TRUE;

	adapter->devices = g_slist_append(adapter->devices, device);

	return device;
}

static DBusMessage *remove_bonding(DBusConnection *conn, DBusMessage *msg,
					const char *address, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	char path[MAX_PATH_LENGTH], filename[PATH_MAX + 1];
	char *str;
	bdaddr_t src, dst;
	GSList *l;
	int dev, err;
	gboolean paired;

	str2ba(adapter->address, &src);
	str2ba(address, &dst);

	dev = hci_open_dev(adapter->dev_id);
	if (dev < 0 && msg)
		return no_such_adapter(msg);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	/* textfile_del doesn't return an error when the key is not found */
	str = textfile_caseget(filename, address);
	paired = str ? TRUE : FALSE;
	g_free(str);

	if (!paired && msg) {
		hci_close_dev(dev);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Bonding does not exist");
	}

	/* Delete the link key from storage */
	if (textfile_casedel(filename, address) < 0 && msg) {
		hci_close_dev(dev);
		err = errno;
		return failed_strerror(msg, err);
	}

	/* Delete the link key from the Bluetooth chip */
	hci_delete_stored_link_key(dev, &dst, 0, 1000);

	/* find the connection */
	l = g_slist_find_custom(adapter->active_conn, &dst,
				active_conn_find_by_bdaddr);
	if (l) {
		struct active_conn_info *con = l->data;
		/* Send the HCI disconnect command */
		if ((hci_disconnect(dev, htobs(con->handle),
					HCI_OE_USER_ENDED_CONNECTION, 500) < 0)
					&& msg){
			int err = errno;
			error("Disconnect failed");
			hci_close_dev(dev);
			return failed_strerror(msg, err);
		}
	}

	hci_close_dev(dev);

	if (paired) {
		snprintf(path, MAX_PATH_LENGTH, BASE_PATH "/hci%d",
			adapter->dev_id);
		g_dbus_emit_signal(conn, path,
					ADAPTER_INTERFACE, "BondingRemoved",
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);
	}

	device = adapter_find_device(adapter, address);
	if (!device)
		goto proceed;

	if (paired) {
		gboolean paired = FALSE;
		dbus_connection_emit_property_changed(conn, device->path,
					DEVICE_INTERFACE, "Paired",
					DBUS_TYPE_BOOLEAN, &paired);
	}

proceed:
	if(!msg)
		goto done;

	return dbus_message_new_method_return(msg);

done:
	return NULL;
}


void adapter_remove_device(DBusConnection *conn, struct adapter *adapter,
				struct device *device)
{
	bdaddr_t src;
	char path[MAX_PATH_LENGTH];

	str2ba(adapter->address, &src);
	delete_entry(&src, "profiles", device->address);

	remove_bonding(conn, NULL, device->address, adapter);

	if (!device->temporary) {
		snprintf(path, MAX_PATH_LENGTH, "/hci%d", adapter->dev_id);
		g_dbus_emit_signal(conn, path,
				ADAPTER_INTERFACE,
				"DeviceRemoved",
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);
	}

	if (device->agent) {
		agent_destroy(device->agent, FALSE);
		device->agent = NULL;
	}

	adapter->devices = g_slist_remove(adapter->devices, device);

	device_remove(conn, device);
}

struct device *adapter_get_device(DBusConnection *conn,
				struct adapter *adapter, const gchar *address)
{
	struct device *device;

	debug("adapter_get_device(%s)", address);

	if (!adapter)
		return NULL;

	device = adapter_find_device(adapter, address);
	if (device)
		return device;

	return adapter_create_device(conn, adapter, address);
}

void remove_pending_device(struct adapter *adapter)
{
	struct device *device;
	char address[18];

	ba2str(&adapter->bonding->bdaddr, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return;

	if (device->temporary)
		adapter_remove_device(adapter->bonding->conn, adapter, device);
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
						adapter->bonding->msg);
		goto cleanup;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		debug("Hangup or error on bonding IO channel");

		if (!adapter->bonding->auth_active)
			error_connection_attempt_failed(adapter->bonding->conn,
							adapter->bonding->msg,
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
		error_failed_errno(adapter->bonding->conn, adapter->bonding->msg,
				errno);
		goto failed;
	}

	if (ret != 0) {
		if (adapter->bonding->auth_active)
			reply_authentication_failure(adapter->bonding);
		else
			error_connection_attempt_failed(adapter->bonding->conn,
							adapter->bonding->msg,
							ret);
		goto failed;
	}

	len = sizeof(cinfo);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_CONNINFO, &cinfo, &len) < 0) {
		error("Can't get connection info: %s (%d)",
				strerror(errno), errno);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->msg,
				errno);
		goto failed;
	}

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		error_no_such_adapter(adapter->bonding->conn,
					adapter->bonding->msg);
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
		error_failed_errno(adapter->bonding->conn, adapter->bonding->msg,
				errno);
		hci_close_dev(dd);
		goto failed;
	}

	if (rp.status) {
		error("HCI_Authentication_Requested failed with status 0x%02x",
				rp.status);
		error_failed_errno(adapter->bonding->conn, adapter->bonding->msg,
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
	remove_pending_device(adapter);

cleanup:
	g_dbus_remove_watch(adapter->bonding->conn,
				adapter->bonding->listener_id);
	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;

	return FALSE;
}

static void cancel_auth_request(struct pending_auth_info *auth, int dev_id)
{
	int dd;

	if (auth->replied)
		return;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("hci_open_dev: %s (%d)", strerror(errno), errno);
		return;
	}

	switch (auth->type) {
	case AUTH_TYPE_PINCODE:
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY,
				6, &auth->bdaddr);
		break;
	case AUTH_TYPE_CONFIRM:
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_NEG_REPLY,
				6, &auth->bdaddr);
		break;
	case AUTH_TYPE_PASSKEY:
		hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_PASSKEY_NEG_REPLY,
				6, &auth->bdaddr);
		break;
	case AUTH_TYPE_NOTIFY:
		/* User Notify doesn't require any reply */
		break;
	}

	auth->replied = TRUE;

	hci_close_dev(dd);
}

static void create_bond_req_exit(void *user_data)
{
	struct adapter *adapter = user_data;
	struct pending_auth_info *auth;
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, adapter->dev_id);

	debug("CreateConnection requestor exited before bonding was completed");

	cancel_passkey_agent_requests(adapter->passkey_agents, path,
					&adapter->bonding->bdaddr);
	release_passkey_agents(adapter, &adapter->bonding->bdaddr);

	auth = adapter_find_auth_request(adapter, &adapter->bonding->bdaddr);
	if (auth) {
		cancel_auth_request(auth, adapter->dev_id);
		if (auth->agent)
			agent_cancel(auth->agent);
		adapter_remove_auth_request(adapter, &adapter->bonding->bdaddr);
	}

	remove_pending_device(adapter);

	g_io_channel_close(adapter->bonding->io);
	if (adapter->bonding->io_id)
		g_source_remove(adapter->bonding->io_id);
	bonding_request_free(adapter->bonding);
	adapter->bonding = NULL;
}

static DBusMessage *create_bonding(DBusConnection *conn, DBusMessage *msg,
				const char *address, const char *agent_path,
				uint8_t capability, void *data)
{
	char filename[PATH_MAX + 1];
	char *str;
	struct adapter *adapter = data;
	struct bonding_request_info *bonding;
	bdaddr_t bdaddr;
	int sk;

	str2ba(address, &bdaddr);

	/* check if there is a pending discover: requested by D-Bus/non clients */
	if (adapter->discov_active)
		return in_progress(msg, "Discover in progress");

	pending_remote_name_cancel(adapter);

	if (adapter->bonding)
		return in_progress(msg, "Bonding in progress");

	if (adapter_find_auth_request(adapter, &bdaddr))
		return in_progress(msg, "Bonding in progress");

	/* check if a link key already exists */
	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
			"linkkeys");

	str = textfile_caseget(filename, address);
	if (str) {
		free(str);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".AlreadyExists",
				"Bonding already exists");
	}

	sk = l2raw_connect(adapter->address, &bdaddr);
	if (sk < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Connection attempt failed");

	bonding = bonding_request_new(conn, msg, adapter, address, agent_path,
					capability);
	if (!bonding) {
		close(sk);
		return NULL;
	}

	bonding->io = g_io_channel_unix_new(sk);
	bonding->io_id = g_io_add_watch(bonding->io,
					G_IO_OUT | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
					(GIOFunc) create_bonding_conn_complete,
					adapter);

	bonding->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						create_bond_req_exit, adapter,
						NULL);

	adapter->bonding = bonding;

	return NULL;
}

static void periodic_discover_req_exit(void *user_data)
{
	struct adapter *adapter = user_data;

	debug("PeriodicDiscovery requestor exited");

	/* Cleanup the discovered devices list and send the cmd to exit from
	 * periodic inquiry or cancel remote name request. The return value can
	 * be ignored. */

	cancel_periodic_discovery(adapter);
}

static DBusMessage *adapter_start_periodic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	periodic_inquiry_cp cp;
	struct hci_request rq;
	struct adapter *adapter = data;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	uint8_t status;
	int dd;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
				"StartPeriodicDiscovery")) {
		if (!dbus_message_has_signature(msg,
					DBUS_TYPE_INVALID_AS_STRING))
			return invalid_args(msg);
	}

	if (adapter->discov_active || adapter->pdiscov_active)
		return in_progress(msg, "Discover in progress");

	pending_remote_name_cancel(adapter);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return no_such_adapter(msg);

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
		return failed_strerror(msg, err);
	}

	if (status) {
		error("HCI_Periodic_Inquiry_Mode failed with status 0x%02x",
				status);
		hci_close_dev(dd);
		return failed_strerror(msg, bt_error(status));
	}

	adapter->pdiscov_requestor = g_strdup(dbus_message_get_sender(msg));

	if (adapter->pdiscov_resolve_names)
		adapter->discov_type = PERIODIC_INQUIRY | RESOLVE_NAME;
	else
		adapter->discov_type = PERIODIC_INQUIRY;

	hci_close_dev(dd);

	/* track the request owner to cancel it automatically if the owner
	 * exits */
	adapter->pdiscov_listener = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						periodic_discover_req_exit,
						adapter, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *adapter_stop_periodic(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	int err;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (dbus_message_is_method_call(msg, ADAPTER_INTERFACE,
				"StopPeriodicDiscovery")) {
		if (!dbus_message_has_signature(msg,
					DBUS_TYPE_INVALID_AS_STRING))
			return invalid_args(msg);
	}

	if (!adapter->pdiscov_active)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not authorized");
	/*
	 * Cleanup the discovered devices list and send the cmd to exit
	 * from periodic inquiry mode or cancel remote name request.
	 */
	err = cancel_periodic_discovery(adapter);
	if (err < 0) {
		if (err == -ENODEV)
			return no_such_adapter(msg);

		else
			return failed_strerror(msg, -err);
	}

	return dbus_message_new_method_return(msg);
}

static void discover_devices_req_exit(void *user_data)
{
	struct adapter *adapter = user_data;

	debug("DiscoverDevices requestor exited");

	/* Cleanup the discovered devices list and send the command to cancel
	 * inquiry or cancel remote name request. The return can be ignored. */
	cancel_discovery(adapter);
}

static DBusMessage *adapter_discover_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *method;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct adapter *adapter = data;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int dd;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	if (adapter->discov_active)
		return in_progress(msg, "Discover in progress");

	pending_remote_name_cancel(adapter);

	if (adapter->bonding)
		return in_progress(msg, "Bonding in progress");

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return no_such_adapter(msg);

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
		return failed_strerror(msg, err);
	}

	if (rp.status) {
		error("HCI_Inquiry command failed with status 0x%02x",
				rp.status);
		hci_close_dev(dd);
		return failed_strerror(msg, bt_error(rp.status));
	}

	method = dbus_message_get_member(msg);
	if (strcmp("DiscoverDevicesWithoutNameResolving", method) == 0)
		adapter->discov_type |= STD_INQUIRY;
	else
		adapter->discov_type |= (STD_INQUIRY | RESOLVE_NAME);

	adapter->discov_requestor = g_strdup(dbus_message_get_sender(msg));


	hci_close_dev(dd);

	/* track the request owner to cancel it automatically if the owner
	 * exits */
	adapter->discov_listener = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						discover_devices_req_exit,
						adapter, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *adapter_cancel_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	int err;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	/* is there discover pending? or discovery cancel was requested
	 * previously */
	if (!adapter->discov_active || adapter->discovery_cancel)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

	/* only the discover requestor can cancel the inquiry process */
	if (!adapter->discov_requestor ||
			strcmp(adapter->discov_requestor, dbus_message_get_sender(msg)))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

	/* Cleanup the discovered devices list and send the cmd to cancel
	 * inquiry or cancel remote name request */
	err = cancel_discovery(adapter);
	if (err < 0) {
		if (err == -ENODEV)
			return no_such_adapter(msg);
		else
			return failed_strerror(msg, -err);
	}

	/* Reply before send DiscoveryCompleted */
	adapter->discovery_cancel = dbus_message_ref(msg);

	return NULL;
}

struct remote_device_list_t {
	GSList *list;
	time_t time;
};

static DBusMessage *get_properties(DBusConnection *conn,
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
		return adapter_not_ready(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

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

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Name", property)) {
		const char *name;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &name);

		return set_name(conn, msg, name, data);
	} else if (g_str_equal("DiscoverableTimeout", property)) {
		uint32_t timeout;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT32)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &timeout);

		return set_discoverable_timeout(conn, msg, timeout, data);
	} else if (g_str_equal("PeriodicDiscovery", property)) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &value);

		if (value)
			return adapter_start_periodic(conn, msg, data);
		else
			return adapter_stop_periodic(conn, msg, data);
	} else if (g_str_equal("Mode", property)) {
		const char *mode;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &mode);

		adapter->global_mode = str2mode(adapter->address, mode);

		if (adapter->global_mode == adapter->mode)
			return dbus_message_new_method_return(msg);

		if (adapter->sessions && adapter->global_mode < adapter->mode)
			return confirm_mode(conn, msg, mode, data);

		return set_mode(conn, msg, str2mode(adapter->address, mode),
				data);
	}

	return invalid_args(msg);
}

static void session_exit(void *data)
{
	struct mode_req *req = data;
	struct adapter *adapter = req->adapter;

	adapter->sessions = g_slist_remove(adapter->sessions, req);

	if (!adapter->sessions) {
		debug("Falling back to '%s' mode", mode2str(adapter->global_mode));
		/* FIXME: fallback to previous mode
		set_mode(req->conn, req->msg, adapter->global_mode, adapter);
		*/
	}
	dbus_connection_unref(req->conn);
	dbus_message_unref(req->msg);
	g_free(req);
}

static DBusMessage *request_mode(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *mode;
	struct adapter *adapter = data;
	struct mode_req *req;
	uint8_t new_mode;
	int ret;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &mode,
						DBUS_TYPE_INVALID))
		return invalid_args(msg);

	new_mode = str2mode(adapter->address, mode);
	if (new_mode != MODE_CONNECTABLE && new_mode != MODE_DISCOVERABLE)
		return invalid_args(msg);

	if (!adapter->agent)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"No agent registered");

	if (g_slist_find_custom(adapter->sessions, msg,
			(GCompareFunc) find_session))
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"Mode already requested");

	req = g_new0(struct mode_req, 1);
	req->adapter = adapter;
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->mode = new_mode;
	req->id = g_dbus_add_disconnect_watch(conn,
					dbus_message_get_sender(msg),
					session_exit, req, NULL);

	if (!adapter->sessions)
		adapter->global_mode = adapter->mode;
	adapter->sessions = g_slist_append(adapter->sessions, req);

	/* No need to change mode */
	if (adapter->mode >= new_mode)
		return dbus_message_new_method_return(msg);

	ret = agent_confirm_mode_change(adapter->agent, mode, confirm_mode_cb,
					req);
	if (ret < 0) {
		dbus_message_unref(req->msg);
		g_dbus_remove_watch(req->conn, req->id);
		dbus_connection_unref(req->conn);
		g_free(req);
		return invalid_args(msg);
	}

	return NULL;
}

static DBusMessage *release_mode(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	GSList *l;

	l = g_slist_find_custom(adapter->sessions, msg,
			(GCompareFunc) find_session);
	if (!l)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"No Mode to release");

	session_exit(l->data);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *list_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	GSList *l;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapter->devices; l; l = l->next) {
		struct device *device = l->data;

		if (device->temporary)
			continue;

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_OBJECT_PATH, &device->path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static DBusMessage *create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	const gchar *address;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID) == FALSE)
		return invalid_args(msg);

	if (check_address(address) < 0)
		return invalid_args(msg);

	if (adapter_find_device(adapter, address))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".AlreadyExists",
				"Device already exists");

	debug("create_device(%s)", address);

	device = device_create(conn, adapter, address);
	if (!device)
		return NULL;

	device->temporary = FALSE;

	device_browse(device, conn, msg, NULL);

	adapter->devices = g_slist_append(adapter->devices, device);

	return NULL;
}

static uint8_t parse_io_capability(const char *capability)
{
	if (g_str_equal(capability, ""))
		return IO_CAPABILITY_DISPLAYYESNO;
	if (g_str_equal(capability, "DisplayOnly"))
		return IO_CAPABILITY_DISPLAYONLY;
	if (g_str_equal(capability, "DisplayYesNo"))
		return IO_CAPABILITY_DISPLAYYESNO;
	if (g_str_equal(capability, "KeyboardOnly"))
		return IO_CAPABILITY_KEYBOARDONLY;
	if (g_str_equal(capability, "NoInputOutput"))
		return IO_CAPABILITY_NOINPUTOUTPUT;
	return IO_CAPABILITY_INVALID;
}

static DBusMessage *create_paired_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const gchar *address, *agent_path, *capability;
	uint8_t cap;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_OBJECT_PATH, &agent_path,
					DBUS_TYPE_STRING, &capability,
						DBUS_TYPE_INVALID) == FALSE)
		return invalid_args(msg);

	if (check_address(address) < 0)
		return invalid_args(msg);

	cap = parse_io_capability(capability);
	if (cap == IO_CAPABILITY_INVALID)
		return invalid_args(msg);

	return create_bonding(conn, msg, address, agent_path, cap, data);
}

static gint device_path_cmp(struct device *device, const gchar *path)
{
	return strcasecmp(device->path, path);
}

static DBusMessage *remove_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	const char *path;
	GSList *l;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		return invalid_args(msg);

	l = g_slist_find_custom(adapter->devices,
			path, (GCompareFunc) device_path_cmp);
	if (!l)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device does not exist");
	device = l->data;

	if (device->temporary || device->discov_active)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device creation in progress");

	adapter_remove_device(conn, adapter, device);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *find_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	struct device *device;
	DBusMessage *reply;
	const gchar *address;
	GSList *l;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_INVALID))
		return invalid_args(msg);

	l = g_slist_find_custom(adapter->devices,
			address, (GCompareFunc) device_address_cmp);
	if (!l)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device does not exist");

	device = l->data;

	if (device->temporary)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device creation in progress");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply,
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);

	return reply;
}

static void agent_removed(struct agent *agent, struct adapter *adapter)
{
	struct pending_auth_info *auth;
	GSList *l;

	adapter->agent = NULL;

	l = g_slist_find_custom(adapter->auth_reqs, agent,
					auth_info_agent_cmp);
	if (!l)
		return;

	auth = l->data;
	auth->agent = NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *name, *capability;
	struct agent *agent;
	struct adapter *adapter = data;
	uint8_t cap;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_STRING, &capability, DBUS_TYPE_INVALID))
		return NULL;

	if (adapter->agent)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".AlreadyExists",
				"Agent already exists");

	cap = parse_io_capability(capability);
	if (cap == IO_CAPABILITY_INVALID)
		return invalid_args(msg);

	name = dbus_message_get_sender(msg);

	agent = agent_create(adapter, name, path, cap,
				(agent_remove_cb) agent_removed, adapter);
	if (!agent)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"Failed to create a new agent");

	adapter->agent = agent;

	debug("Agent registered for hci%d at %s:%s", adapter->dev_id, name,
			path);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *name;
	struct adapter *adapter = data;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID))
		return NULL;

	name = dbus_message_get_sender(msg);

	if (!adapter->agent || !agent_matches(adapter->agent, name, path))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"No such agent");

	agent_destroy(adapter->agent, FALSE);
	adapter->agent = NULL;

	return dbus_message_new_method_return(msg);
}

static DBusMessage *add_service_record(DBusConnection *conn,
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
		return NULL;

	sender = dbus_message_get_sender(msg);
	str2ba(adapter->address, &src);
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
	struct adapter *adapter = data;
	bdaddr_t src;

	str2ba(adapter->address, &src);

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

/* BlueZ 4.0 API */
static GDBusMethodTable adapter_methods[] = {
	{ "GetProperties",	"",	"a{sv}",get_properties		},
	{ "SetProperty",	"sv",	"",	set_property,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "RequestMode",	"s",	"",	request_mode,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "ReleaseMode",	"",	"",	release_mode		},
	{ "DiscoverDevices",	"",	"",	adapter_discover_devices},
	{ "CancelDiscovery",	"",	"",	adapter_cancel_discovery,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "ListDevices",	"",	"ao",	list_devices		},
	{ "CreateDevice",	"s",	"o",	create_device,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CreatePairedDevice",	"sos",	"o",	create_paired_device,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "RemoveDevice",	"o",	"",	remove_device		},
	{ "FindDevice",		"s",	"o",	find_device		},
	{ "RegisterAgent",	"os",	"",	register_agent		},
	{ "UnregisterAgent",	"o",	"",	unregister_agent	},
	{ "AddServiceRecord",	"s",	"u",	add_service_record	},
	{ "UpdateServiceRecord","us",	"",	update_service_record	},
	{ "RemoveServiceRecord","u",	"",	remove_service_record	},
	{ "RequestAuthorization","su",	"",	request_authorization,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelAuthorization","",	"",	cancel_authorization	},
	{ }
};

static GDBusSignalTable adapter_signals[] = {
	{ "DiscoveryStarted",		""		},
	{ "DiscoveryCompleted",		""		},
	{ "DeviceCreated",		"o"		},
	{ "DeviceRemoved",		"o"		},
	{ "DeviceFound",		"sa{sv}"	},
	{ "PropertyChanged",		"sv"		},
	{ "DeviceDisappeared",		"s"		},
	{ }
};

dbus_bool_t adapter_init(DBusConnection *conn,
		const char *path, struct adapter *adapter)
{
	return g_dbus_register_interface(conn, path,
			ADAPTER_INTERFACE, adapter_methods,
			adapter_signals, NULL, adapter, NULL);
}

dbus_bool_t adapter_cleanup(DBusConnection *conn, const char *path)
{
	return g_dbus_unregister_interface(conn, path, ADAPTER_INTERFACE);
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
