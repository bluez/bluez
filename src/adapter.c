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
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"

#include "hcid.h"
#include "sdpd.h"
#include "sdp-xml.h"
#include "manager.h"
#include "adapter.h"
#include "device.h"
#include "dbus-common.h"
#include "dbus-hci.h"
#include "error.h"
#include "glib-helper.h"
#include "agent.h"
#include "storage.h"

#define NUM_ELEMENTS(table) (sizeof(table)/sizeof(const char *))

#define IO_CAPABILITY_DISPLAYONLY	0x00
#define IO_CAPABILITY_DISPLAYYESNO	0x01
#define IO_CAPABILITY_KEYBOARDONLY	0x02
#define IO_CAPABILITY_NOINPUTOUTPUT	0x03
#define IO_CAPABILITY_INVALID		0xFF

#define check_address(address) bachk(address)

static DBusConnection *connection = NULL;
static GSList *adapter_drivers = NULL;

struct record_list {
	sdp_list_t *recs;
	const gchar *addr;
};

struct session_req {
	struct btd_adapter	*adapter;
	DBusConnection		*conn;		/* Connection reference */
	DBusMessage		*msg;		/* Message reference */
	guint			id;		/* Listener id */
	uint8_t			mode;		/* Requested mode */
	int			refcount;	/* Session refcount */
};

struct service_auth {
	service_auth_cb cb;
	void *user_data;
};

struct btd_adapter {
	uint16_t dev_id;
	int up;
	char *path;			/* adapter object path */
	char address[18];		/* adapter Bluetooth Address */
	guint discov_timeout_id;	/* discoverable timeout id */
	uint32_t discov_timeout;	/* discoverable time(msec) */
	uint8_t scan_mode;		/* scan mode: SCAN_DISABLED, SCAN_PAGE, SCAN_INQUIRY */
	uint8_t mode;			/* off, connectable, discoverable, limited */
	uint8_t global_mode;		/* last valid global mode */
	int state;			/* standard inq, periodic inq, name resloving */
	GSList *found_devices;
	GSList *oor_devices;		/* out of range device list */
	DBusMessage *discovery_cancel;	/* discovery cancel message request */
	GSList *passkey_agents;
	struct agent *agent;		/* For the new API */
	GSList *active_conn;
	struct bonding_request_info *bonding;
	GSList *auth_reqs;		/* Received and replied HCI
					   authentication requests */
	GSList *devices;		/* Devices structure pointers */
	GSList *mode_sessions;		/* Request Mode sessions */
	GSList *disc_sessions;		/* Discovery sessions */
	guint scheduler_id;		/* Scheduler handle */

	struct hci_dev dev;		/* hci info */
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

static DBusHandlerResult error_failed(DBusConnection *conn,
					DBusMessage *msg, const char * desc)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".Failed", desc);
}

static DBusHandlerResult error_failed_errno(DBusConnection *conn,
						DBusMessage *msg, int err)
{
	const char *desc = strerror(err);

	return error_failed(conn, msg, desc);
}

static DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn,
						DBusMessage *msg, int err)
{
	return error_common_reply(conn, msg,
			ERROR_INTERFACE ".ConnectionAttemptFailed",
			err > 0 ? strerror(err) : "Connection attempt failed");
}

static void bonding_request_free(struct bonding_request_info *bonding)
{
	struct btd_device *device;
	char address[18];
	struct agent *agent;

	if (!bonding)
		return;

	if (bonding->msg)
		dbus_message_unref(bonding->msg);

	if (bonding->conn)
		dbus_connection_unref(bonding->conn);

	if (bonding->io)
		g_io_channel_unref(bonding->io);

	ba2str(&bonding->bdaddr, address);

	device = adapter_find_device(bonding->adapter, address);
	agent = device_get_agent(device);

	if (device && agent) {
		agent_destroy(agent, FALSE);
		device_set_agent(device, NULL);
	}

	g_free(bonding);
}

static int active_conn_find_by_bdaddr(const void *data, const void *user_data)
{
	const struct active_conn_info *con = data;
	const bdaddr_t *bdaddr = user_data;

	return bacmp(&con->bdaddr, bdaddr);
}

static int active_conn_find_by_handle(const void *data, const void *user_data)
{
	const struct active_conn_info *dev = data;
	const uint16_t *handle = user_data;

	if (dev->handle == *handle)
		return 0;

	return -1;
}

static void send_out_of_range(const char *path, GSList *l)
{
	while (l) {
		const char *peer_addr = l->data;

		g_dbus_emit_signal(connection, path,
				ADAPTER_INTERFACE, "DeviceDisappeared",
				DBUS_TYPE_STRING, &peer_addr,
				DBUS_TYPE_INVALID);

		l = l->next;
	}
}

static int found_device_cmp(const struct remote_dev_info *d1,
			const struct remote_dev_info *d2)
{
	int ret;

	if (bacmp(&d2->bdaddr, BDADDR_ANY)) {
		ret = bacmp(&d1->bdaddr, &d2->bdaddr);
		if (ret)
			return ret;
	}

	if (d2->name_status != NAME_ANY) {
		ret = (d1->name_status - d2->name_status);
		if (ret)
			return ret;
	}

	return 0;
}

static int auth_req_cmp(const void *p1, const void *p2)
{
	const struct pending_auth_info *pb1 = p1;
	const bdaddr_t *bda = p2;

	return bda ? bacmp(&pb1->bdaddr, bda) : -1;
}

struct pending_auth_info *adapter_find_auth_request(struct btd_adapter *adapter,
							bdaddr_t *dba)
{
	GSList *l;

	l = g_slist_find_custom(adapter->auth_reqs, dba, auth_req_cmp);
	if (l)
		return l->data;

	return NULL;
}

void adapter_remove_auth_request(struct btd_adapter *adapter, bdaddr_t *dba)
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

struct pending_auth_info *adapter_new_auth_request(struct btd_adapter *adapter,
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

int pending_remote_name_cancel(struct btd_adapter *adapter)
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
	struct btd_device *device = user_data;
	struct pending_auth_info *auth;
	GSList *l;
	struct btd_adapter *adapter;

	adapter = device_get_adapter(device);
	device_set_agent(device, NULL);

	l = g_slist_find_custom(adapter->auth_reqs, agent,
					auth_info_agent_cmp);
	if (!l)
		return;

	auth = l->data;
	auth->agent = NULL;
}

static struct bonding_request_info *bonding_request_new(DBusConnection *conn,
							DBusMessage *msg,
							struct btd_adapter *adapter,
							const char *address,
							const char *agent_path,
							uint8_t capability)
{
	struct bonding_request_info *bonding;
	struct btd_device *device;
	const char *name = dbus_message_get_sender(msg);
	struct agent *agent;
	char addr[18];
	bdaddr_t bdaddr;

	debug("bonding_request_new(%s)", address);

	device = adapter_get_device(conn, adapter, address);
	if (!device)
		return NULL;

	device_get_address(device, &bdaddr);
	ba2str(&bdaddr, addr);

	agent = agent_create(adapter, name, agent_path,
					capability,
					device_agent_removed,
					device);

	device_set_agent(device, agent);

	debug("Temporary agent registered for hci%d/%s at %s:%s",
			adapter->dev_id, addr, name,
			agent_path);

	bonding = g_new0(struct bonding_request_info, 1);

	bonding->conn = dbus_connection_ref(conn);
	bonding->msg = dbus_message_ref(msg);
	bonding->adapter = adapter;

	str2ba(address, &bonding->bdaddr);

	return bonding;
}

static const char *mode2str(uint8_t mode)
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

static uint8_t str2mode(const char *addr, const char *mode)
{
	if (strcasecmp("off", mode) == 0)
		return MODE_OFF;
	else if (strcasecmp("connectable", mode) == 0)
		return MODE_CONNECTABLE;
	else if (strcasecmp("discoverable", mode) == 0)
		return MODE_DISCOVERABLE;
	else if (strcasecmp("limited", mode) == 0)
		return MODE_LIMITED;
	else if (strcasecmp("on", mode) == 0) {
		char onmode[14];
		if (read_on_mode(addr, onmode, sizeof(onmode)) < 0)
			return MODE_CONNECTABLE;

		return str2mode(addr, onmode);
	} else
		return MODE_UNKNOWN;
}

static DBusMessage *set_mode(DBusConnection *conn, DBusMessage *msg,
				uint8_t new_mode, void *data)
{
	struct btd_adapter *adapter = data;
	uint8_t scan_enable;
	uint8_t current_scan = adapter->scan_mode;
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
			(main_opts.offmode == HCID_OFFMODE_NOSCAN ||
			 (main_opts.offmode == HCID_OFFMODE_DEVDOWN &&
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
			main_opts.offmode == HCID_OFFMODE_DEVDOWN) {
		if (ioctl(dd, HCIDEVDOWN, adapter->dev_id) < 0) {
			hci_close_dev(dd);
			return failed_strerror(msg, errno);
		}

		goto done;
	}

	limited = (new_mode == MODE_LIMITED ? TRUE : FALSE);
	err = set_limited_discoverable(dd, adapter->dev.class, limited);
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
			if (adapter->discov_timeout_id) {
				g_source_remove(adapter->discov_timeout_id);
				adapter->discov_timeout_id = 0;
			}

			if (!adapter->mode_sessions && !adapter->discov_timeout)
				adapter_set_discov_timeout(adapter,
						adapter->discov_timeout * 1000);
		}
	}
done:
	str2ba(adapter->address, &local);
	write_device_mode(&local, mode);

	hci_close_dev(dd);

	adapter->mode = new_mode;

	return dbus_message_new_method_return(msg);
}

static struct session_req *find_session(GSList *list, DBusMessage *msg)
{
	GSList *l;
	const char *sender = dbus_message_get_sender(msg);

	for (l = list; l; l = l->next) {
		struct session_req *req = l->data;
		const char *name = dbus_message_get_sender(req->msg);

		if (g_str_equal(name, sender))
			return req;
	}

	return NULL;
}

static void session_free(struct session_req *req)
{
	struct btd_adapter *adapter = req->adapter;
	const char *sender = dbus_message_get_sender(req->msg);

	info("%s session %p with %s deactivated",
		req->mode ? "Mode" : "Discovery", req, sender);

	if (req->mode)
		adapter->mode_sessions = g_slist_remove(adapter->mode_sessions,
						req);
	else
		adapter->disc_sessions = g_slist_remove(adapter->disc_sessions,
						req);

	dbus_message_unref(req->msg);
	dbus_connection_unref(req->conn);
	g_free(req);
}

static struct session_req *session_ref(struct session_req *req)
{
	req->refcount++;

	debug("session_ref(%p): ref=%d", req, req->refcount);

	return req;
}

static void session_unref(struct session_req *req)
{
	req->refcount--;

	debug("session_unref(%p): ref=%d", req, req->refcount);

	if (req->refcount)
		return;

	if (req->id)
		g_dbus_remove_watch(req->conn, req->id);

	session_free(req);
}

static struct session_req *create_session(struct btd_adapter *adapter,
					DBusConnection *conn, DBusMessage *msg,
					uint8_t mode, GDBusWatchFunction cb)
{
	struct session_req *req;
	const char *sender = dbus_message_get_sender(msg);

	req = g_new0(struct session_req, 1);
	req->adapter = adapter;
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->mode = mode;

	if (cb)
		req->id = g_dbus_add_disconnect_watch(conn,
					dbus_message_get_sender(msg),
					cb, req, NULL);

	info("%s session %p with %s activated",
		req->mode ? "Mode" : "Discovery", req, sender);

	return session_ref(req);
}

static void confirm_mode_cb(struct agent *agent, DBusError *err, void *data)
{
	struct session_req *req = data;
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

	if (!find_session(req->adapter->mode_sessions, req->msg))
		goto cleanup;

	return;

cleanup:
	session_unref(req);
}

static DBusMessage *confirm_mode(DBusConnection *conn, DBusMessage *msg,
					const char *mode, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;
	int ret;
	uint8_t umode;

	if (!adapter->agent)
		return dbus_message_new_method_return(msg);

	umode = str2mode(adapter->address, mode);

	req = create_session(adapter, conn, msg, umode, NULL);

	ret = agent_confirm_mode_change(adapter->agent, mode, confirm_mode_cb,
					req);
	if (ret < 0) {
		session_unref(req);
		return invalid_args(msg);
	}

	return NULL;
}

static DBusMessage *set_discoverable_timeout(DBusConnection *conn,
							DBusMessage *msg,
							uint32_t timeout,
							void *data)
{
	struct btd_adapter *adapter = data;
	bdaddr_t bdaddr;
	const char *path;

	if (adapter->discov_timeout_id) {
		g_source_remove(adapter->discov_timeout_id);
		adapter->discov_timeout_id = 0;
	}

	if ((timeout != 0) && (adapter->scan_mode & SCAN_INQUIRY))
		adapter_set_discov_timeout(adapter, timeout * 1000);

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

static void update_ext_inquiry_response(int dd, struct hci_dev *dev)
{
	uint8_t fec = 0, data[240];

	if (!(dev->features[6] & LMP_EXT_INQ))
		return;

	memset(data, 0, sizeof(data));

	if (dev->ssp_mode > 0)
		create_ext_inquiry_response((char *) dev->name, data);

	if (hci_write_ext_inquiry_response(dd, fec, data, 2000) < 0)
		error("Can't write extended inquiry response: %s (%d)",
						strerror(errno), errno);
}

static int adapter_set_name(struct btd_adapter *adapter, const char *name)
{
	struct hci_dev *dev = &adapter->dev;
	int dd, err;
	bdaddr_t bdaddr;

	str2ba(adapter->address, &bdaddr);

	write_local_name(&bdaddr, (char *) name);

	if (!adapter->up)
		return 0;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					adapter->dev_id, strerror(err), err);
		return -err;
	}

	if (hci_write_local_name(dd, name, 5000) < 0) {
		err = errno;
		error("Can't write name for hci%d: %s (%d)",
					adapter->dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	strncpy((char *) dev->name, name, 248);

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

static DBusMessage *set_name(DBusConnection *conn, DBusMessage *msg,
					const char *name, void *data)
{
	struct btd_adapter *adapter = data;
	int ecode;
	const char *path;

	if (!g_utf8_validate(name, -1, NULL)) {
		error("Name change failed: the supplied name isn't valid UTF-8");
		return invalid_args(msg);
	}

	ecode = adapter_set_name(adapter, name);
	if (ecode < 0)
		return failed_strerror(msg, -ecode);

	path = dbus_message_get_path(msg);

	dbus_connection_emit_property_changed(conn, path,
					ADAPTER_INTERFACE,
					"Name", DBUS_TYPE_STRING,
					&name);

	return dbus_message_new_method_return(msg);
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

struct btd_device *adapter_find_device(struct btd_adapter *adapter, const char *dest)
{
	struct btd_device *device;
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

struct btd_device *adapter_create_device(DBusConnection *conn,
				struct btd_adapter *adapter, const char *address)
{
	struct btd_device *device;

	debug("adapter_create_device(%s)", address);

	device = device_create(conn, adapter, address);
	if (!device)
		return NULL;

	device_set_temporary(device, TRUE);

	adapter->devices = g_slist_append(adapter->devices, device);

	return device;
}

static DBusMessage *remove_bonding(DBusConnection *conn, DBusMessage *msg,
					const char *address, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	char filename[PATH_MAX + 1];
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

	device = adapter_find_device(adapter, address);
	if (!device)
		goto proceed;

	if (paired) {
		gboolean paired = FALSE;

		const gchar *dev_path = device_get_path(device);

		dbus_connection_emit_property_changed(conn, dev_path,
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


void adapter_remove_device(DBusConnection *conn, struct btd_adapter *adapter,
				struct btd_device *device)
{
	bdaddr_t src, dst;
	const gchar *dev_path = device_get_path(device);
	struct agent *agent;
	char dst_addr[18];

	device_get_address(device, &dst);
	ba2str(&dst, dst_addr);

	str2ba(adapter->address, &src);
	delete_entry(&src, "profiles", dst_addr);

	if (!device_is_temporary(device)) {
		remove_bonding(conn, NULL, dst_addr, adapter);

		g_dbus_emit_signal(conn, adapter->path,
				ADAPTER_INTERFACE,
				"DeviceRemoved",
				DBUS_TYPE_OBJECT_PATH, &dev_path,
				DBUS_TYPE_INVALID);
	}

	agent = device_get_agent(device);

	if (agent) {
		agent_destroy(agent, FALSE);
		device_set_agent(device, NULL);
	}

	adapter->devices = g_slist_remove(adapter->devices, device);

	device_remove(conn, device);
}

struct btd_device *adapter_get_device(DBusConnection *conn,
				struct btd_adapter *adapter, const gchar *address)
{
	struct btd_device *device;

	debug("adapter_get_device(%s)", address);

	if (!adapter)
		return NULL;

	device = adapter_find_device(adapter, address);
	if (device)
		return device;

	return adapter_create_device(conn, adapter, address);
}

void remove_pending_device(struct btd_adapter *adapter)
{
	struct btd_device *device;
	char address[18];

	ba2str(&adapter->bonding->bdaddr, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return;

	if (device_is_temporary(device))
		adapter_remove_device(adapter->bonding->conn, adapter, device);
}

static gboolean create_bonding_conn_complete(GIOChannel *io, GIOCondition cond,
						struct btd_adapter *adapter)
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
		DBusMessage *reply;
		reply = new_authentication_return(adapter->bonding->msg, 0x09);
		g_dbus_send_message(adapter->bonding->conn, reply);
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
		DBusMessage *reply = no_such_adapter(adapter->bonding->msg);
		g_dbus_send_message(adapter->bonding->conn, reply);
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
	struct btd_adapter *adapter = user_data;
	struct pending_auth_info *auth;

	debug("CreateConnection requestor exited before bonding was completed");

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
	struct btd_adapter *adapter = data;
	struct bonding_request_info *bonding;
	bdaddr_t bdaddr;
	int sk;

	str2ba(address, &bdaddr);

	/* check if there is a pending discover: requested by D-Bus/non clients */
	if (adapter->state & STD_INQUIRY)
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

static void discover_req_exit(void *user_data)
{
	struct session_req *req = user_data;
	struct btd_adapter *adapter = req->adapter;

	adapter->disc_sessions = g_slist_remove(adapter->disc_sessions, req);
	req->id = 0;
	session_free(req);

	if (adapter->disc_sessions)
		return;

	/* Cleanup the discovered devices list and send the cmd to exit from
	 * periodic inquiry or cancel remote name request. The return value can
	 * be ignored. */

	if (adapter->state & STD_INQUIRY)
		cancel_discovery(adapter);
	else
		cancel_periodic_discovery(adapter);
}

int start_inquiry(struct btd_adapter *adapter)
{
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int dd, err;

	pending_remote_name_cancel(adapter);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return dd;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.lap, lap, 3);
	cp.length = 0x08;
	cp.num_rsp = 0x00;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LINK_CTL;
	rq.ocf = OCF_INQUIRY;
	rq.cparam = &cp;
	rq.clen = INQUIRY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen = EVT_CMD_STATUS_SIZE;
	rq.event = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 500) < 0) {
		err = errno;
		error("Unable to start inquiry: %s (%d)",
			strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	if (rp.status) {
		err = bt_error(rp.status);
		error("HCI_Inquiry command failed with status 0x%02x",
			rp.status);
		hci_close_dev(dd);
		return -err;
	}

	hci_close_dev(dd);

	adapter->state |= RESOLVE_NAME;

	return 0;
}

static int start_periodic_inquiry(struct btd_adapter *adapter)
{
	periodic_inquiry_cp cp;
	struct hci_request rq;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	uint8_t status;
	int dd, err;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0)
		return dd;

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
		err = errno;
		error("Unable to start periodic inquiry: %s (%d)",
				strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	if (status) {
		err = bt_error(status);
		error("HCI_Periodic_Inquiry_Mode failed with status 0x%02x",
				status);
		hci_close_dev(dd);
		return -err;
	}

	hci_close_dev(dd);

	adapter->state |= RESOLVE_NAME;

	return 0;
}

static DBusMessage *adapter_start_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct session_req *req;
	struct btd_adapter *adapter = data;
	int err;

	if (!adapter->up)
		return adapter_not_ready(msg);

	req = find_session(adapter->disc_sessions, msg);
	if (req) {
		session_ref(req);
		return dbus_message_new_method_return(msg);
	}

	if (adapter->disc_sessions)
		goto done;

	if (main_opts.inqmode)
		err = start_inquiry(adapter);
	else
		err = start_periodic_inquiry(adapter);

	if (err < 0)
		return failed_strerror(msg, -err);

done:
	req = create_session(adapter, conn, msg, 0, discover_req_exit);

	adapter->disc_sessions = g_slist_append(adapter->disc_sessions, req);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *adapter_stop_discovery(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;
	int err = 0;

	if (!adapter->up)
		return adapter_not_ready(msg);

	req = find_session(adapter->disc_sessions, msg);
	if (!req)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"Invalid discovery session");

	session_unref(req);
	if (adapter->disc_sessions)
		return dbus_message_new_method_return(msg);

	/*
	 * Cleanup the discovered devices list and send the cmd to exit
	 * from periodic inquiry mode or cancel remote name request.
	 */
	if (adapter->state & STD_INQUIRY)
		err = cancel_discovery(adapter);
	else if (adapter->scheduler_id)
		g_source_remove(adapter->scheduler_id);
	else
		err = cancel_periodic_discovery(adapter);

	if (err < 0) {
		if (err == -ENODEV)
			return no_such_adapter(msg);

		else
			return failed_strerror(msg, -err);
	}

	return dbus_message_new_method_return(msg);
}

struct remote_device_list_t {
	GSList *list;
	time_t time;
};

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	const char *property;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t ba;
	char str[249];
	gboolean discov_active;

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

	if (adapter->state & PERIODIC_INQUIRY || adapter->state & STD_INQUIRY)
		discov_active = TRUE;
	else
		discov_active = FALSE;

	/* PeriodicDiscovery */
	dbus_message_iter_append_dict_entry(&dict, "Discovering",
				DBUS_TYPE_BOOLEAN, &discov_active);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
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
	} else if (g_str_equal("Mode", property)) {
		const char *mode;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &mode);

		adapter->global_mode = str2mode(adapter->address, mode);

		if (adapter->global_mode == adapter->mode)
			return dbus_message_new_method_return(msg);

		if (adapter->mode_sessions && adapter->global_mode < adapter->mode)
			return confirm_mode(conn, msg, mode, data);

		return set_mode(conn, msg, str2mode(adapter->address, mode),
				data);
	}

	return invalid_args(msg);
}

static void session_exit(void *data)
{
	struct session_req *req = data;
	struct btd_adapter *adapter = req->adapter;

	if (!adapter->mode_sessions) {
		debug("Falling back to '%s' mode", mode2str(adapter->global_mode));
		/* FIXME: fallback to previous mode
		set_mode(req->conn, req->msg, adapter->global_mode, adapter);
		*/
	}

	session_free(req);
}

static DBusMessage *request_mode(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *mode;
	struct btd_adapter *adapter = data;
	struct session_req *req;
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

	req = find_session(adapter->mode_sessions, msg);
	if (req)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"Mode already requested");

	req = create_session(adapter, conn, msg, new_mode, session_exit);

	if (!adapter->mode_sessions)
		adapter->global_mode = adapter->mode;
	adapter->mode_sessions = g_slist_append(adapter->mode_sessions, req);

	/* No need to change mode */
	if (adapter->mode >= new_mode)
		return dbus_message_new_method_return(msg);

	ret = agent_confirm_mode_change(adapter->agent, mode, confirm_mode_cb,
					req);
	if (ret < 0) {
		session_unref(req);
		return invalid_args(msg);
	}

	return NULL;
}

static DBusMessage *release_mode(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct session_req *req;

	req = find_session(adapter->mode_sessions, msg);
	if (!req)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				"No Mode to release");

	session_exit(req);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *list_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	DBusMessage *reply;
	GSList *l;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	const gchar *dev_path;

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING))
		return invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapter->devices; l; l = l->next) {
		struct btd_device *device = l->data;

		if (device_is_temporary(device))
			continue;

		dev_path = device_get_path(device);

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_OBJECT_PATH, &dev_path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static DBusMessage *create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
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

	device_set_temporary(device, FALSE);

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

static gint device_path_cmp(struct btd_device *device, const gchar *path)
{
	const gchar *dev_path = device_get_path(device);

	return strcasecmp(dev_path, path);
}

static DBusMessage *remove_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
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

	if (device_is_temporary(device) || device_is_busy(device))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device creation in progress");

	adapter_remove_device(conn, adapter, device);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *find_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	struct btd_device *device;
	DBusMessage *reply;
	const gchar *address;
	GSList *l;
	const gchar *dev_path;

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

	if (device_is_temporary(device))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".DoesNotExist",
				"Device creation in progress");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dev_path = device_get_path(device);

	dbus_message_append_args(reply,
				DBUS_TYPE_OBJECT_PATH, &dev_path,
				DBUS_TYPE_INVALID);

	return reply;
}

static void agent_removed(struct agent *agent, struct btd_adapter *adapter)
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
	struct btd_adapter *adapter = data;
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
	struct btd_adapter *adapter = data;

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

/* BlueZ 4.0 API */
static GDBusMethodTable adapter_methods[] = {
	{ "GetProperties",	"",	"a{sv}",get_properties		},
	{ "SetProperty",	"sv",	"",	set_property,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "RequestMode",	"s",	"",	request_mode,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "ReleaseMode",	"",	"",	release_mode		},
	{ "StartDiscovery",	"",	"",	adapter_start_discovery },
	{ "StopDiscovery",	"",	"",	adapter_stop_discovery,
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
	{ }
};

static GDBusSignalTable adapter_signals[] = {
	{ "DeviceCreated",		"o"		},
	{ "DeviceRemoved",		"o"		},
	{ "DeviceFound",		"sa{sv}"	},
	{ "PropertyChanged",		"sv"		},
	{ "DeviceDisappeared",		"s"		},
	{ }
};

static inline uint8_t get_inquiry_mode(struct hci_dev *dev)
{
	if (dev->features[6] & LMP_EXT_INQ)
		return 2;

	if (dev->features[3] & LMP_RSSI_INQ)
		return 1;

	if (dev->manufacturer == 11 &&
			dev->hci_rev == 0x00 && dev->lmp_subver == 0x0757)
		return 1;

	if (dev->manufacturer == 15) {
		if (dev->hci_rev == 0x03 && dev->lmp_subver == 0x6963)
			return 1;
		if (dev->hci_rev == 0x09 && dev->lmp_subver == 0x6963)
			return 1;
		if (dev->hci_rev == 0x00 && dev->lmp_subver == 0x6965)
			return 1;
	}

	if (dev->manufacturer == 31 &&
			dev->hci_rev == 0x2005 && dev->lmp_subver == 0x1805)
		return 1;

	return 0;
}

static int device_read_bdaddr(uint16_t dev_id, const char *address)
{
	int dd, err;
	bdaddr_t bdaddr;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	str2ba(address, &bdaddr);
	if (hci_read_bd_addr(dd, &bdaddr, 2000) < 0) {
		err = errno;
		error("Can't read address for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	hci_close_dev(dd);

	return 0;
}

static int adapter_setup(struct btd_adapter *adapter, int dd)
{
	struct hci_dev *dev = &adapter->dev;
	uint8_t events[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00 };
	uint8_t inqmode;
	bdaddr_t bdaddr;
	int err;
	char name[249];

	if (dev->hci_rev > 1) {
		if (dev->features[5] & LMP_SNIFF_SUBR)
			events[5] |= 0x20;

		if (dev->features[5] & LMP_PAUSE_ENC)
			events[5] |= 0x80;

		if (dev->features[6] & LMP_EXT_INQ)
			events[5] |= 0x40;

		if (dev->features[6] & LMP_NFLUSH_PKTS)
			events[7] |= 0x01;

		if (dev->features[7] & LMP_LSTO)
			events[6] |= 0x80;

		if (dev->features[6] & LMP_SIMPLE_PAIR) {
			events[6] |= 0x01;	/* IO Capability Request */
			events[6] |= 0x02;	/* IO Capability Response */
			events[6] |= 0x04;	/* User Confirmation Request */
			events[6] |= 0x08;	/* User Passkey Request */
			events[6] |= 0x10;	/* Remote OOB Data Request */
			events[6] |= 0x20;	/* Simple Pairing Complete */
			events[7] |= 0x04;	/* User Passkey Notification */
			events[7] |= 0x08;	/* Keypress Notification */
			events[7] |= 0x10;	/* Remote Host Supported Features Notification */
		}

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_SET_EVENT_MASK,
						sizeof(events), events);
	}

	str2ba(adapter->address, &bdaddr);
	if (read_local_name(&bdaddr, name) == 0) {
		memcpy(dev->name, name, 248);
		hci_write_local_name(dd, name, 5000);
        }

	update_ext_inquiry_response(dd, dev);

	inqmode = get_inquiry_mode(dev);
	if (inqmode < 1)
		return 0;

	if (hci_write_inquiry_mode(dd, inqmode, 2000) < 0) {
		err = errno;
		error("Can't write inquiry mode for %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	return 0;
}

static int active_conn_append(GSList **list, bdaddr_t *bdaddr,
				uint16_t handle)
{
	struct active_conn_info *dev;

	dev = g_new0(struct active_conn_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->handle = handle;

	*list = g_slist_append(*list, dev);
	return 0;
}

static void create_stored_records_from_keys(char *key, char *value,
						void *user_data)
{
	struct record_list *rec_list = user_data;
	const gchar *addr = rec_list->addr;
	sdp_record_t *rec;
	int size, i, len;
	uint8_t *pdata;
	char tmp[3] = "";

	if (strstr(key, addr) == NULL)
		return;

	size = strlen(value)/2;
	pdata = g_malloc0(size);

	for (i = 0; i < size; i++) {
		 memcpy(tmp, value + (i * 2), 2);
		 pdata[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	rec = sdp_extract_pdu(pdata, size, &len);
	free(pdata);

	rec_list->recs = sdp_list_append(rec_list->recs, rec);
}

static void create_stored_device_from_profiles(char *key, char *value,
						void *user_data)
{
	char filename[PATH_MAX + 1];
	struct btd_adapter *adapter = user_data;
	GSList *uuids = bt_string2list(value);
	struct btd_device *device;
	const gchar *src;
	struct record_list rec_list;
	bdaddr_t dst;
	char dst_addr[18];

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key);
	if (!device)
		return;

	device_set_temporary(device, FALSE);
	adapter->devices = g_slist_append(adapter->devices, device);

	device_get_address(device, &dst);
	ba2str(&dst, dst_addr);

	src = adapter->address;
	rec_list.addr = dst_addr;
	rec_list.recs = NULL;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");
	textfile_foreach(filename, create_stored_records_from_keys, &rec_list);

	device_probe_drivers(device, uuids, rec_list.recs);

	if (rec_list.recs != NULL)
		sdp_list_free(rec_list.recs, (sdp_free_func_t) sdp_record_free);

	g_slist_free(uuids);
}

static void create_stored_device_from_linkkeys(char *key, char *value,
						void *user_data)
{
	struct btd_adapter *adapter = user_data;
	struct btd_device *device;

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
	}
}

static void load_devices(struct btd_adapter *adapter)
{
	char filename[PATH_MAX + 1];

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "profiles");
	textfile_foreach(filename, create_stored_device_from_profiles, adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "linkkeys");
	textfile_foreach(filename, create_stored_device_from_linkkeys, adapter);
}

static void load_drivers(struct btd_adapter *adapter)
{
	GSList *l;

	for (l = adapter_drivers; l; l = l->next) {
		struct btd_adapter_driver *driver = l->data;

		if (driver->probe)
			driver->probe(adapter);
	}
}

static int get_discoverable_timeout(const char *src)
{
	int timeout;

	if (read_discoverable_timeout(src, &timeout) == 0)
		return timeout;

	return main_opts.discovto;
}

static void adapter_up(struct btd_adapter *adapter, int dd)
{
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci;
	const char *pmode;
	char mode[14];
	int i;

	adapter->up = 1;
	adapter->discov_timeout = get_discoverable_timeout(adapter->address);
	adapter->state = DISCOVER_TYPE_NONE;

	/* Set scan mode */
	if (read_device_mode(adapter->address, mode, sizeof(mode)) == 0) {
		if (!strcmp(mode, "off") && main_opts.offmode == HCID_OFFMODE_NOSCAN) {
			adapter->mode = MODE_OFF;
			adapter->scan_mode= SCAN_DISABLED;
		} else if (!strcmp(mode, "connectable")) {
			adapter->mode = MODE_CONNECTABLE;
			adapter->scan_mode = SCAN_PAGE;
		} else if (!strcmp(mode, "discoverable")) {
			/* Set discoverable only if timeout is 0 */
			if (adapter->discov_timeout == 0) {
				adapter->mode = MODE_DISCOVERABLE;
				adapter->scan_mode = SCAN_PAGE | SCAN_INQUIRY;
			} else {
				adapter->mode = MODE_CONNECTABLE;
				adapter->scan_mode = SCAN_PAGE;
			}
		} else if (!strcmp(mode, "limited")) {
			/* Set discoverable only if timeout is 0 */
			if (adapter->discov_timeout == 0) {
				adapter->mode = MODE_LIMITED;
				adapter->scan_mode = SCAN_PAGE | SCAN_INQUIRY;
			} else {
				adapter->mode = MODE_CONNECTABLE;
				adapter->scan_mode = SCAN_PAGE;

			}
		}
	}

	hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &adapter->scan_mode);

	if (adapter->mode == MODE_LIMITED)
		set_limited_discoverable(dd, adapter->dev.class, TRUE);

	/*
	 * retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started
	 */

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = adapter->dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, cl) == 0) {
		for (i = 0; i < cl->conn_num; i++, ci++)
			active_conn_append(&adapter->active_conn,
						&ci->bdaddr, ci->handle);
	}
	g_free(cl);

	pmode = mode2str(adapter->mode);

	dbus_connection_emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &pmode);

	load_drivers(adapter);
	load_devices(adapter);
}

int adapter_start(struct btd_adapter *adapter)
{
	struct hci_dev *dev = &adapter->dev;
	struct hci_dev_info di;
	struct hci_version ver;
	uint8_t features[8];
	int dd, err;
	char name[249];

	if (hci_devinfo(adapter->dev_id, &di) < 0)
		return -errno;

	if (hci_test_bit(HCI_RAW, &di.flags)) {
		dev->ignore = 1;
		return -1;
	}

	if (bacmp(&di.bdaddr, BDADDR_ANY))
		ba2str(&di.bdaddr, adapter->address);
	else {
		int err = device_read_bdaddr(adapter->dev_id, adapter->address);
		if (err < 0)
			return err;
	}
	memcpy(dev->features, di.features, 8);

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open adapter %s: %s (%d)",
					adapter->path, strerror(err), err);
		return -err;
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		err = errno;
		error("Can't read version info for %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	dev->hci_rev = ver.hci_rev;
	dev->lmp_ver = ver.lmp_ver;
	dev->lmp_subver = ver.lmp_subver;
	dev->manufacturer = ver.manufacturer;

	if (hci_read_local_features(dd, features, 1000) < 0) {
		err = errno;
		error("Can't read features for %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	memcpy(dev->features, features, 8);

	if (hci_read_class_of_dev(dd, dev->class, 1000) < 0) {
		err = errno;
		error("Can't read class of adapter on %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	if (hci_read_local_name(dd, sizeof(name), name, 2000) < 0) {
		err = errno;
		error("Can't read local name on %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	memcpy(dev->name, name, 248);

	if (!(features[6] & LMP_SIMPLE_PAIR))
		goto setup;

	if (ioctl(dd, HCIGETAUTHINFO, NULL) < 0 && errno != EINVAL)
		hci_write_simple_pairing_mode(dd, 0x01, 2000);

	if (hci_read_simple_pairing_mode(dd, &dev->ssp_mode, 1000) < 0) {
		err = errno;
		error("Can't read simple pairing mode on %s: %s (%d)",
					adapter->path, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

setup:
	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		adapter->state |= STD_INQUIRY;
	else
		adapter->state &= ~STD_INQUIRY;

	adapter_setup(adapter, dd);
	adapter_up(adapter, dd);

	hci_close_dev(dd);

	info("Adapter %s has been enabled", adapter->path);

	return 0;
}

static void reply_pending_requests(struct btd_adapter *adapter)
{
	DBusMessage *reply;

	if (!adapter)
		return;

	/* pending bonding */
	if (adapter->bonding) {
		reply = new_authentication_return(adapter->bonding->msg,
					HCI_OE_USER_ENDED_CONNECTION);
		g_dbus_send_message(connection, reply);
		remove_pending_device(adapter);

		g_dbus_remove_watch(adapter->bonding->conn,
					adapter->bonding->listener_id);

		if (adapter->bonding->io_id)
			g_source_remove(adapter->bonding->io_id);
		g_io_channel_close(adapter->bonding->io);
		bonding_request_free(adapter->bonding);
		adapter->bonding = NULL;
	}

	if (adapter->state & STD_INQUIRY) {
		/* Cancel inquiry initiated by D-Bus client */
		if (adapter->disc_sessions)
			cancel_discovery(adapter);
	}

	if (adapter->state & PERIODIC_INQUIRY) {
		/* Stop periodic inquiry initiated by D-Bus client */
		if (adapter->disc_sessions)
			cancel_periodic_discovery(adapter);
	}
}

static void unload_drivers(struct btd_adapter *adapter)
{
	GSList *l;

	for (l = adapter_drivers; l; l = l->next) {
		struct btd_adapter_driver *driver = l->data;

		if (driver->remove)
			driver->remove(adapter);
	}
}

int adapter_stop(struct btd_adapter *adapter)
{
	const char *mode = "off";

	/* cancel pending timeout */
	if (adapter->discov_timeout_id) {
		g_source_remove(adapter->discov_timeout_id);
		adapter->discov_timeout_id = 0;
	}

	/* check pending requests */
	reply_pending_requests(adapter);

	if (adapter->disc_sessions) {
		g_slist_foreach(adapter->disc_sessions, (GFunc) session_free,
				NULL);
		g_slist_free(adapter->disc_sessions);
		adapter->disc_sessions = NULL;
	}

	if (adapter->found_devices) {
		g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	if (adapter->auth_reqs) {
		g_slist_foreach(adapter->auth_reqs, (GFunc) g_free, NULL);
		g_slist_free(adapter->auth_reqs);
		adapter->auth_reqs = NULL;
	}

	if (adapter->active_conn) {
		g_slist_foreach(adapter->active_conn, (GFunc) g_free, NULL);
		g_slist_free(adapter->active_conn);
		adapter->active_conn = NULL;
	}

	dbus_connection_emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &mode);

	adapter->up = 0;
	adapter->scan_mode = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->state = DISCOVER_TYPE_NONE;

	unload_drivers(adapter);

	info("Adapter %s has been disabled", adapter->path);

	return 0;
}

int adapter_update(struct btd_adapter *adapter)
{
	struct hci_dev *dev = &adapter->dev;
	int dd;

	if (dev->ignore)
		return 0;

	dd = hci_open_dev(adapter->dev_id);
	if (dd < 0) {
		int err = errno;
		error("Can't open adapter %s: %s (%d)",
					adapter->path, strerror(err), err);
		return -err;
	}

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

int adapter_get_class(struct btd_adapter *adapter, uint8_t *cls)
{
	struct hci_dev *dev = &adapter->dev;

	memcpy(cls, dev->class, 3);

	return 0;
}

int adapter_set_class(struct btd_adapter *adapter, uint8_t *cls)
{
	struct hci_dev *dev = &adapter->dev;

	memcpy(dev->class, cls, 3);

	return 0;
}

int adapter_update_ssp_mode(struct btd_adapter *adapter, int dd, uint8_t mode)
{
	struct hci_dev *dev = &adapter->dev;

	dev->ssp_mode = mode;

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

static void adapter_free(gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	agent_destroy(adapter->agent, FALSE);
	adapter->agent = NULL;

	g_free(adapter->path);
	g_free(adapter);

	return;
}

struct btd_adapter *adapter_create(DBusConnection *conn, int id)
{
	char path[MAX_PATH_LENGTH];
	struct btd_adapter *adapter;

	if (!connection)
		connection = conn;

	snprintf(path, sizeof(path), "%s/hci%d", "/org/bluez", id);

	adapter = g_try_new0(struct btd_adapter, 1);
	if (!adapter) {
		error("Failed to alloc memory to D-Bus path register data (%s)",
				path);
		return NULL;
	}

	adapter->dev_id = id;
	adapter->state |= RESOLVE_NAME;
	adapter->path = g_strdup(path);

	if (!g_dbus_register_interface(conn, path, ADAPTER_INTERFACE,
			adapter_methods, adapter_signals, NULL,
			adapter, adapter_free)) {
		error("Adapter interface init failed on path %s", path);
		adapter_free(adapter);
		return NULL;
	}

	return adapter;
}

void adapter_remove(struct btd_adapter *adapter)
{
	GSList *l;
	char *path = g_strdup(adapter->path);

	debug("Removing adapter %s", path);

	for (l = adapter->devices; l; l = l->next)
		device_remove(connection, l->data);
	g_slist_free(adapter->devices);

	g_dbus_unregister_interface(connection, path, ADAPTER_INTERFACE);

	g_free(path);
}

uint16_t adapter_get_dev_id(struct btd_adapter *adapter)
{
	return adapter->dev_id;
}

const gchar *adapter_get_path(struct btd_adapter *adapter)
{
	if (!adapter)
		return NULL;

	return adapter->path;
}

void adapter_get_address(struct btd_adapter *adapter, bdaddr_t *bdaddr)
{
	str2ba(adapter->address, bdaddr);
}

static gboolean discov_timeout_handler(void *data)
{
	struct btd_adapter *adapter = data;
	struct hci_request rq;
	int dd;
	uint8_t scan_enable = adapter->scan_mode;
	uint8_t status = 0;
	gboolean retval = TRUE;
	uint16_t dev_id = adapter->dev_id;

	scan_enable &= ~SCAN_INQUIRY;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("HCI device open failed: hci%d", dev_id);
		return TRUE;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_SCAN_ENABLE;
	rq.cparam = &scan_enable;
	rq.clen   = sizeof(scan_enable);
	rq.rparam = &status;
	rq.rlen   = sizeof(status);
	rq.event  = EVT_CMD_COMPLETE;

	if (hci_send_req(dd, &rq, 1000) < 0) {
		error("Sending write scan enable command to hci%d failed: %s (%d)",
				dev_id, strerror(errno), errno);
		goto failed;
	}
	if (status) {
		error("Setting scan enable failed with status 0x%02x", status);
		goto failed;
	}

	set_limited_discoverable(dd, adapter->dev.class, FALSE);

	adapter_remove_discov_timeout(adapter);
	retval = FALSE;

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return retval;
}

void adapter_set_discov_timeout(struct btd_adapter *adapter, guint interval)
{
	if (!adapter)
		return;

	if (adapter->discov_timeout_id) {
		error("Timeout already added for adapter %s", adapter->path);
		return;
	}

	adapter->discov_timeout_id = g_timeout_add(interval, discov_timeout_handler, adapter);
}

void adapter_remove_discov_timeout(struct btd_adapter *adapter)
{
	if (!adapter)
		return;

	if(adapter->discov_timeout_id == 0)
		return;

	g_source_remove(adapter->discov_timeout_id);
	adapter->discov_timeout_id = 0;
}

void adapter_set_scan_mode(struct btd_adapter *adapter, uint8_t scan_mode)
{
	if (!adapter)
		return;

	adapter->scan_mode = scan_mode;
}

uint8_t adapter_get_scan_mode(struct btd_adapter *adapter)
{
	return adapter->scan_mode;
}

void adapter_set_mode(struct btd_adapter *adapter, uint8_t mode)
{
	if (!adapter)
		return;

	adapter->mode = mode;
}

uint8_t adapter_get_mode(struct btd_adapter *adapter)
{
	return adapter->mode;
}

void adapter_set_state(struct btd_adapter *adapter, int state)
{
	gboolean discov_active = FALSE;
	const char *path = adapter->path;

	if (adapter->state == state)
		return;

	if (state & PERIODIC_INQUIRY || state & STD_INQUIRY)
		discov_active = TRUE;
	else if (adapter->disc_sessions && main_opts.inqmode)
		adapter->scheduler_id = g_timeout_add(main_opts.inqmode * 1000,
				(GSourceFunc) start_inquiry, adapter);

	if (!discov_active && adapter->found_devices) {
		g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (!discov_active && adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices, (GFunc) g_free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	dbus_connection_emit_property_changed(connection, path,
				ADAPTER_INTERFACE, "Discovering",
				DBUS_TYPE_BOOLEAN, &discov_active);

	adapter->state = state;
}

int adapter_get_state(struct btd_adapter *adapter)
{
	return adapter->state;
}

struct remote_dev_info *adapter_search_found_devices(struct btd_adapter *adapter,
						struct remote_dev_info *match)
{
	GSList *l;

	l = g_slist_find_custom(adapter->found_devices, match,
					(GCompareFunc) found_device_cmp);
	if (l)
		return l->data;

	return NULL;
}

int dev_rssi_cmp(struct remote_dev_info *d1, struct remote_dev_info *d2)
{
	int rssi1, rssi2;

	rssi1 = d1->rssi < 0 ? -d1->rssi : d1->rssi;
	rssi2 = d2->rssi < 0 ? -d2->rssi : d2->rssi;

	return rssi1 - rssi2;
}

int adapter_add_found_device(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				int8_t rssi, name_status_t name_status)
{
	struct remote_dev_info *dev, match;

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, bdaddr);
	match.name_status = NAME_ANY;

	/* ignore repeated entries */
	dev = adapter_search_found_devices(adapter, &match);
	if (dev) {
		/* device found, update the attributes */
		if (rssi != 0)
			dev->rssi = rssi;

		 /* Get remote name can be received while inquiring.
		  * Keep in mind that multiple inquiry result events can
		  * be received from the same remote device.
		  */
		if (name_status != NAME_NOT_REQUIRED)
			dev->name_status = name_status;

		adapter->found_devices = g_slist_sort(adapter->found_devices,
						(GCompareFunc) dev_rssi_cmp);

		return -EALREADY;
	}

	dev = g_new0(struct remote_dev_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->rssi = rssi;
	dev->name_status = name_status;

	adapter->found_devices = g_slist_insert_sorted(adapter->found_devices,
						dev, (GCompareFunc) dev_rssi_cmp);

	return 0;
}

int adapter_remove_found_device(struct btd_adapter *adapter, bdaddr_t *bdaddr)
{
	struct remote_dev_info *dev, match;

	memset(&match, 0, sizeof(struct remote_dev_info));
	bacpy(&match.bdaddr, bdaddr);

	dev = adapter_search_found_devices(adapter, &match);
	if (!dev)
		return -1;

	adapter->found_devices = g_slist_remove(adapter->found_devices, dev);
	g_free(dev);

	return 0;
}

void adapter_update_oor_devices(struct btd_adapter *adapter)
{
	GSList *l = adapter->found_devices;
	struct remote_dev_info *dev;
	bdaddr_t tmp;

	send_out_of_range(adapter->path, adapter->oor_devices);

	g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
	g_slist_free(adapter->oor_devices);
	adapter->oor_devices = NULL;

	while (l) {
		dev = l->data;
		baswap(&tmp, &dev->bdaddr);
		adapter->oor_devices = g_slist_append(adapter->oor_devices,
							batostr(&tmp));
		l = l->next;
	}
}

void adapter_remove_oor_device(struct btd_adapter *adapter, char *peer_addr)
{
	GSList *l;

	l = g_slist_find_custom(adapter->oor_devices, peer_addr,
				(GCompareFunc) strcmp);
	if (l) {
		char *dev = l->data;
		adapter->oor_devices = g_slist_remove(adapter->oor_devices,
								dev);
		g_free(dev);
	}
}

void adapter_mode_changed(struct btd_adapter *adapter, uint8_t scan_mode)
{
	const char *mode;
	const gchar *path = adapter_get_path(adapter);

	adapter_set_scan_mode(adapter, scan_mode);

	switch (scan_mode) {
	case SCAN_DISABLED:
		mode = "off";
		adapter_set_mode(adapter, MODE_OFF);
		break;
	case SCAN_PAGE:
		mode = "connectable";
		adapter_set_mode(adapter, MODE_CONNECTABLE);
		break;
	case (SCAN_PAGE | SCAN_INQUIRY):

		if (adapter->discov_timeout != 0)
			adapter_set_discov_timeout(adapter, adapter->discov_timeout * 1000);

		if (adapter_get_mode(adapter) == MODE_LIMITED) {
			mode = "limited";
		} else {
			adapter_set_mode(adapter, MODE_DISCOVERABLE);
			mode = "discoverable";
		}
		break;
	case SCAN_INQUIRY:
		/* Address the scenario where another app changed the scan mode */
		if (adapter->discov_timeout != 0)
			adapter_set_discov_timeout(adapter, adapter->discov_timeout * 1000);

		/* ignore, this event should not be sent*/
	default:
		/* ignore, reserved */
		return;
	}

	dbus_connection_emit_property_changed(connection, path,
					ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &mode);
}

struct agent *adapter_get_agent(struct btd_adapter *adapter)
{
	if (!adapter || !adapter->agent)
		return NULL;

	return adapter->agent;
}

void adapter_add_active_conn(struct btd_adapter *adapter, bdaddr_t *bdaddr,
				uint16_t handle)
{
	struct active_conn_info *dev;

	if (!adapter)
		return;

	dev = g_new0(struct active_conn_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->handle = handle;

	adapter->active_conn = g_slist_append(adapter->active_conn, dev);
}

void adapter_remove_active_conn(struct btd_adapter *adapter,
				struct active_conn_info *dev)
{
	if (!adapter || !adapter->active_conn)
		return;

	adapter->active_conn = g_slist_remove(adapter->active_conn, dev);
	g_free(dev);
}

struct active_conn_info *adapter_search_active_conn_by_bdaddr(struct btd_adapter *adapter,
						    bdaddr_t *bda)
{
	GSList *l;

	if (!adapter || !adapter->active_conn)
		return NULL;

	l = g_slist_find_custom(adapter->active_conn, &bda,
					active_conn_find_by_bdaddr);
	if (l)
		return l->data;

	return NULL;
}

struct active_conn_info *adapter_search_active_conn_by_handle(struct btd_adapter *adapter,
						    uint16_t handle)
{
	GSList *l;

	if (!adapter || !adapter->active_conn)
		return NULL;

	l = g_slist_find_custom(adapter->active_conn, &handle,
					active_conn_find_by_handle);
	if (l)
		return l->data;

	return NULL;
}

void adapter_free_bonding_request(struct btd_adapter *adapter)
{
	g_dbus_remove_watch(connection, adapter->bonding->listener_id);

	if (adapter->bonding->io_id)
		g_source_remove(adapter->bonding->io_id);

	g_io_channel_close(adapter->bonding->io);

	bonding_request_free(adapter->bonding);

	adapter->bonding = NULL;
}

struct bonding_request_info *adapter_get_bonding_info(struct btd_adapter *adapter)
{
	if (!adapter || !adapter->bonding)
		return NULL;

	return adapter->bonding;
}

gboolean adapter_has_discov_sessions(struct btd_adapter *adapter)
{
	if (!adapter || !adapter->disc_sessions)
		return FALSE;

	return TRUE;
}

int btd_register_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_append(adapter_drivers, driver);

	return 0;
}

void btd_unregister_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_remove(adapter_drivers, driver);
}

static void agent_auth_cb(struct agent *agent, DBusError *derr, void *user_data)
{
	struct service_auth *auth = user_data;

	auth->cb(derr, auth->user_data);

	g_free(auth);
}

int btd_request_authorization(const bdaddr_t *src, const bdaddr_t *dst,
		const char *uuid, service_auth_cb cb, void *user_data)
{
	struct service_auth *auth;
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct agent *agent;
	char address[18];
	gboolean trusted;
	const gchar *dev_path;

	if (src == NULL || dst == NULL)
		return -EINVAL;

	adapter = manager_find_adapter(src);
	if (!adapter)
		return -EPERM;

	/* Device connected? */
	if (!g_slist_find_custom(adapter->active_conn,
				dst, active_conn_find_by_bdaddr))
		return -ENOTCONN;

	ba2str(dst, address);
	trusted = read_trust(src, address, GLOBAL_TRUST);

	if (trusted) {
		cb(NULL, user_data);
		return 0;
	}

	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	agent = device_get_agent(device);

	if (!agent)
		agent =  adapter->agent;

	if (!agent)
		return -EPERM;

	auth = g_try_new0(struct service_auth, 1);
	if (!auth)
		return -ENOMEM;

	auth->cb = cb;
	auth->user_data = user_data;

	dev_path = device_get_path(device);

	return agent_authorize(agent, dev_path, uuid, agent_auth_cb, auth);
}

int btd_cancel_authorization(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct btd_adapter *adapter = manager_find_adapter(src);
	struct btd_device *device;
	struct agent *agent;
	char address[18];

	if (!adapter)
		return -EPERM;

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	/*
	 * FIXME: Cancel fails if authorization is requested to adapter's
	 * agent and in the meanwhile CreatePairedDevice is called.
	 */

	agent = device_get_agent(device);

	if (!agent)
		agent =  adapter->agent;

	if (!agent)
		return -EPERM;

	return agent_cancel(agent);
}
