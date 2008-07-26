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

#define ADAPTER_INTERFACE	"org.bluez.Adapter"

#define INVALID_DEV_ID		0xFFFF

#define BONDING_TIMEOUT         45000 /* 45 sec */

#define DC_PENDING_TIMEOUT      2000  /* 2 secs */

/* Discover types */
#define DISCOVER_TYPE_NONE	0x00
#define STD_INQUIRY		0x01
#define PERIODIC_INQUIRY	0x02

/* Actions executed after inquiry complete */
#define RESOLVE_NAME		0x10

typedef enum {
	NAME_ANY,
	NAME_NOT_REQUIRED, /* used by get remote name without name resolving */
	NAME_REQUIRED,      /* remote name needs be resolved       */
	NAME_REQUESTED,    /* HCI remote name request was sent    */
	NAME_SENT          /* D-Bus signal RemoteNameUpdated sent */
} name_status_t;

typedef enum {
	AUTH_TYPE_PINCODE,
	AUTH_TYPE_PASSKEY,
	AUTH_TYPE_CONFIRM,
	AUTH_TYPE_NOTIFY,
} auth_type_t;

struct remote_dev_info {
	bdaddr_t bdaddr;
	int8_t rssi;
	name_status_t name_status;
};

struct bonding_request_info {
	DBusConnection *conn;
	DBusMessage *msg;
	struct adapter *adapter;
	bdaddr_t bdaddr;
	GIOChannel *io;
	guint io_id;
	guint listener_id;
	int hci_status;
	int cancel;
	int auth_active;
};

struct pending_auth_info {
	auth_type_t type;
	bdaddr_t bdaddr;
	gboolean replied;	/* If we've already replied to the request */
	struct agent *agent;    /* Agent associated with the request */
};

struct active_conn_info {
	bdaddr_t bdaddr;
	uint16_t handle;
};

struct pending_dc_info {
	DBusConnection *conn;
	DBusMessage *msg;
	uint16_t conn_handle;
	guint timeout_id;
};

struct adapter {
	uint16_t dev_id;
	int up;
	char *path;			/* adapter object path */
	char address[18];		/* adapter Bluetooth Address */
	guint timeout_id;		/* discoverable timeout id */
	uint32_t discov_timeout;	/* discoverable time(msec) */
	uint8_t scan_enable;		/* scan mode: SCAN_DISABLED, SCAN_PAGE, SCAN_INQUIRY */
	uint8_t mode;			/* off, connectable, discoverable, limited */
	uint8_t global_mode;		/* last valid global mode */
	uint8_t class[3];		/* device class */
	int discov_active;		/* standard discovery active: includes name resolution step */
	int pdiscov_active;		/* periodic discovery active */
	int pinq_idle;			/* tracks the idle time for periodic inquiry */
	int discov_type;		/* type requested */
	int pdiscov_resolve_names;	/* Resolve names when doing periodic discovery */
	GSList *found_devices;
	GSList *oor_devices;	/* out of range device list */
	char *pdiscov_requestor;	/* periodic discovery requestor unique name */
	guint pdiscov_listener;
	char *discov_requestor;		/* discovery requestor unique name */
	guint discov_listener;
	DBusMessage *discovery_cancel;	/* discovery cancel message request */
	GSList *passkey_agents;
	struct agent *agent;		/* For the new API */
	GSList *active_conn;
	struct bonding_request_info *bonding;
	GSList *auth_reqs;		/* Received and replied HCI
					   authentication requests */
	struct pending_dc_info *pending_dc;
	GSList *devices;		/* Devices structure pointers */
	GSList *sessions;		/* Request Mode sessions */
};

dbus_bool_t adapter_init(DBusConnection *conn,
		const char *path, struct adapter *adapter);

dbus_bool_t adapter_cleanup(DBusConnection *conn, const char *path);

struct device *adapter_get_device(DBusConnection *conn,
				struct adapter *adapter, const gchar *address);

struct device *adapter_find_device(struct adapter *adapter, const char *dest);

void adapter_remove_device(DBusConnection *conn, struct adapter *adapter,
				struct device *device);
struct device *adapter_create_device(DBusConnection *conn,
				struct adapter *adapter, const char *address);

const char *major_class_str(uint32_t class);

const char *minor_class_str(uint32_t class);

const char *mode2str(uint8_t mode);

uint8_t str2mode(const char *addr, const char *mode);

GSList *service_classes_str(uint32_t class);

int pending_remote_name_cancel(struct adapter *adapter);

void dc_pending_timeout_cleanup(struct adapter *adapter);

void remove_pending_device(struct adapter *adapter);

void adapter_auth_request_replied(struct adapter *adapter, bdaddr_t *dba);
struct pending_auth_info *adapter_find_auth_request(struct adapter *adapter,
							bdaddr_t *dba);
void adapter_remove_auth_request(struct adapter *adapter, bdaddr_t *dba);
struct pending_auth_info *adapter_new_auth_request(struct adapter *adapter,
							bdaddr_t *dba,
							auth_type_t type);
