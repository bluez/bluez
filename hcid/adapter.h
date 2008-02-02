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

struct remote_dev_info {
	bdaddr_t bdaddr;
	int8_t rssi;
	name_status_t name_status;
};

struct bonding_request_info {
	bdaddr_t bdaddr;
	DBusConnection *conn;
	DBusMessage *rq;
	GIOChannel *io;
	guint io_id;
	int hci_status;
	int cancel;
	int auth_active;
};

struct pending_pin_info {
	bdaddr_t bdaddr;
	int replied;	/* If we've already replied to the request */
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
	char address[18];		/* adapter Bluetooth Address */
	guint timeout_id;		/* discoverable timeout id */
	uint32_t discov_timeout;	/* discoverable time(msec) */
	uint8_t scan_enable;		/* scan mode: SCAN_DISABLED, SCAN_PAGE, SCAN_INQUIRY */
	uint8_t mode;			/* off, connectable, discoverable, limited */
	uint8_t class[3];		/* device class */
	int discov_active;		/* standard discovery active: includes name resolution step */
	int pdiscov_active;		/* periodic discovery active */
	int pinq_idle;			/* tracks the idle time for periodic inquiry */
	int discov_type;		/* type requested */
	int pdiscov_resolve_names;	/* Resolve names when doing periodic discovery */
	GSList *found_devices;
	GSList *oor_devices;	/* out of range device list */
	char *pdiscov_requestor;	/* periodic discovery requestor unique name */
	char *discov_requestor;		/* discovery requestor unique name */
	DBusMessage *discovery_cancel;	/* discovery cancel message request */
	GSList *passkey_agents;
	GSList *auth_agents;	/* Authorization agents */
	bdaddr_t agents_disabled;	/* temporarely disable agents for bda */
	GSList *active_conn;
	struct bonding_request_info *bonding;
	GSList *pin_reqs;
	struct pending_dc_info *pending_dc;
};

dbus_bool_t adapter_init(DBusConnection *conn, const char *path);

const char *major_class_str(uint32_t class);

const char *minor_class_str(uint32_t class);

const char *mode2str(uint8_t mode);

uint8_t str2mode(const char *addr, const char *mode);

GSList *service_classes_str(uint32_t class);

int pending_remote_name_cancel(struct adapter *adapter);

void dc_pending_timeout_cleanup(struct adapter *adapter);
