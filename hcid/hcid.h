/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <syslog.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "glib-ectomy.h"

#define HCID_CONFIG_FILE CONFIGDIR "/hcid.conf"
#define HCID_PIN_FILE    CONFIGDIR "/pin"
#define HCID_KEY_FILE    CONFIGDIR "/link_key"
#define HCID_PIN_HELPER  "/usr/bin/bluepin"

enum {
	HCID_SET_NAME,
	HCID_SET_CLASS,
	HCID_SET_VOICE,
	HCID_SET_INQMODE,
	HCID_SET_PAGETO,
	HCID_SET_PTYPE,
	HCID_SET_LM,
	HCID_SET_LP,
};

struct device_opts {
	unsigned long flags;
	char    *name;
	uint32_t class;
	uint16_t voice;
	uint8_t  inqmode;
	uint16_t pageto;
	uint16_t pkt_type;
	uint16_t link_mode;
	uint16_t link_policy;
	uint16_t scan;
	uint16_t auth;
	uint16_t encrypt;
};

extern struct device_opts default_device;
extern struct device_opts *parser_device;

struct device_list {
	char *ref;			/* HCI device or Bluetooth address */
	struct device_list *next;
	struct device_opts opts;
};

struct link_key {
	bdaddr_t sba;
	bdaddr_t dba;
	uint8_t  key[16];
	uint8_t  type;
	time_t   time;
};

struct hcid_opts {
	char   *host_name;
	int     auto_init;
	int     security;
	int     pairing;

	char   *config_file;

	uint8_t pin_code[16];
	int     pin_len;
	char   *pin_helper;
	char   *pin_file;
	int     dbus_pin_helper;

	char   *key_file;

	int     sock;
};
extern struct hcid_opts hcid;

#define HCID_SEC_NONE	0
#define HCID_SEC_AUTO	1
#define HCID_SEC_USER	2

#define HCID_PAIRING_NONE	0
#define HCID_PAIRING_MULTI	1
#define HCID_PAIRING_ONCE	2

int read_config(char *file);

struct device_opts *alloc_device_opts(char *ref);

void init_security_data(void);
void start_security_manager(int hdev);
void stop_security_manager(int hdev);
void toggle_pairing(int enable);

#ifdef ENABLE_DBUS
gboolean hcid_dbus_init(void);
void hcid_dbus_exit(void);
gboolean hcid_dbus_register_device(uint16_t id);
gboolean hcid_dbus_unregister_device(uint16_t id);
gboolean hcid_dbus_dev_up(uint16_t id);
gboolean hcid_dbus_dev_down(uint16_t id);
void hcid_dbus_request_pin(int dev, struct hci_conn_info *ci);

void hcid_dbus_inquiry_start(bdaddr_t *local);
void hcid_dbus_inquiry_complete(bdaddr_t *local);
void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi);
void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, char *name);
void hcid_dbus_remote_name_failed(bdaddr_t *local, bdaddr_t *peer, uint8_t status);
void hcid_dbus_conn_complete(bdaddr_t *local, bdaddr_t *peer);
void hcid_dbus_disconn_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t reason);
void hcid_dbus_auth_complete(bdaddr_t *local, bdaddr_t *peer, const uint8_t status);
void hcid_dbus_setname_complete(bdaddr_t *local);
void hcid_dbus_setscan_enable_complete(bdaddr_t *local);
#else
static inline void hcid_dbus_inquiry_start(bdaddr_t *local) {}
static inline void hcid_dbus_inquiry_complete(bdaddr_t *local) {}
static inline void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi) {}
static inline void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, char *name) {}
static inline void hcid_dbus_remote_name_failed(bdaddr_t *local, bdaddr_t *peer, uint8_t status) {}
static inline void hcid_dbus_conn_complete(bdaddr_t *local, bdaddr_t *peer) {}
static inline void hcid_dbus_disconn_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t reason) {}
static inline void hcid_dbus_auth_complete(bdaddr_t *local, bdaddr_t *peer, const uint8_t status) {}
static inline void hcid_dbus_setname_complete(bdaddr_t *local) {}
static inline void hcid_dbus_setscan_enable_complete(bdaddr_t *local) {}
#endif

int write_device_name(bdaddr_t *local, bdaddr_t *peer, char *name);
int read_device_name(bdaddr_t *local, bdaddr_t *peer, char *name);
int write_version_info(bdaddr_t *local, bdaddr_t *peer, uint16_t manufacturer, uint8_t lmp_ver, uint16_t lmp_subver);
int write_features_info(bdaddr_t *local, bdaddr_t *peer, unsigned char *features);
int write_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, int type);
int read_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key);
int read_pin_code(bdaddr_t *local, bdaddr_t *peer, char *pin);

static inline int find_conn(int dd, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	cl = malloc(10 * sizeof(*ci) + sizeof(*cl));
	if (!cl) {
		syslog(LOG_ERR, "Can't allocate memory");
		return 0;
	}

	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, (void *) cl)) {
		syslog(LOG_ERR, "Can't get connection list");
		return 0;
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		if (!bacmp((bdaddr_t *) arg, &ci->bdaddr))
			return 1;

	free(cl);

	return 0;
}
