/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <time.h>
#include <sys/types.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "logging.h"

#define HCID_CONFIG_FILE CONFIGDIR "/hcid.conf"

#define HCID_DEFAULT_DISCOVERABLE_TIMEOUT 180 /* 3 minutes */

/* When all services should trust a remote device */
#define GLOBAL_TRUST "[all]"

enum {
	HCID_SET_NAME,
	HCID_SET_CLASS,
	HCID_SET_VOICE,
	HCID_SET_INQMODE,
	HCID_SET_PAGETO,
	HCID_SET_DISCOVTO,
	HCID_SET_PTYPE,
	HCID_SET_LM,
	HCID_SET_LP,
};

/*
 * Scanning modes, used by DEV_SET_MODE
 * off: remote devices are not allowed to find or connect to this device
 * connectable: remote devices are allowed to connect, but they are not
 *              allowed to find it.
 * discoverable: remote devices are allowed to connect and find this device
 * limited: limited discoverable - GIAC + IAC enabled and set limited
 *          bit on device class.
 */

#define MODE_OFF		0x00
#define MODE_CONNECTABLE	0x01
#define MODE_DISCOVERABLE	0x02
#define MODE_LIMITED		0x03
#define MODE_UNKNOWN		0xff

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
	uint8_t  scan;
	uint8_t  mode;
	uint32_t discovto;
};

extern struct device_opts default_device;
extern struct device_opts *parser_device;

struct device_list {
	char *ref;			/* HCI device or Bluetooth address */
	struct device_list *next;
	struct device_opts opts;
};

struct hcid_opts {
	char    host_name[40];
	int     auto_init;
	int     security;
	int     pairing;
	int	offmode;
        char    deviceid[15];

	char   *config_file;

	uint8_t pin_code[16];
	int     pin_len;

	int     sock;
};
extern struct hcid_opts hcid;

typedef enum {
	REQ_PENDING,
	REQ_SENT
} req_status_t;

struct hci_req_data {
	int dev_id;
	int event;
	req_status_t status;
	bdaddr_t dba;
	uint16_t ogf;
	uint16_t ocf;
	void *cparam;
	int clen;
};

struct hci_req_data *hci_req_data_new(int dev_id, const bdaddr_t *dba, uint16_t ogf, uint16_t ocf, int event, const void *cparam, int clen);
void hci_req_queue_append(struct hci_req_data *data);
void hci_req_queue_remove(int dev_id, bdaddr_t *dba);

#define HCID_SEC_NONE	0
#define HCID_SEC_AUTO	1
#define HCID_SEC_USER	2

#define HCID_PAIRING_NONE	0
#define HCID_PAIRING_MULTI	1
#define HCID_PAIRING_ONCE	2

#define HCID_OFFMODE_DEVDOWN	0
#define HCID_OFFMODE_NOSCAN	1

int read_config(char *file);

struct device_opts *alloc_device_opts(char *ref);

uint8_t get_startup_scan(int hdev);
uint8_t get_startup_mode(int hdev);
int get_discoverable_timeout(int dev_id);

void init_security_data(void);
void start_security_manager(int hdev);
void stop_security_manager(int hdev);
void toggle_pairing(int enable);

void set_pin_length(bdaddr_t *sba, int length);

void init_adapters(void);
int add_adapter(uint16_t dev_id);
int remove_adapter(uint16_t dev_id);
int start_adapter(uint16_t dev_id);
int stop_adapter(uint16_t dev_id);
int update_adapter(uint16_t dev_id);

int get_device_address(uint16_t dev_id, char *address, size_t size);
int get_device_class(uint16_t dev_id, uint8_t *class);
int set_device_class(uint16_t dev_id, uint8_t *class);
int get_device_version(uint16_t dev_id, char *version, size_t size);
int get_device_revision(uint16_t dev_id, char *revision, size_t size);
int get_device_manufacturer(uint16_t dev_id, char *manufacturer, size_t size);
int get_device_company(uint16_t dev_id, char *company, size_t size);

int set_simple_pairing_mode(uint16_t dev_id, uint8_t mode);
int get_device_name(uint16_t dev_id, char *name, size_t size);
int set_device_name(uint16_t dev_id, const char *name);
int get_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr, char *alias, size_t size);
int set_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr, const char *alias);

int get_encryption_key_size(uint16_t dev_id, const bdaddr_t *baddr);

int write_discoverable_timeout(bdaddr_t *bdaddr, int timeout);
int read_discoverable_timeout(bdaddr_t *bdaddr, int *timeout);
int write_device_mode(bdaddr_t *bdaddr, const char *mode);
int read_device_mode(bdaddr_t *bdaddr, char *mode, int length);
int read_on_mode(bdaddr_t *bdaddr, char *mode, int length);
int write_local_name(bdaddr_t *bdaddr, char *name);
int read_local_name(bdaddr_t *bdaddr, char *name);
int write_local_class(bdaddr_t *bdaddr, uint8_t *class);
int read_local_class(bdaddr_t *bdaddr, uint8_t *class);
int write_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class);
int read_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t *class);
int write_device_name(bdaddr_t *local, bdaddr_t *peer, char *name);
int read_device_name(bdaddr_t *local, bdaddr_t *peer, char *name);
int write_remote_eir(bdaddr_t *local, bdaddr_t *peer, uint8_t *data);
int write_l2cap_info(bdaddr_t *local, bdaddr_t *peer,
			uint16_t mtu_result, uint16_t mtu,
			uint16_t mask_result, uint32_t mask);
int read_l2cap_info(bdaddr_t *local, bdaddr_t *peer,
			uint16_t *mtu_result, uint16_t *mtu,
			uint16_t *mask_result, uint32_t *mask);
int write_version_info(bdaddr_t *local, bdaddr_t *peer, uint16_t manufacturer, uint8_t lmp_ver, uint16_t lmp_subver);
int write_features_info(bdaddr_t *local, bdaddr_t *peer, unsigned char *features);
int write_lastseen_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm);
int write_lastused_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm);
int write_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t type, int length);
int read_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t *type);
int read_pin_length(bdaddr_t *local, bdaddr_t *peer);
int read_pin_code(bdaddr_t *local, bdaddr_t *peer, char *pin);
gboolean read_trust(const bdaddr_t *local, const char *addr, const char *service);
int write_trust(bdaddr_t *local, const char *addr, const char *service, gboolean trust);
GSList *list_trusts(bdaddr_t *local, const char *service);
int write_device_profiles(bdaddr_t *src, bdaddr_t *dst, const char *profiles);
int delete_entry(bdaddr_t *src, const char *storage, const char *key);

gboolean plugin_init(GKeyFile *config);
void plugin_cleanup(void);
void __probe_servers(const char *adapter);
void __remove_servers(const char *adapter);
