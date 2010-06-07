/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

/* When all services should trust a remote device */
#define GLOBAL_TRUST "[all]"

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

#define HCID_DEFAULT_DISCOVERABLE_TIMEOUT 180 /* 3 minutes */

/* Timeout for hci_send_req (milliseconds) */
#define HCI_REQ_TIMEOUT		5000

struct main_opts {
	char		host_name[40];
	unsigned long	flags;
	char		*name;
	uint32_t	class;
	uint16_t	pageto;
	uint32_t	discovto;
	uint32_t	pairto;
	uint16_t	link_mode;
	uint16_t	link_policy;
	gboolean	remember_powered;
	gboolean	reverse_sdp;
	gboolean	name_resolv;
	gboolean	debug_keys;

	uint8_t		scan;
	uint8_t		mode;
	uint8_t		discov_interval;
	char		deviceid[15]; /* FIXME: */

	int		sock;
};

enum {
	HCID_SET_NAME,
	HCID_SET_CLASS,
	HCID_SET_PAGETO,
	HCID_SET_DISCOVTO,
};

extern struct main_opts main_opts;

char *expand_name(char *dst, int size, char *str, int dev_id);

void hci_req_queue_remove(int dev_id, bdaddr_t *dba);

void start_security_manager(int hdev);
void stop_security_manager(int hdev);

void btd_start_exit_timer(void);
void btd_stop_exit_timer(void);

void set_pin_length(bdaddr_t *sba, int length);

gboolean plugin_init(GKeyFile *config);
void plugin_cleanup(void);

void rfkill_init(void);
void rfkill_exit(void);

void __probe_servers(const char *adapter);
void __remove_servers(const char *adapter);
