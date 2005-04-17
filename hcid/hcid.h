/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "glib-ectomy.h"

#define HCID_CONFIG_FILE CONFIGDIR "/hcid.conf"
#define HCID_PIN_FILE    CONFIGDIR "/pin"
#define HCID_KEY_FILE    CONFIGDIR "/link_key"
#define HCID_PIN_HELPER  "/usr/bin/bluepin"

struct device_opts {
	char    *name;
	uint32_t class;
	uint16_t pkt_type;
	uint16_t scan;
	uint16_t link_mode;
	uint16_t link_policy;
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
void hcid_dbus_request_pin(int dev, struct hci_conn_info *ci);
gboolean hcid_dbus_init(void);
#endif

int write_device_name(const bdaddr_t *local, const bdaddr_t *peer, const char *name);
int write_link_key(const bdaddr_t *local, const bdaddr_t *peer, const unsigned char *key, const int type);
int read_link_key(const bdaddr_t *local, const bdaddr_t *peer, unsigned char *key);
int read_pin_code(const bdaddr_t *local, const bdaddr_t *peer, char *pin);
