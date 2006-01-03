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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "glib-ectomy.h"

#include "hcid.h"
#include "lib.h"

static GIOChannel *io_chan[HCI_MAX_DEV];

static int pairing;

void toggle_pairing(int enable)
{
	if (enable)
		pairing = hcid.pairing;
	else
		pairing = 0;

	syslog(LOG_INFO, "Pairing %s", pairing ? "enabled" : "disabled");
}

static inline int get_bdaddr(int dev, bdaddr_t *sba, uint16_t handle, bdaddr_t *dba)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	char addr[18];
	int i;

	cl = malloc(10 * sizeof(*ci) + sizeof(*cl));
	if (!cl)
		return -ENOMEM;

	ba2str(sba, addr);
	cl->dev_id = hci_devid(addr);
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dev, HCIGETCONNLIST, (void *) cl) < 0) {
		free(cl);
		return -EIO;
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		if (ci->handle == handle) {
			bacpy(dba, &ci->bdaddr);
			free(cl);
			return 0;
		}

	free(cl);
	return -ENOENT;
}

/* Link Key handling */

/* This function is not reentrable */
static struct link_key *__get_link_key(int f, bdaddr_t *sba, bdaddr_t *dba)
{
	static struct link_key k;
	struct link_key *key = NULL;
	int r;

	while ((r = read_n(f, &k, sizeof(k)))) {
		if (r < 0) {
			syslog(LOG_ERR, "Link key database read failed: %s (%d)",
							strerror(errno), errno);
			break;
		}

		if (!bacmp(&k.sba, sba) && !bacmp(&k.dba, dba)) {
			key = &k;
			break;
		}
	}

	return key;
}

static struct link_key *get_link_key(bdaddr_t *sba, bdaddr_t *dba)
{
	struct link_key *key = NULL;
	int f;

	f = open(hcid.key_file, O_RDONLY);
	if (f >= 0)
		key = __get_link_key(f, sba, dba);
	else if (errno != ENOENT)
		syslog(LOG_ERR, "Link key database open failed: %s (%d)",
							strerror(errno), errno);

	close(f);

	return key;
}

static void link_key_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	unsigned char key[16];
	char sa[18], da[18];
	int err;

	ba2str(sba, sa); ba2str(dba, da);
	syslog(LOG_INFO, "link_key_request (sba=%s, dba=%s)", sa, da);

	err = read_link_key(sba, dba, key);
	if (err < 0) {
		struct link_key *linkkey = get_link_key(sba, dba);
		if (linkkey) {
			memcpy(key, linkkey->key, 16);
			linkkey->time = time(0);
			err = 0;
		}
	}

	if (err < 0) {
		/* Link key not found */
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6, dba);
	} else {
		/* Link key found */
		link_key_reply_cp lr;
		memcpy(lr.link_key, key, 16);
		bacpy(&lr.bdaddr, dba);
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_REPLY,
						LINK_KEY_REPLY_CP_SIZE, &lr);
	}
}

#if 0
static void save_link_key(struct link_key *key)
{
	struct link_key *exist;
	char sa[18], da[18];
	int f, err;

	f = open(hcid.key_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (f < 0) {
		syslog(LOG_ERR, "Link key database open failed: %s (%d)",
							strerror(errno), errno);
		return;
	}

	/* Check if key already exist */
	exist = __get_link_key(f, &key->sba, &key->dba);

	err = 0;

	if (exist) {
		off_t o = lseek(f, 0, SEEK_CUR);
		err = lseek(f, o - sizeof(*key), SEEK_SET);
	} else
		err = fcntl(f, F_SETFL, O_APPEND);

	if (err < 0) {
		syslog(LOG_ERR, "Link key database seek failed: %s (%d)",
							strerror(errno), errno);
		goto failed;
	}

	if (write_n(f, key, sizeof(*key)) < 0) {
		syslog(LOG_ERR, "Link key database write failed: %s (%d)",
							strerror(errno), errno);
	}

	ba2str(&key->sba, sa); ba2str(&key->dba, da);
	syslog(LOG_INFO, "%s link key %s %s", exist ? "Replacing" : "Saving", sa, da);

failed:
	close(f);
}
#endif

static void link_key_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_link_key_notify *evt = ptr;
	bdaddr_t *dba = &evt->bdaddr;
	struct link_key key;
	char sa[18], da[18];

	ba2str(sba, sa); ba2str(dba, da);
	syslog(LOG_INFO, "link_key_notify (sba=%s, dba=%s)", sa, da);

	memcpy(key.key, evt->link_key, 16);
	bacpy(&key.sba, sba);
	bacpy(&key.dba, dba);
	key.type = evt->key_type;
	key.time = time(0);

#if 0
	save_link_key(&key);
#endif

	write_link_key(sba, dba, evt->link_key, evt->key_type);
}

static void return_link_keys(int dev, bdaddr_t *sba, void *ptr)
{
	evt_return_link_keys *evt = ptr;
	uint8_t num = evt->num_keys;
	unsigned char key[16];
	char sa[18], da[18];
	bdaddr_t dba;
	int i;

	ba2str(sba, sa);
	ptr++;

	for (i = 0; i < num; i++) {
		bacpy(&dba, ptr); ba2str(&dba, da);
		memcpy(key, ptr + 6, 16);

		syslog(LOG_INFO, "return_link_keys (sba=%s, dba=%s)", sa, da);

		ptr += 22;
	}
}

/* PIN code handling */

static int read_default_pin_code(void)
{
	char buf[17];
	FILE *f; 
	int len;

	if (!(f = fopen(hcid.pin_file, "r"))) {
		syslog(LOG_ERR, "Can't open PIN file %s: %s (%d)",
					hcid.pin_file, strerror(errno), errno);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f)) {
		strtok(buf, "\n\r");
		len = strlen(buf); 
		memcpy(hcid.pin_code, buf, len);
		hcid.pin_len = len;
	} else {
		syslog(LOG_ERR, "Can't read PIN file %s: %s (%d)",
					hcid.pin_file, strerror(errno), errno);
		len = -1;
	}

	fclose(f);

	return len;
}

/*
  PIN helper is an external app that asks user for a PIN. It can 
  implement its own PIN  code generation policy and methods like
  PIN look up in some database, etc. 
  HCId expects following output from PIN helper:
	PIN:12345678	-	PIN code
	ERR		-	No PIN available
*/

static void call_pin_helper(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
	pin_code_reply_cp pr;
	struct sigaction sa;
	char addr[18], str[512], *pin, name[249], tmp[497], *ptr;
	FILE *pipe;
	int i, ret, len;

	/* Run PIN helper in the separate process */
	switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "Can't fork PIN helper: %s (%d)",
							strerror(errno), errno);
		default:
			return;
	}

	if (access(hcid.pin_helper, R_OK | X_OK)) {
		syslog(LOG_ERR, "Can't exec PIN helper %s: %s (%d)",
					hcid.pin_helper, strerror(errno), errno);
		goto reject;
	}

	memset(name, 0, sizeof(name));
	read_device_name(sba, &ci->bdaddr, name);
	//hci_remote_name(dev, &ci->bdaddr, sizeof(name), name, 0);

	memset(tmp, 0, sizeof(tmp));
	ptr = tmp;

	for (i = 0; i < 248 && name[i]; i++)
		if (isprint(name[i])) {
			switch (name[i]) {
			case '"':
			case '`':
			case '$':
			case '|':
			case '>':
			case '<':
			case '&':
			case ';':
			case '\\':
				*ptr++ = '\\';
			}
			*ptr++ = name[i];
		} else {
			name[i] = '.';
			*ptr++ = '.';
		}

	ba2str(&ci->bdaddr, addr);
	snprintf(str, sizeof(str), "%s %s %s \"%s\"", hcid.pin_helper,
					ci->out ? "out" : "in", addr, tmp);

	setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

	pipe = popen(str, "r");
	if (!pipe) {
		syslog(LOG_ERR, "Can't exec PIN helper: %s (%d)",
							strerror(errno), errno);
		goto reject;
	}

	pin = fgets(str, sizeof(str), pipe);
	ret = pclose(pipe);

	if (!pin || strlen(pin) < 5)
		goto nopin;

	strtok(pin, "\n\r");

	if (strncmp("PIN:", pin, 4))
		goto nopin;

	pin += 4;
	len  = strlen(pin);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &ci->bdaddr);
	memcpy(pr.pin_code, pin, len);
	pr.pin_len = len;
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
			PIN_CODE_REPLY_CP_SIZE, &pr);
	exit(0);

nopin:
	if (!pin || strncmp("ERR", pin, 3))
		syslog(LOG_ERR, "PIN helper exited abnormally with code %d", ret);

reject:
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, &ci->bdaddr);
	exit(0);
}

static void request_pin(int dev, bdaddr_t *sba, struct hci_conn_info *ci)
{
#ifdef ENABLE_DBUS
	if (hcid.dbus_pin_helper) {
		hcid_dbus_request_pin(dev, ci);
		return;
	}
#endif
	call_pin_helper(dev, sba, ci);
}

static void pin_code_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	pin_code_reply_cp pr;
	struct hci_conn_info_req *cr;
	struct hci_conn_info *ci;
	char sa[18], da[18], pin[17];
	int pinlen;

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, dba);

	ba2str(sba, sa); ba2str(dba, da);
	syslog(LOG_INFO, "pin_code_request (sba=%s, dba=%s)", sa, da);

	cr = malloc(sizeof(*cr) + sizeof(*ci));
	if (!cr)
		return;

	bacpy(&cr->bdaddr, dba);
	cr->type = ACL_LINK;
	if (ioctl(dev, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		syslog(LOG_ERR, "Can't get conn info: %s (%d)",
							strerror(errno), errno);
		goto reject;
	}
	ci = cr->conn_info;

	memset(pin, 0, sizeof(pin));
	pinlen = read_pin_code(sba, dba, pin);

	if (pairing == HCID_PAIRING_ONCE) {
		struct link_key *key = get_link_key(sba, dba);
		if (key) {
			ba2str(dba, da);
			syslog(LOG_WARNING, "PIN code request for already paired device %s", da);
			goto reject;
		}
	} else if (pairing == HCID_PAIRING_NONE)
		goto reject;

	if (hcid.security == HCID_SEC_AUTO) {
		if (!ci->out) {
			/* Incomming connection */
			memcpy(pr.pin_code, hcid.pin_code, hcid.pin_len);
			pr.pin_len = hcid.pin_len;
			hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
				PIN_CODE_REPLY_CP_SIZE, &pr);
		} else {
			/* Outgoing connection */
			if (pinlen > 0) {
				memcpy(pr.pin_code, pin, pinlen);
				pr.pin_len = pinlen;
				hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
					PIN_CODE_REPLY_CP_SIZE, &pr);
			} else {
				/* Let PIN helper handle that */ 
				request_pin(dev, sba, ci);
			}
		}
	} else {
		/* Let PIN helper handle that */ 
		request_pin(dev, sba, ci);
	}
	free(cr);
	return;

reject:
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);
	free(cr);
	return;
}

static inline void cmd_status(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_status *evt = ptr;

	if (evt->status)
		return;

	if (evt->opcode == cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY))
		hcid_dbus_inquiry_start(sba);
}

static inline void cmd_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_complete *evt = ptr;
	switch (evt->opcode) {
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY_CANCEL):
		hcid_dbus_inquiry_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME):
		hcid_dbus_setname_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE):
		hcid_dbus_setscan_enable_complete(sba);
	};
}

static inline void remote_name_information(int dev, bdaddr_t *sba, void *ptr)
{
	evt_remote_name_req_complete *evt = ptr;
	bdaddr_t dba;

	bacpy(&dba, &evt->bdaddr);

	if (!evt->status) {
		char name[249];
		memset(name, 0, sizeof(name));
		memcpy(name, evt->name, 248);
		write_device_name(sba, &dba, name);
		hcid_dbus_remote_name(sba, &dba, name);
	} else
		hcid_dbus_remote_name_failed(sba, &dba, evt->status);
}

static inline void remote_version_information(int dev, bdaddr_t *sba, void *ptr)
{
	evt_read_remote_version_complete *evt = ptr;
	bdaddr_t dba;

	if (evt->status)
		return;

	if (get_bdaddr(dev, sba, btohs(evt->handle), &dba) < 0)
		return;

	write_version_info(sba, &dba, btohs(evt->manufacturer),
				evt->lmp_ver, btohs(evt->lmp_subver));
}

static inline void inquiry_complete(int dev, bdaddr_t *sba, void *ptr)
{
	hcid_dbus_inquiry_complete(sba);
}

static inline void inquiry_result(int dev, bdaddr_t *sba, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0]
			| (info->dev_class[1] << 8)
			| (info->dev_class[2] << 16);

		hcid_dbus_inquiry_result(sba, &info->bdaddr, class, 0);

		ptr += INQUIRY_INFO_SIZE;
	}
}

static inline void inquiry_result_with_rssi(int dev, bdaddr_t *sba, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	if (!num)
		return;

	if ((plen - 1) / num == INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE) {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi_and_pscan_mode *info = ptr;
			uint32_t class = info->dev_class[0]
				| (info->dev_class[1] << 8)
				| (info->dev_class[2] << 16);

			hcid_dbus_inquiry_result(sba, &info->bdaddr,
							class, info->rssi);

			ptr += INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE;
		}
	} else {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi *info = ptr;
			uint32_t class = info->dev_class[0]
				| (info->dev_class[1] << 8)
				| (info->dev_class[2] << 16);

			hcid_dbus_inquiry_result(sba, &info->bdaddr,
							class, info->rssi);

			ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
		}
	}
}

static inline void extended_inquiry_result(int dev, bdaddr_t *sba, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		extended_inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0]
			| (info->dev_class[1] << 8)
			| (info->dev_class[2] << 16);

		hcid_dbus_inquiry_result(sba, &info->bdaddr, class, info->rssi);

		ptr += EXTENDED_INQUIRY_INFO_SIZE;
	}
}

static inline void remote_features_information(int dev, bdaddr_t *sba, void *ptr)
{
	evt_read_remote_features_complete *evt = ptr;
	bdaddr_t dba;

	if (evt->status)
		return;

	if (get_bdaddr(dev, sba, btohs(evt->handle), &dba) < 0)
		return;

	write_features_info(sba, &dba, evt->features);
}

static inline void conn_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_conn_complete *evt = ptr;

	if (evt->status)
		return;

	hcid_dbus_conn_complete(sba, &evt->bdaddr);
}

static inline void disconn_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_disconn_complete *evt = ptr;
	bdaddr_t dba;

	if (evt->status)
		return;

	bacpy(&dba, BDADDR_ANY);

	hcid_dbus_disconn_complete(sba, &dba, evt->reason);
}

static inline void auth_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_auth_complete *evt = ptr;
	bdaddr_t dba;

	if (get_bdaddr(dev, sba, evt->handle, &dba) < 0) 
		return;

	hcid_dbus_auth_complete(sba, &dba, evt->status);
}


static gboolean io_security_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_dev_info *di = (void *) data;
	int type, dev;
	size_t len;
	hci_event_hdr *eh;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		free(data);
		return FALSE;
	}

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		g_io_channel_close(chan);
		free(data);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	ptr += HCI_EVENT_HDR_SIZE;

	dev = g_io_channel_unix_get_fd(chan);

	ioctl(dev, HCIGETDEVINFO, (void *) di);

	if (hci_test_bit(HCI_RAW, &di->flags))
		return TRUE;

	switch (eh->evt) {
	case EVT_CMD_STATUS:
		cmd_status(dev, &di->bdaddr, ptr);
		break;

	case EVT_CMD_COMPLETE:
		cmd_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_REMOTE_NAME_REQ_COMPLETE:
		remote_name_information(dev, &di->bdaddr, ptr);
		break;

	case EVT_READ_REMOTE_VERSION_COMPLETE:
		remote_version_information(dev, &di->bdaddr, ptr);
		break;

	case EVT_READ_REMOTE_FEATURES_COMPLETE:
		remote_features_information(dev, &di->bdaddr, ptr);
		break;

	case EVT_INQUIRY_COMPLETE:
		inquiry_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_INQUIRY_RESULT:
		inquiry_result(dev, &di->bdaddr, eh->plen, ptr);
		break;

	case EVT_INQUIRY_RESULT_WITH_RSSI:
		inquiry_result_with_rssi(dev, &di->bdaddr, eh->plen, ptr);
		break;

	case EVT_EXTENDED_INQUIRY_RESULT:
		extended_inquiry_result(dev, &di->bdaddr, eh->plen, ptr);
		break;

	case EVT_CONN_COMPLETE:
		conn_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_DISCONN_COMPLETE:
		disconn_complete(dev, &di->bdaddr, ptr);
		break;
	case EVT_AUTH_COMPLETE:
		auth_complete(dev, &di->bdaddr, ptr);
		break;
	}

	if (hci_test_bit(HCI_SECMGR, &di->flags))
		return TRUE;

	switch (eh->evt) {
	case EVT_PIN_CODE_REQ:
		pin_code_request(dev, &di->bdaddr, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_REQ:
		link_key_request(dev, &di->bdaddr, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_NOTIFY:
		link_key_notify(dev, &di->bdaddr, ptr);
		break;

	case EVT_RETURN_LINK_KEYS:
		return_link_keys(dev, &di->bdaddr, ptr);
		break;
	}

	return TRUE;
}

void start_security_manager(int hdev)
{
	GIOChannel *chan = io_chan[hdev];
	struct hci_dev_info *di;
	struct hci_filter flt;
	read_stored_link_key_cp cp;
	int dev;

	if (chan)
		return;

	syslog(LOG_INFO, "Starting security manager %d", hdev);

	if ((dev = hci_open_dev(hdev)) < 0) {
		syslog(LOG_ERR, "Can't open device hci%d: %s (%d)",
						hdev, strerror(errno), errno);
		return;
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_CMD_STATUS, &flt);
	hci_filter_set_event(EVT_CMD_COMPLETE, &flt);
	hci_filter_set_event(EVT_PIN_CODE_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_NOTIFY, &flt);
	hci_filter_set_event(EVT_RETURN_LINK_KEYS, &flt);
	hci_filter_set_event(EVT_REMOTE_NAME_REQ_COMPLETE, &flt);
	hci_filter_set_event(EVT_READ_REMOTE_VERSION_COMPLETE, &flt);
	hci_filter_set_event(EVT_READ_REMOTE_FEATURES_COMPLETE, &flt);
	hci_filter_set_event(EVT_INQUIRY_COMPLETE, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT_WITH_RSSI, &flt);
	hci_filter_set_event(EVT_EXTENDED_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_CONN_COMPLETE, &flt);
	hci_filter_set_event(EVT_DISCONN_COMPLETE, &flt);
	hci_filter_set_event(EVT_AUTH_COMPLETE, &flt);
	if (setsockopt(dev, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_ERR, "Can't set filter on hci%d: %s (%d)",
						hdev, strerror(errno), errno);
		close(dev);
		return;
	}

	di = malloc(sizeof(*di));
	if (!di) {
		syslog(LOG_ERR, "Can't allocate device info buffer: %s (%d)",
							strerror(errno), errno);
		close(dev);
		return;
	}

	di->dev_id = hdev;
	if (ioctl(dev, HCIGETDEVINFO, (void *)di)) {
		syslog(LOG_ERR, "Can't get device info: %s (%d)",
							strerror(errno), errno);
		close(dev);
		return;
	}

	chan = g_io_channel_unix_new(dev);
	g_io_add_watch(chan, G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
			io_security_event, (void *) di);

	io_chan[hdev] = chan;

	if (hci_test_bit(HCI_RAW, &di->flags))
		return;

	bacpy(&cp.bdaddr, BDADDR_ANY);
	cp.read_all = 1;

	hci_send_cmd(dev, OGF_HOST_CTL, OCF_READ_STORED_LINK_KEY,
			READ_STORED_LINK_KEY_CP_SIZE, (void *) &cp);
}

void stop_security_manager(int hdev)
{
	GIOChannel *chan = io_chan[hdev];

	if (!chan)
		return;

	syslog(LOG_INFO, "Stoping security manager %d", hdev);

	/* this is a bit sneaky. closing the fd will cause the event
	   loop to call us right back with G_IO_NVAL set, at which
	   point we will see it and clean things up */
	close(g_io_channel_unix_get_fd(chan));
	io_chan[hdev] = NULL;
}

void init_security_data(void)
{
	/* Set local PIN code */
	if (read_default_pin_code() < 0) {
		strcpy((char *) hcid.pin_code, "BlueZ");
		hcid.pin_len = 5;
	}

	pairing = hcid.pairing;
}
