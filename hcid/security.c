/* 
	BlueZ - Bluetooth protocol stack for Linux
	Copyright (C) 2000-2001 Qualcomm Incorporated

	Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation;

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
	IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
	OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
	RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
	NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
	USE OR PERFORMANCE OF THIS SOFTWARE.

	ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
	TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/
/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <asm/types.h>

#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>

#include <glib.h>

#include "hcid.h"
#include "lib.h"

static GIOChannel *io_chan[HCI_MAX_DEV];

void save_link_keys(void)
{
	int n, f;

	umask(0077);
	if (!(f = open(hcid.key_file, O_WRONLY | O_CREAT | O_TRUNC, 0))) {
		syslog(LOG_ERR, "Can't save key database %s. %s(%d)",
				hcid.key_file, strerror(errno), errno);
		return;
	}

	for (n = 0; n < hcid.key_num; n++) {
		if (!hcid.link_key[n])
			continue;

		if (write_n(f, hcid.link_key[n], sizeof(struct link_key)) < 0)
			break;
	}
	
	close(f);
}

void flush_link_keys(void)
{
	int n;
	for (n=0; n < hcid.key_num; n++) {
		if (hcid.link_key[n]) {
			free(hcid.link_key[n]);
			hcid.link_key[n] = NULL;
		}
	}
}

int read_link_keys(void)
{
	int f, n = 0;

	if (!(f = open(hcid.key_file, O_RDONLY))) {
		syslog(LOG_ERR, "Can't open key database %s. %s(%d)",
				hcid.key_file, strerror(errno), errno);
		return -1;
	}

	while (n < hcid.key_num) {
		struct link_key *key;
		int r;

		key = malloc(sizeof(*key));
		if (!key)
			continue;

		r = read_n(f, key, sizeof(*key));
		if (r <= 0) {
			free(key);
			break;
		}

		hcid.link_key[n++] = key;
	}
	
	close(f);
	return n;
}

int read_pin_code(void)
{
	char buf[17];
	FILE *f; 
	int len;

	if (!(f = fopen(hcid.pin_file, "r"))) {
		syslog(LOG_ERR, "Can't open PIN file %s. %s(%d)",
				hcid.pin_file, strerror(errno), errno);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f)) {
		strtok(buf, "\n\r");
		len = strlen(buf); 
		memcpy(hcid.pin_code, buf, len);
		hcid.pin_len = len;
	} else {
		syslog(LOG_ERR, "Can't read PIN file %s. %s(%d)",
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

static void call_pin_helper(int dev, struct hci_conn_info *ci)
{
	pin_code_reply_cp pr;
	char str[255], *pin, name[20];
	bdaddr_t ba;
	FILE *pipe;
	int len;
	
	/* Run PIN helper in the separate process */
	switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "Can't fork PIN helper. %s(%d)", 
					strerror(errno), errno);
		default:
			return;
	}

	if (access(hcid.pin_helper, R_OK | X_OK)) {
		syslog(LOG_ERR, "Can't exec PIN helper %s. %s(%d)",
				hcid.pin_helper, strerror(errno), errno);
		goto reject;
	}

	name[0] = 0;
	//hci_remote_name(dev, &ci->bdaddr, sizeof(name), name, 0);

	baswap(&ba, &ci->bdaddr);
	sprintf(str, "%s %s %s \'%s\'", hcid.pin_helper, 
			ci->out ? "out" : "in", 
			batostr(&ba), name);

	setenv("PATH", "/bin:/usr/bin:/usr/local/bin", 1);

	pipe = popen(str, "r");
	if (!pipe) {
		syslog(LOG_ERR, "Can't exec PIN helper. %s(%d)", strerror(errno), errno);
		goto reject;
	}	

	pin = fgets(str, sizeof(str), pipe);
	pclose(pipe);

	if (!pin || strlen(pin) < 5)
		goto reject;

	strtok(pin, "\n\r");

	if (strncmp("PIN:", pin, 4))
		goto reject;

	pin += 4;
	len  = strlen(pin);
	
	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &ci->bdaddr);
	memcpy(pr.pin_code, pin, len);
	pr.pin_len = len;
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
			PIN_CODE_REPLY_CP_SIZE, &pr);
	exit(0);

reject:
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, &ci->bdaddr);
	exit(0);
}

static void link_key_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	struct link_key *key = NULL;
	int n;

	/* Find the key */
	for (n=0; n < hcid.key_num; n++) {
		if (!hcid.link_key[n])
			continue;
		if (!bacmp(&hcid.link_key[n]->sba, sba) && 
				!bacmp(&hcid.link_key[n]->dba, dba)) {
			key = hcid.link_key[n];
			break;
		}
	}

	if (key) {
		/* Link key found */
		link_key_reply_cp lr;
		memcpy(lr.link_key, key->key, 16);
		bacpy(&lr.bdaddr, dba);
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_REPLY,
				LINK_KEY_REPLY_CP_SIZE, &lr);
		key->time = time(0);
	} else {
		/* Link key not found */
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6, dba);
	}
}

static void pin_code_request(int dev, bdaddr_t *ba)
{
	struct hci_conn_info_req *cr;
	struct hci_conn_info *ci;
	
	cr = malloc(sizeof(*cr) + sizeof(*ci));
	if (!cr)
		return;

	bacpy(&cr->bdaddr, ba);
	cr->type = ACL_LINK;
	if (ioctl(dev, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		syslog(LOG_ERR, "Can't get conn info %s(%d)",
					strerror(errno), errno);
		/* Reject PIN */
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, ba);

		free(cr);
		return;
	}
	ci = cr->conn_info;

	if (hcid.security == HCID_SEC_AUTO) {
		if (!ci->out) {
			/* Incomming connection */
			pin_code_reply_cp pr;
			memset(&pr, 0, sizeof(pr));
			bacpy(&pr.bdaddr, ba);
			memcpy(pr.pin_code, hcid.pin_code, hcid.pin_len);
			pr.pin_len = hcid.pin_len;
			hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
				PIN_CODE_REPLY_CP_SIZE, &pr);
		} else {
			/* Outgoing connection */
		
			/* Let PIN helper handle that */ 
			call_pin_helper(dev, ci);
		}
	} else {
		/* Let PIN helper handle that */ 
		call_pin_helper(dev, ci);
	}	
	free(cr);
}

static void link_key_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_link_key_notify *evt = ptr;
	bdaddr_t *dba = &evt->bdaddr;
	struct link_key *key;
	time_t tm = time(0);
	int n, k = -1;

	/* Find a slot */
	for (n=0; n < hcid.key_num; n++) {
		key = hcid.link_key[n];
		if (!key || (!bacmp(&key->sba, sba) && !bacmp(&key->dba, dba)) ||
				(tm - key->time) > HCID_KEY_TTL) {
			k = n;
			break;
		}
	}

	if (k != -1) {
		/* Update link key */
		key = hcid.link_key[k];
		if (!key && !(key = malloc(sizeof(*key))))
			return;

		bacpy(&key->sba, sba);
		bacpy(&key->dba, dba);
		memcpy(key->key, evt->link_key, 16);
		key->type = evt->key_type;
		key->time = tm;

		hcid.link_key[k] = key;
	}
}

gboolean io_security_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_dev_info *di = (void *) data;
	int len, type, dev;
	hci_event_hdr *eh;
	GIOError err;

	if (cond & G_IO_NVAL) {
		free(data);
		return FALSE;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		free(data);
		return FALSE;
	}
	
	if ((err = g_io_channel_read(chan, buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		g_io_channel_close(chan);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	ptr += HCI_EVENT_HDR_SIZE;

	dev = g_io_channel_unix_get_fd(chan);

	switch (eh->evt) {
	case EVT_PIN_CODE_REQ:
		pin_code_request(dev, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_REQ:
		link_key_request(dev, &di->bdaddr, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_NOTIFY:
		link_key_notify(dev, &di->bdaddr, ptr);
		break;
	}
		
	return TRUE;
}

int init_security_data(void)
{
	void *buf;

	buf = calloc(hcid.key_num, sizeof(void*));
	if (!buf) {
		syslog(LOG_ERR, "Can't allocate link key database. %s(%d)",
				strerror(errno), errno);
		return -1;
	}
	hcid.link_key = buf;
	read_link_keys();

	/* Set local PIN code */
	if (hcid.security == HCID_SEC_AUTO) {
		if (read_pin_code() < 0) {
			strcpy(hcid.pin_code, "bluez");
			hcid.pin_len = 5;
		}
	}
	
	return 0;
}

void start_security_manager(int hdev)
{
	GIOChannel *chan = io_chan[hdev];
	struct hci_dev_info *di;
	struct hci_filter flt;
	int dev;

	if (chan)
		return;
	
	syslog(LOG_INFO, "Starting security manager %d", hdev);

	if (!hcid.link_key && init_security_data())
		return;

	if ((dev = hci_open_dev(hdev)) < 0) {
		syslog(LOG_ERR, "Can't open device hci%d. %s(%d)",
				hdev, strerror(errno), errno);
		return;
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_PIN_CODE_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_NOTIFY, &flt);
	if (setsockopt(dev, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_ERR, "Can't set filter on hci%d. %s(%d)", 
				hdev, strerror(errno), errno);
		close(dev);
		return;
	}

	di = malloc(sizeof(*di));
	if (!di) {
		syslog(LOG_ERR, "Can't allocate device info buffer. %s(%d)", 
				strerror(errno), errno);
		close(dev);
		return;
	}
	
	di->dev_id = hdev;
	if (ioctl(dev, HCIGETDEVINFO, (void *)di)) {
		syslog(LOG_ERR, "Can't get device info. %s(%d)", 
				strerror(errno), errno);
		close(dev);
		return;
	}
	
	chan = g_io_channel_unix_new(dev);
	g_io_add_watch(chan, G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
			io_security_event, (void *) di);

	io_chan[hdev] = chan;
}

void stop_security_manager(int hdev)
{
	GIOChannel *chan = io_chan[hdev];

	if (!chan)
		return;

	syslog(LOG_INFO, "Stoping security manager %d", hdev);

	close(g_io_channel_unix_get_fd(chan));
	io_chan[hdev] = NULL;
}
