/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "plugin.h"
#include "log.h"
#include "storage.h"
#include "event.h"
#include "device.h"
#include "manager.h"

static int child_pipe[2] = { -1, -1 };

static guint child_io_id = 0;
static guint ctl_io_id = 0;

/* Commands sent by kernel on starting an adapter */
enum {
	PENDING_BDADDR,
	PENDING_VERSION,
	PENDING_FEATURES,
	PENDING_NAME,
};

#define SK(index) devs[(index)].sk
#define BDADDR(index) devs[(index)].bdaddr
#define NAME(index) devs[(index)].name
#define EIR(index) devs[(index)].eir
#define FEATURES(index) devs[(index)].features
#define SSP_MODE(index) devs[(index)].ssp_mode
#define TX_POWER(index) devs[(index)].tx_power
#define CURRENT_COD(index) devs[(index)].current_cod
#define WANTED_COD(index) devs[(index)].wanted_cod
#define PENDING_COD(index) devs[(index)].pending_cod
#define CACHE_ENABLE(index) devs[(index)].cache_enable
#define VER(index) devs[(index)].ver
#define DID_VENDOR(index) devs[(index)].did_vendor
#define DID_PRODUCT(index) devs[(index)].did_product
#define DID_VERSION(index) devs[(index)].did_version
#define UP(index) devs[(index)].up
#define PENDING(index) devs[(index)].pending
#define CHANNEL(index) devs[(index)].channel
#define WATCH_ID(index) devs[(index)].watch_id
#define PIN_LENGTH(index) devs[(index)].pin_length

static int max_dev = -1;
static struct dev_info {
	int sk;
	bdaddr_t bdaddr;
	char name[249];
	uint8_t eir[240];
	uint8_t features[8];
	uint8_t ssp_mode;

	int8_t tx_power;

	uint32_t current_cod;
	uint32_t wanted_cod;
	uint32_t pending_cod;
	gboolean cache_enable;

	struct hci_version ver;

	uint16_t did_vendor;
	uint16_t did_product;
	uint16_t did_version;

	gboolean up;
	unsigned long pending;

	GIOChannel *channel;
	guint watch_id;
	int pin_length;
} *devs = NULL;

static int ignore_device(struct hci_dev_info *di)
{
	return hci_test_bit(HCI_RAW, &di->flags) || di->type >> 4 != HCI_BREDR;
}

static void init_dev_info(int index, int sk)
{
	memset(&devs[index], 0, sizeof(struct dev_info));
	SK(index) = sk;
	PIN_LENGTH(index) = -1;
	CACHE_ENABLE(index) = TRUE;
}

/* Async HCI command handling with callback support */

struct hci_cmd_data {
	bt_hci_result_t		cb;
	uint16_t		handle;
	uint16_t		ocf;
	gpointer		caller_data;
};

static gboolean hci_event_watch(GIOChannel *io,
			GIOCondition cond, gpointer user_data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *body;
	struct hci_cmd_data *cmd = user_data;
	evt_cmd_status *evt_status;
	evt_auth_complete *evt_auth;
	evt_encrypt_change *evt_enc;
	hci_event_hdr *hdr;
	set_conn_encrypt_cp cp;
	int dd;
	uint16_t ocf;
	uint8_t status = HCI_OE_POWER_OFF;

	if (cond & G_IO_NVAL) {
		cmd->cb(status, cmd->caller_data);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	dd = g_io_channel_unix_get_fd(io);

	if (read(dd, buf, sizeof(buf)) < 0)
		goto failed;

	hdr = (hci_event_hdr *) (buf + 1);
	body = buf + (1 + HCI_EVENT_HDR_SIZE);

	switch (hdr->evt) {
	case EVT_CMD_STATUS:
		evt_status = (evt_cmd_status *) body;
		ocf = cmd_opcode_ocf(evt_status->opcode);
		if (ocf != cmd->ocf)
			return TRUE;
		switch (ocf) {
		case OCF_AUTH_REQUESTED:
		case OCF_SET_CONN_ENCRYPT:
			if (evt_status->status != 0) {
				/* Baseband rejected command */
				status = evt_status->status;
				goto failed;
			}
			break;
		default:
			return TRUE;
		}
		/* Wait for the next event */
		return TRUE;
	case EVT_AUTH_COMPLETE:
		evt_auth = (evt_auth_complete *) body;
		if (evt_auth->handle != cmd->handle) {
			/* Skipping */
			return TRUE;
		}

		if (evt_auth->status != 0x00) {
			status = evt_auth->status;
			/* Abort encryption */
			goto failed;
		}

		memset(&cp, 0, sizeof(cp));
		cp.handle  = cmd->handle;
		cp.encrypt = 1;

		cmd->ocf = OCF_SET_CONN_ENCRYPT;

		if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_SET_CONN_ENCRYPT,
					SET_CONN_ENCRYPT_CP_SIZE, &cp) < 0) {
			status = HCI_COMMAND_DISALLOWED;
			goto failed;
		}
		/* Wait for encrypt change event */
		return TRUE;
	case EVT_ENCRYPT_CHANGE:
		evt_enc = (evt_encrypt_change *) body;
		if (evt_enc->handle != cmd->handle)
			return TRUE;

		/* Procedure finished: reporting status */
		status = evt_enc->status;
		break;
	default:
		/* Skipping */
		return TRUE;
	}

failed:
	cmd->cb(status, cmd->caller_data);
	g_io_channel_shutdown(io, TRUE, NULL);

	return FALSE;
}

static int write_inq_mode(int index, uint8_t mode)
{
	write_inquiry_mode_cp cp;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE,
					WRITE_INQUIRY_MODE_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static uint8_t get_inquiry_mode(int index)
{
	if (FEATURES(index)[6] & LMP_EXT_INQ)
		return 2;

	if (FEATURES(index)[3] & LMP_RSSI_INQ)
		return 1;

	if (VER(index).manufacturer == 11 && VER(index).hci_rev == 0x00 &&
					VER(index).lmp_subver == 0x0757)
		return 1;

	if (VER(index).manufacturer == 15) {
		if (VER(index).hci_rev == 0x03 &&
					VER(index).lmp_subver == 0x6963)
			return 1;
		if (VER(index).hci_rev == 0x09 &&
					VER(index).lmp_subver == 0x6963)
			return 1;
		if (VER(index).hci_rev == 0x00 &&
					VER(index).lmp_subver == 0x6965)
			return 1;
	}

	if (VER(index).manufacturer == 31 && VER(index).hci_rev == 0x2005 &&
					VER(index).lmp_subver == 0x1805)
		return 1;

	return 0;
}

static int init_ssp_mode(int index)
{
	write_simple_pairing_mode_cp cp;

	if (ioctl(SK(index), HCIGETAUTHINFO, NULL) < 0 && errno == EINVAL)
		return 0;

	memset(&cp, 0, sizeof(cp));
	cp.mode = 0x01;

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_WRITE_SIMPLE_PAIRING_MODE,
				WRITE_SIMPLE_PAIRING_MODE_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static void start_adapter(int index)
{
	uint8_t events[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00 };
	uint8_t inqmode;
	uint16_t link_policy;

	if (VER(index).lmp_ver > 1) {
		if (FEATURES(index)[5] & LMP_SNIFF_SUBR)
			events[5] |= 0x20;

		if (FEATURES(index)[5] & LMP_PAUSE_ENC)
			events[5] |= 0x80;

		if (FEATURES(index)[6] & LMP_EXT_INQ)
			events[5] |= 0x40;

		if (FEATURES(index)[6] & LMP_NFLUSH_PKTS)
			events[7] |= 0x01;

		if (FEATURES(index)[7] & LMP_LSTO)
			events[6] |= 0x80;

		if (FEATURES(index)[6] & LMP_SIMPLE_PAIR) {
			events[6] |= 0x01;	/* IO Capability Request */
			events[6] |= 0x02;	/* IO Capability Response */
			events[6] |= 0x04;	/* User Confirmation Request */
			events[6] |= 0x08;	/* User Passkey Request */
			events[6] |= 0x10;	/* Remote OOB Data Request */
			events[6] |= 0x20;	/* Simple Pairing Complete */
			events[7] |= 0x04;	/* User Passkey Notification */
			events[7] |= 0x08;	/* Keypress Notification */
			events[7] |= 0x10;	/* Remote Host Supported
						 * Features Notification */
		}

		if (FEATURES(index)[4] & LMP_LE)
			events[7] |= 0x20;	/* LE Meta-Event */

		hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_SET_EVENT_MASK,
						sizeof(events), events);
	}

	if (FEATURES(index)[6] & LMP_SIMPLE_PAIR)
		init_ssp_mode(index);

	inqmode = get_inquiry_mode(index);
	if (inqmode)
		write_inq_mode(index, inqmode);

	if (FEATURES(index)[7] & LMP_INQ_TX_PWR)
		hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL, 0, NULL);


	/* Set default link policy */
	link_policy = main_opts.link_policy;

	if (!(FEATURES(index)[0] & LMP_RSWITCH))
		link_policy &= ~HCI_LP_RSWITCH;
	if (!(FEATURES(index)[0] & LMP_HOLD))
		link_policy &= ~HCI_LP_HOLD;
	if (!(FEATURES(index)[0] & LMP_SNIFF))
		link_policy &= ~HCI_LP_SNIFF;
	if (!(FEATURES(index)[1] & LMP_PARK))
		link_policy &= ~HCI_LP_PARK;

	link_policy = htobs(link_policy);
	hci_send_cmd(SK(index), OGF_LINK_POLICY, OCF_WRITE_DEFAULT_LINK_POLICY,
					sizeof(link_policy), &link_policy);

	CURRENT_COD(index) = 0;
	memset(EIR(index), 0, sizeof(EIR(index)));

	manager_start_adapter(index);
}

static int hciops_encrypt_link(int index, bdaddr_t *dst, bt_hci_result_t cb,
							gpointer user_data)
{
	GIOChannel *io;
	struct hci_cmd_data *cmd;
	struct hci_conn_info_req *cr;
	auth_requested_cp cp;
	struct hci_filter nf;
	int dd, err;
	uint32_t link_mode;
	uint16_t handle;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	cr->type = ACL_LINK;
	bacpy(&cr->bdaddr, dst);

	err = ioctl(dd, HCIGETCONNINFO, cr);
	link_mode = cr->conn_info->link_mode;
	handle = cr->conn_info->handle;
	g_free(cr);

	if (err < 0) {
		err = -errno;
		goto fail;
	}

	if (link_mode & HCI_LM_ENCRYPT) {
		err = -EALREADY;
		goto fail;
	}

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_AUTH_REQUESTED,
				AUTH_REQUESTED_CP_SIZE, &cp) < 0) {
		err = -errno;
		goto fail;
	}

	cmd = g_new0(struct hci_cmd_data, 1);
	cmd->handle = handle;
	cmd->ocf = OCF_AUTH_REQUESTED;
	cmd->cb	= cb;
	cmd->caller_data = user_data;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_AUTH_COMPLETE, &nf);
	hci_filter_set_event(EVT_ENCRYPT_CHANGE, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		err = -errno;
		g_free(cmd);
		goto fail;
	}

	io = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL | G_IO_IN,
			hci_event_watch, cmd, g_free);
	g_io_channel_unref(io);

	return 0;

fail:
	close(dd);
	return err;
}

static int hciops_set_did(int index, uint16_t vendor, uint16_t product,
							uint16_t version)
{
	DID_VENDOR(index) = vendor;
	DID_PRODUCT(index) = product;
	DID_VERSION(index) = version;

	return 0;
}

/* End async HCI command handling */

/* Start of HCI event callbacks */

static int get_handle(int index, bdaddr_t *dba, uint16_t *handle)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = index;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(SK(index), HCIGETCONNLIST, (void *) cl) < 0) {
		g_free(cl);
		return -EIO;
	}

	for (i = 0; i < cl->conn_num; i++, ci++) {
		if (bacmp(&ci->bdaddr, dba) == 0) {
			*handle = ci->handle;
			g_free(cl);
			return 0;
		}
	}

	g_free(cl);

	return -ENOENT;
}

static inline int get_bdaddr(int index, uint16_t handle, bdaddr_t *dba)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = index;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(SK(index), HCIGETCONNLIST, (void *) cl) < 0) {
		g_free(cl);
		return -EIO;
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		if (ci->handle == handle) {
			bacpy(dba, &ci->bdaddr);
			g_free(cl);
			return 0;
		}

	g_free(cl);

	return -ENOENT;
}

static inline void update_lastseen(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastseen_info(sba, dba, tm);
}

static inline void update_lastused(bdaddr_t *sba, bdaddr_t *dba)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = gmtime(&t);

	write_lastused_info(sba, dba, tm);
}

/* Link Key handling */

static void link_key_request(int index, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct hci_auth_info_req req;
	unsigned char key[16];
	char da[18];
	uint8_t type;
	int err;

	ba2str(dba, da);
	DBG("hci%d dba %s", index, da);

	adapter = manager_find_adapter(&BDADDR(index));
	if (adapter)
		device = adapter_find_device(adapter, da);
	else
		device = NULL;

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, dba);

	err = ioctl(SK(index), HCIGETAUTHINFO, (unsigned long) &req);
	if (err < 0) {
		if (errno != EINVAL)
			DBG("HCIGETAUTHINFO failed %s (%d)",
						strerror(errno), errno);
		req.type = 0x00;
	}

	DBG("kernel auth requirements = 0x%02x", req.type);

	if (main_opts.debug_keys && device &&
					device_get_debug_key(device, key))
		type = 0x03;
	else if (read_link_key(&BDADDR(index), dba, key, &type) < 0 ||
								type == 0x03) {
		/* Link key not found */
		hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY,
								6, dba);
		return;
	}

	/* Link key found */

	DBG("link key type 0x%02x", type);

	/* Don't use unauthenticated combination keys if MITM is
	 * required */
	if (type == 0x04 && req.type != 0xff && (req.type & 0x01))
		hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY,
								6, dba);
	else {
		link_key_reply_cp lr;

		memcpy(lr.link_key, key, 16);
		bacpy(&lr.bdaddr, dba);

		hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_LINK_KEY_REPLY,
						LINK_KEY_REPLY_CP_SIZE, &lr);
	}
}

static void link_key_notify(int index, void *ptr)
{
	evt_link_key_notify *evt = ptr;
	bdaddr_t *dba = &evt->bdaddr;
	char da[18];
	int err;
	unsigned char old_key[16];
	uint8_t old_key_type;

	ba2str(dba, da);
	DBG("hci%d dba %s type %d", index, da, evt->key_type);

	err = read_link_key(&BDADDR(index), dba, old_key, &old_key_type);
	if (err < 0)
		old_key_type = 0xff;

	err = btd_event_link_key_notify(&BDADDR(index), dba, evt->link_key,
					evt->key_type, PIN_LENGTH(index),
					old_key_type);
	PIN_LENGTH(index) = -1;

	if (err < 0) {
		uint16_t handle;

		if (err == -ENODEV)
			btd_event_bonding_process_complete(&BDADDR(index), dba,
							HCI_OE_LOW_RESOURCES);
		else
			btd_event_bonding_process_complete(&BDADDR(index), dba,
							HCI_MEMORY_FULL);

		if (get_handle(index, dba, &handle) == 0) {
			disconnect_cp cp;

			memset(&cp, 0, sizeof(cp));
			cp.handle = htobs(handle);
			cp.reason = HCI_OE_LOW_RESOURCES;

			hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_DISCONNECT,
						DISCONNECT_CP_SIZE, &cp);
		}
	}
}

static void return_link_keys(int index, void *ptr)
{
	evt_return_link_keys *evt = ptr;
	uint8_t num = evt->num_keys;
	unsigned char key[16];
	char da[18];
	bdaddr_t dba;
	int i;

	DBG("hci%d num_keys %u", index, num);

	ptr++;

	for (i = 0; i < num; i++) {
		bacpy(&dba, ptr); ba2str(&dba, da);
		memcpy(key, ptr + 6, 16);

		DBG("hci%d returned key for %s", index, da);

		btd_event_returned_link_key(&BDADDR(index), &dba);

		ptr += 22;
	}
}

/* Simple Pairing handling */

static void user_confirm_request(int index, void *ptr)
{
	evt_user_confirm_request *req = ptr;

	DBG("hci%d", index);

	if (btd_event_user_confirm(&BDADDR(index), &req->bdaddr,
					btohl(req->passkey)) < 0)
		hci_send_cmd(SK(index), OGF_LINK_CTL,
				OCF_USER_CONFIRM_NEG_REPLY, 6, ptr);
}

static void user_passkey_request(int index, void *ptr)
{
	evt_user_passkey_request *req = ptr;

	DBG("hci%d", index);

	if (btd_event_user_passkey(&BDADDR(index), &req->bdaddr) < 0)
		hci_send_cmd(SK(index), OGF_LINK_CTL,
				OCF_USER_PASSKEY_NEG_REPLY, 6, ptr);
}

static void user_passkey_notify(int index, void *ptr)
{
	evt_user_passkey_notify *req = ptr;

	DBG("hci%d", index);

	btd_event_user_notify(&BDADDR(index), &req->bdaddr,
						btohl(req->passkey));
}

static void remote_oob_data_request(int index, void *ptr)
{
	DBG("hci%d", index);
	hci_send_cmd(SK(index), OGF_LINK_CTL,
				OCF_REMOTE_OOB_DATA_NEG_REPLY, 6, ptr);
}

static void io_capa_request(int index, void *ptr)
{
	bdaddr_t *dba = ptr;
	char da[18];
	uint8_t cap, auth;

	ba2str(dba, da);
	DBG("hci%d IO capability request for %s", index, da);

	if (btd_event_get_io_cap(&BDADDR(index), dba, &cap, &auth) < 0) {
		io_capability_neg_reply_cp cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, dba);
		cp.reason = HCI_PAIRING_NOT_ALLOWED;
		hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_IO_CAPABILITY_NEG_REPLY,
					IO_CAPABILITY_NEG_REPLY_CP_SIZE, &cp);
	} else {
		io_capability_reply_cp cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, dba);
		cp.capability = cap;
		cp.oob_data = 0x00;
		cp.authentication = auth;
		hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_IO_CAPABILITY_REPLY,
					IO_CAPABILITY_REPLY_CP_SIZE, &cp);
	}
}

static void io_capa_response(int index, void *ptr)
{
	evt_io_capability_response *evt = ptr;
	char da[18];

	ba2str(&evt->bdaddr, da);
	DBG("hci%d IO capability response from %s", index, da);

	btd_event_set_io_cap(&BDADDR(index), &evt->bdaddr,
				evt->capability, evt->authentication);
}

/* PIN code handling */

static void pin_code_request(int index, bdaddr_t *dba)
{
	pin_code_reply_cp pr;
	struct hci_conn_info_req *cr;
	struct hci_conn_info *ci;
	char da[18], pin[17];
	int pinlen;

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, dba);

	ba2str(dba, da);
	DBG("hci%d PIN request for %s", index, da);

	cr = g_malloc0(sizeof(*cr) + sizeof(*ci));

	bacpy(&cr->bdaddr, dba);
	cr->type = ACL_LINK;
	if (ioctl(SK(index), HCIGETCONNINFO, (unsigned long) cr) < 0) {
		error("Can't get conn info: %s (%d)", strerror(errno), errno);
		goto reject;
	}
	ci = cr->conn_info;

	memset(pin, 0, sizeof(pin));
	pinlen = read_pin_code(&BDADDR(index), dba, pin);

	if (pinlen > 0) {
		PIN_LENGTH(index) = pinlen;
		memcpy(pr.pin_code, pin, pinlen);
		pr.pin_len = pinlen;
		hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
	} else {
		/* Request PIN from passkey agent */
		if (btd_event_request_pin(&BDADDR(index), ci) < 0)
			goto reject;
	}

	g_free(cr);

	return;

reject:
	g_free(cr);

	hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);
}

static void start_inquiry(bdaddr_t *local, uint8_t status, gboolean periodic)
{
	struct btd_adapter *adapter;
	int state;

	/* Don't send the signal if the cmd failed */
	if (status) {
		error("Inquiry Failed with status 0x%02x", status);
		return;
	}

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	state = adapter_get_state(adapter);

	if (periodic)
		state |= STATE_PINQ;
	else
		state |= STATE_STDINQ;

	adapter_set_state(adapter, state);
}

static void inquiry_complete(bdaddr_t *local, uint8_t status,
							gboolean periodic)
{
	struct btd_adapter *adapter;
	int state;

	/* Don't send the signal if the cmd failed */
	if (status) {
		error("Inquiry Failed with status 0x%02x", status);
		return;
	}

	adapter = manager_find_adapter(local);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	state = adapter_get_state(adapter);
	state &= ~(STATE_STDINQ | STATE_PINQ);
	adapter_set_state(adapter, state);
}

static inline void remote_features_notify(int index, void *ptr)
{
	evt_remote_host_features_notify *evt = ptr;

	if (evt->features[0] & 0x01)
		btd_event_set_legacy_pairing(&BDADDR(index), &evt->bdaddr,
									FALSE);
	else
		btd_event_set_legacy_pairing(&BDADDR(index), &evt->bdaddr,
									TRUE);

	write_features_info(&BDADDR(index), &evt->bdaddr, NULL, evt->features);
}

static void write_le_host_complete(bdaddr_t *sba, uint8_t status)
{
	struct btd_adapter *adapter;

	if (status)
		return;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	btd_adapter_read_local_ext_features(adapter);
}

static void read_local_version_complete(int index,
				const read_local_version_rp *rp)
{
	if (rp->status)
		return;

	VER(index).manufacturer = btohs(bt_get_unaligned(&rp->manufacturer));
	VER(index).hci_ver = rp->hci_ver;
	VER(index).hci_rev = btohs(bt_get_unaligned(&rp->hci_rev));
	VER(index).lmp_ver = rp->lmp_ver;
	VER(index).lmp_subver = btohs(bt_get_unaligned(&rp->lmp_subver));

	if (!PENDING(index))
		return;

	hci_clear_bit(PENDING_VERSION, &PENDING(index));

	DBG("Got version for hci%d", index);

	if (!PENDING(index) && UP(index))
		start_adapter(index);
}

static void read_local_features_complete(int index,
				const read_local_features_rp *rp)
{
	if (rp->status)
		return;

	memcpy(FEATURES(index), rp->features, 8);

	if (!PENDING(index))
		return;

	hci_clear_bit(PENDING_FEATURES, &PENDING(index));

	DBG("Got features for hci%d", index);

	if (!PENDING(index) && UP(index))
		start_adapter(index);
}

#define SIZEOF_UUID128 16

static void eir_generate_uuid128(sdp_list_t *list,
					uint8_t *ptr, uint16_t *eir_len)
{
	int i, k, uuid_count = 0;
	uint16_t len = *eir_len;
	uint8_t *uuid128;
	gboolean truncated = FALSE;

	/* Store UUIDs in place, skip 2 bytes to write type and length later */
	uuid128 = ptr + 2;

	for (; list; list = list->next) {
		sdp_record_t *rec = list->data;
		uint8_t *uuid128_data = rec->svclass.value.uuid128.data;

		if (rec->svclass.type != SDP_UUID128)
			continue;

		/* Stop if not enough space to put next UUID128 */
		if ((len + 2 + SIZEOF_UUID128) > EIR_DATA_LENGTH) {
			truncated = TRUE;
			break;
		}

		/* Check for duplicates, EIR data is Little Endian */
		for (i = 0; i < uuid_count; i++) {
			for (k = 0; k < SIZEOF_UUID128; k++) {
				if (uuid128[i * SIZEOF_UUID128 + k] !=
					uuid128_data[SIZEOF_UUID128 - 1 - k])
					break;
			}
			if (k == SIZEOF_UUID128)
				break;
		}

		if (i < uuid_count)
			continue;

		/* EIR data is Little Endian */
		for (k = 0; k < SIZEOF_UUID128; k++)
			uuid128[uuid_count * SIZEOF_UUID128 + k] =
				uuid128_data[SIZEOF_UUID128 - 1 - k];

		len += SIZEOF_UUID128;
		uuid_count++;
	}

	if (uuid_count > 0 || truncated) {
		/* EIR Data length */
		ptr[0] = (uuid_count * SIZEOF_UUID128) + 1;
		/* EIR Data type */
		ptr[1] = truncated ? EIR_UUID128_SOME : EIR_UUID128_ALL;
		len += 2;
		*eir_len = len;
	}
}

static void create_ext_inquiry_response(int index, uint8_t *data)
{
	sdp_list_t *services;
	sdp_list_t *list;
	uint8_t *ptr = data;
	uint16_t eir_len = 0;
	uint16_t uuid16[EIR_DATA_LENGTH / 2];
	int i, uuid_count = 0;
	gboolean truncated = FALSE;
	struct btd_adapter *adapter;
	size_t name_len;

	name_len = strlen(NAME(index));

	if (name_len > 0) {
		/* EIR Data type */
		if (name_len > 48) {
			name_len = 48;
			ptr[1] = EIR_NAME_SHORT;
		} else
			ptr[1] = EIR_NAME_COMPLETE;

		/* EIR Data length */
		ptr[0] = name_len + 1;

		memcpy(ptr + 2, NAME(index), name_len);

		eir_len += (name_len + 2);
		ptr += (name_len + 2);
	}

	if (TX_POWER(index) != 0) {
		*ptr++ = 2;
		*ptr++ = EIR_TX_POWER;
		*ptr++ = (uint8_t) TX_POWER(index);
		eir_len += 3;
	}

	if (DID_VENDOR(index) != 0x0000) {
		uint16_t source = 0x0002;
		*ptr++ = 9;
		*ptr++ = EIR_DEVICE_ID;
		*ptr++ = (source & 0x00ff);
		*ptr++ = (source & 0xff00) >> 8;
		*ptr++ = (DID_VENDOR(index) & 0x00ff);
		*ptr++ = (DID_VENDOR(index) & 0xff00) >> 8;
		*ptr++ = (DID_PRODUCT(index) & 0x00ff);
		*ptr++ = (DID_PRODUCT(index) & 0xff00) >> 8;
		*ptr++ = (DID_VERSION(index) & 0x00ff);
		*ptr++ = (DID_VERSION(index) & 0xff00) >> 8;
		eir_len += 10;
	}

	adapter = manager_find_adapter(&BDADDR(index));
	if (adapter == NULL)
		return;

	services = adapter_get_services(adapter);

	/* Group all UUID16 types */
	for (list = services; list; list = list->next) {
		sdp_record_t *rec = list->data;

		if (rec->svclass.type != SDP_UUID16)
			continue;

		if (rec->svclass.value.uuid16 < 0x1100)
			continue;

		if (rec->svclass.value.uuid16 == PNP_INFO_SVCLASS_ID)
			continue;

		/* Stop if not enough space to put next UUID16 */
		if ((eir_len + 2 + sizeof(uint16_t)) > EIR_DATA_LENGTH) {
			truncated = TRUE;
			break;
		}

		/* Check for duplicates */
		for (i = 0; i < uuid_count; i++)
			if (uuid16[i] == rec->svclass.value.uuid16)
				break;

		if (i < uuid_count)
			continue;

		uuid16[uuid_count++] = rec->svclass.value.uuid16;
		eir_len += sizeof(uint16_t);
	}

	if (uuid_count > 0) {
		/* EIR Data length */
		ptr[0] = (uuid_count * sizeof(uint16_t)) + 1;
		/* EIR Data type */
		ptr[1] = truncated ? EIR_UUID16_SOME : EIR_UUID16_ALL;

		ptr += 2;
		eir_len += 2;

		for (i = 0; i < uuid_count; i++) {
			*ptr++ = (uuid16[i] & 0x00ff);
			*ptr++ = (uuid16[i] & 0xff00) >> 8;
		}
	}

	/* Group all UUID128 types */
	if (eir_len <= EIR_DATA_LENGTH - 2)
		eir_generate_uuid128(services, ptr, &eir_len);
}

static void update_ext_inquiry_response(int index)
{
	write_ext_inquiry_response_cp cp;

	DBG("hci%d", index);

	if (!(FEATURES(index)[6] & LMP_EXT_INQ))
		return;

	if (SSP_MODE(index) == 0)
		return;

	if (CACHE_ENABLE(index))
		return;

	memset(&cp, 0, sizeof(cp));

	create_ext_inquiry_response(index, cp.data);

	if (memcmp(cp.data, EIR(index), sizeof(cp.data)) == 0)
		return;

	memcpy(EIR(index), cp.data, sizeof(cp.data));

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_WRITE_EXT_INQUIRY_RESPONSE,
				WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE, &cp) < 0)
		error("Unable to write EIR data: %s (%d)",
						strerror(errno), errno);
}

static void update_name(int index, const char *name)
{
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(&BDADDR(index));
	if (adapter)
		adapter_update_local_name(adapter, name);

	update_ext_inquiry_response(index);
}

static void read_local_name_complete(int index, read_local_name_rp *rp)
{
	DBG("hci%d status %u", index, rp->status);

	if (rp->status)
		return;

	memcpy(NAME(index), rp->name, 248);

	if (!PENDING(index)) {
		update_name(index, (char *) rp->name);
		return;
	}

	hci_clear_bit(PENDING_NAME, &PENDING(index));

	DBG("Got name for hci%d", index);

	if (!UP(index))
		return;

	/* Even though it shouldn't happen (assuming the kernel behaves
	 * properly) it seems like we might miss the very first
	 * initialization commands that the kernel sends. So check for
	 * it here (since read_local_name is one of the last init
	 * commands) and resend the first ones if we haven't seen
	 * their results yet */

	if (hci_test_bit(PENDING_FEATURES, &PENDING(index)))
		hci_send_cmd(SK(index), OGF_INFO_PARAM,
					OCF_READ_LOCAL_FEATURES, 0, NULL);

	if (hci_test_bit(PENDING_VERSION, &PENDING(index)))
		hci_send_cmd(SK(index), OGF_INFO_PARAM,
					OCF_READ_LOCAL_VERSION, 0, NULL);

	if (!PENDING(index))
		start_adapter(index);
}

static void read_tx_power_complete(int index, void *ptr)
{
	read_inq_response_tx_power_level_rp *rp = ptr;

	DBG("hci%d status %u", index, rp->status);

	if (rp->status)
		return;

	TX_POWER(index) = rp->level;
	update_ext_inquiry_response(index);
}

static void read_simple_pairing_mode_complete(int index, void *ptr)
{
	read_simple_pairing_mode_rp *rp = ptr;
	struct btd_adapter *adapter;

	DBG("hci%d status %u", index, rp->status);

	if (rp->status)
		return;

	SSP_MODE(index) = rp->mode;
	update_ext_inquiry_response(index);

	adapter = manager_find_adapter(&BDADDR(index));
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	adapter_update_ssp_mode(adapter, rp->mode);
}

static void read_local_ext_features_complete(int index,
				const read_local_ext_features_rp *rp)
{
	struct btd_adapter *adapter;

	DBG("hci%d status %u", index, rp->status);

	if (rp->status)
		return;

	adapter = manager_find_adapter(&BDADDR(index));
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	/* Local Extended feature page number is 1 */
	if (rp->page_num != 1)
		return;

	btd_adapter_update_local_ext_features(adapter, rp->features);
}

static void read_bd_addr_complete(int index, read_bd_addr_rp *rp)
{
	DBG("hci%d status %u", index, rp->status);

	if (rp->status)
		return;

	bacpy(&BDADDR(index), &rp->bdaddr);

	if (!PENDING(index))
		return;

	hci_clear_bit(PENDING_BDADDR, &PENDING(index));

	DBG("Got bdaddr for hci%d", index);

	if (!PENDING(index) && UP(index))
		start_adapter(index);
}

static inline void cmd_status(int index, void *ptr)
{
	evt_cmd_status *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);

	if (opcode == cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY))
		start_inquiry(&BDADDR(index), evt->status, FALSE);
}

static void read_scan_complete(int index, uint8_t status, void *ptr)
{
	struct btd_adapter *adapter;
	read_scan_enable_rp *rp = ptr;

	DBG("hci%d status %u", index, status);

	adapter = manager_find_adapter(&BDADDR(index));

	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	adapter_mode_changed(adapter, rp->enable);
}

static int write_class(int index, uint32_t class)
{
	write_class_of_dev_cp cp;

	DBG("hci%d class 0x%06x", index, class);

	memcpy(cp.dev_class, &class, 3);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
					WRITE_CLASS_OF_DEV_CP_SIZE, &cp) < 0)
		return -errno;

	PENDING_COD(index) = class;

	return 0;
}

/* Limited Discoverable bit mask in CoD */
#define LIMITED_BIT			0x002000

static int hciops_set_limited_discoverable(int index, gboolean limited)
{
	int num = (limited ? 2 : 1);
	uint8_t lap[] = { 0x33, 0x8b, 0x9e, 0x00, 0x8b, 0x9e };
	write_current_iac_lap_cp cp;

	DBG("hci%d limited %d", index, limited);

	/* Check if limited bit needs to be set/reset */
	if (limited)
		WANTED_COD(index) |= LIMITED_BIT;
	else
		WANTED_COD(index) &= ~LIMITED_BIT;

	/* If we dont need the toggling, save an unnecessary CoD write */
	if (PENDING_COD(index) || WANTED_COD(index) == CURRENT_COD(index))
		return 0;

	/*
	 * 1: giac
	 * 2: giac + liac
	 */
	memset(&cp, 0, sizeof(cp));
	cp.num_current_iac = num;
	memcpy(&cp.lap, lap, num * 3);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_CURRENT_IAC_LAP,
						(num * 3 + 1), &cp) < 0)
		return -errno;

	return write_class(index, WANTED_COD(index));
}

static void write_class_complete(int index, uint8_t status)
{
	struct btd_adapter *adapter;

	if (status)
		return;

	if (PENDING_COD(index) == 0)
		return;

	CURRENT_COD(index) = PENDING_COD(index);
	PENDING_COD(index) = 0;

	adapter = manager_find_adapter(&BDADDR(index));
	if (adapter)
		btd_adapter_class_changed(adapter, CURRENT_COD(index));

	update_ext_inquiry_response(index);

	if (WANTED_COD(index) == CURRENT_COD(index))
		return;

	if (WANTED_COD(index) & LIMITED_BIT &&
			!(CURRENT_COD(index) & LIMITED_BIT))
		hciops_set_limited_discoverable(index, TRUE);
	else if (!(WANTED_COD(index) & LIMITED_BIT) &&
					(CURRENT_COD(index) & LIMITED_BIT))
		hciops_set_limited_discoverable(index, FALSE);
	else
		write_class(index, WANTED_COD(index));
}

static inline void cmd_complete(int index, void *ptr)
{
	evt_cmd_complete *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);
	uint8_t status = *((uint8_t *) ptr + EVT_CMD_COMPLETE_SIZE);

	switch (opcode) {
	case cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_LOCAL_VERSION):
		ptr += sizeof(evt_cmd_complete);
		read_local_version_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_LOCAL_FEATURES):
		ptr += sizeof(evt_cmd_complete);
		read_local_features_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_LOCAL_EXT_FEATURES):
		ptr += sizeof(evt_cmd_complete);
		read_local_ext_features_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_BD_ADDR):
		ptr += sizeof(evt_cmd_complete);
		read_bd_addr_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_PERIODIC_INQUIRY):
		start_inquiry(&BDADDR(index), status, TRUE);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_EXIT_PERIODIC_INQUIRY):
		inquiry_complete(&BDADDR(index), status, TRUE);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY_CANCEL):
		inquiry_complete(&BDADDR(index), status, FALSE);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_LE_HOST_SUPPORTED):
		write_le_host_complete(&BDADDR(index), status);
		break;
	case cmd_opcode_pack(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE):
		btd_event_le_set_scan_enable_complete(&BDADDR(index), status);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME):
		if (!status)
			hci_send_cmd(SK(index), OGF_HOST_CTL,
						OCF_READ_LOCAL_NAME, 0, 0);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE):
		btd_event_setscan_enable_complete(&BDADDR(index));
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_SCAN_ENABLE):
		ptr += sizeof(evt_cmd_complete);
		read_scan_complete(index, status, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV):
		write_class_complete(index, status);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE):
		if (!status)
			hci_send_cmd(SK(index), OGF_HOST_CTL,
					OCF_READ_SIMPLE_PAIRING_MODE, 0, NULL);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_SIMPLE_PAIRING_MODE):
		ptr += sizeof(evt_cmd_complete);
		read_simple_pairing_mode_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_LOCAL_NAME):
		ptr += sizeof(evt_cmd_complete);
		read_local_name_complete(index, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL,
					OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL):
		ptr += sizeof(evt_cmd_complete);
		read_tx_power_complete(index, ptr);
		break;
	};
}

static inline void remote_name_information(int index, void *ptr)
{
	evt_remote_name_req_complete *evt = ptr;
	char name[MAX_NAME_LENGTH + 1];

	DBG("hci%d status %u", index, evt->status);

	memset(name, 0, sizeof(name));

	if (!evt->status)
		memcpy(name, evt->name, MAX_NAME_LENGTH);

	btd_event_remote_name(&BDADDR(index), &evt->bdaddr, evt->status, name);
}

static inline void remote_version_information(int index, void *ptr)
{
	evt_read_remote_version_complete *evt = ptr;
	bdaddr_t dba;

	DBG("hci%d status %u", index, evt->status);

	if (evt->status)
		return;

	if (get_bdaddr(index, btohs(evt->handle), &dba) < 0)
		return;

	write_version_info(&BDADDR(index), &dba, btohs(evt->manufacturer),
				evt->lmp_ver, btohs(evt->lmp_subver));
}

static inline void inquiry_result(int index, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0] |
						(info->dev_class[1] << 8) |
						(info->dev_class[2] << 16);

		btd_event_inquiry_result(&BDADDR(index), &info->bdaddr, class,
								0, NULL);

		update_lastseen(&BDADDR(index), &info->bdaddr);

		ptr += INQUIRY_INFO_SIZE;
	}
}

static inline void inquiry_result_with_rssi(int index, int plen, void *ptr)
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

			btd_event_inquiry_result(&BDADDR(index), &info->bdaddr,
						class, info->rssi, NULL);

			update_lastseen(&BDADDR(index), &info->bdaddr);

			ptr += INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE;
		}
	} else {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi *info = ptr;
			uint32_t class = info->dev_class[0]
						| (info->dev_class[1] << 8)
						| (info->dev_class[2] << 16);

			btd_event_inquiry_result(&BDADDR(index), &info->bdaddr,
						class, info->rssi, NULL);

			update_lastseen(&BDADDR(index), &info->bdaddr);

			ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
		}
	}
}

static inline void extended_inquiry_result(int index, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		extended_inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0]
					| (info->dev_class[1] << 8)
					| (info->dev_class[2] << 16);

		btd_event_inquiry_result(&BDADDR(index), &info->bdaddr, class,
						info->rssi, info->data);

		update_lastseen(&BDADDR(index), &info->bdaddr);

		ptr += EXTENDED_INQUIRY_INFO_SIZE;
	}
}

static inline void remote_features_information(int index, void *ptr)
{
	evt_read_remote_features_complete *evt = ptr;
	bdaddr_t dba;

	DBG("hci%d status %u", index, evt->status);

	if (evt->status)
		return;

	if (get_bdaddr(index, btohs(evt->handle), &dba) < 0)
		return;

	write_features_info(&BDADDR(index), &dba, evt->features, NULL);
}

static inline void conn_complete(int index, void *ptr)
{
	evt_conn_complete *evt = ptr;
	char filename[PATH_MAX];
	char local_addr[18], peer_addr[18], *str;
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(&BDADDR(index));
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	if (evt->link_type != ACL_LINK)
		return;

	btd_event_conn_complete(&BDADDR(index), evt->status,
					btohs(evt->handle), &evt->bdaddr);

	if (evt->status)
		return;

	update_lastused(&BDADDR(index), &evt->bdaddr);

	/* check if the remote version needs be requested */
	ba2str(&BDADDR(index), local_addr);
	ba2str(&evt->bdaddr, peer_addr);

	create_name(filename, sizeof(filename), STORAGEDIR, local_addr,
							"manufacturers");

	str = textfile_get(filename, peer_addr);
	if (!str)
		btd_adapter_get_remote_version(adapter, btohs(evt->handle),
									TRUE);
	else
		free(str);
}

static inline void le_conn_complete(int index, void *ptr)
{
	evt_le_connection_complete *evt = ptr;
	char filename[PATH_MAX];
	char local_addr[18], peer_addr[18], *str;
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(&BDADDR(index));
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	btd_event_conn_complete(&BDADDR(index), evt->status,
					btohs(evt->handle), &evt->peer_bdaddr);

	if (evt->status)
		return;

	update_lastused(&BDADDR(index), &evt->peer_bdaddr);

	/* check if the remote version needs be requested */
	ba2str(&BDADDR(index), local_addr);
	ba2str(&evt->peer_bdaddr, peer_addr);

	create_name(filename, sizeof(filename), STORAGEDIR, local_addr,
							"manufacturers");

	str = textfile_get(filename, peer_addr);
	if (!str)
		btd_adapter_get_remote_version(adapter, btohs(evt->handle),
									TRUE);
	else
		free(str);
}

static inline void disconn_complete(int index, void *ptr)
{
	evt_disconn_complete *evt = ptr;

	btd_event_disconn_complete(&BDADDR(index), evt->status,
					btohs(evt->handle), evt->reason);
}

static inline void auth_complete(int index, void *ptr)
{
	evt_auth_complete *evt = ptr;
	bdaddr_t dba;

	DBG("hci%d status %u", index, evt->status);

	if (get_bdaddr(index, btohs(evt->handle), &dba) < 0)
		return;

	btd_event_bonding_process_complete(&BDADDR(index), &dba, evt->status);
}

static inline void simple_pairing_complete(int index, void *ptr)
{
	evt_simple_pairing_complete *evt = ptr;

	DBG("hci%d status %u", index, evt->status);

	btd_event_simple_pairing_complete(&BDADDR(index), &evt->bdaddr,
								evt->status);
}

static inline void conn_request(int index, void *ptr)
{
	evt_conn_request *evt = ptr;
	uint32_t class = evt->dev_class[0] | (evt->dev_class[1] << 8)
				| (evt->dev_class[2] << 16);

	btd_event_remote_class(&BDADDR(index), &evt->bdaddr, class);
}

static inline void le_advertising_report(int index, evt_le_meta_event *meta)
{
	le_advertising_info *info;
	uint8_t num, i;

	num = meta->data[0];
	info = (le_advertising_info *) (meta->data + 1);

	for (i = 0; i < num; i++) {
		btd_event_advertising_report(&BDADDR(index), info);
		info = (le_advertising_info *) (info->data + info->length + 1);
	}
}

static inline void le_metaevent(int index, void *ptr)
{
	evt_le_meta_event *meta = ptr;

	DBG("hci%d LE Meta Event %u", index, meta->subevent);

	switch (meta->subevent) {
	case EVT_LE_ADVERTISING_REPORT:
		le_advertising_report(index, meta);
		break;

	case EVT_LE_CONN_COMPLETE:
		le_conn_complete(index, meta->data);
		break;
	}
}

static void stop_hci_dev(int index)
{
	GIOChannel *chan = CHANNEL(index);

	if (!chan)
		return;

	info("Stopping hci%d event socket", index);

	g_source_remove(WATCH_ID(index));
	g_io_channel_unref(CHANNEL(index));
	hci_close_dev(SK(index));
	init_dev_info(index, -1);
}

static gboolean io_security_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	int type, index = GPOINTER_TO_INT(data);
	struct hci_dev_info di;
	size_t len;
	hci_event_hdr *eh;
	GIOError err;
	evt_cmd_status *evt;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		stop_hci_dev(index);
		return FALSE;
	}

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		stop_hci_dev(index);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	ptr += HCI_EVENT_HDR_SIZE;

	memset(&di, 0, sizeof(di));
	if (hci_devinfo(index, &di) == 0) {
		bacpy(&BDADDR(index), &di.bdaddr);

		if (ignore_device(&di))
			return TRUE;
	}

	switch (eh->evt) {
	case EVT_CMD_STATUS:
		cmd_status(index, ptr);
		break;

	case EVT_CMD_COMPLETE:
		cmd_complete(index, ptr);
		break;

	case EVT_REMOTE_NAME_REQ_COMPLETE:
		remote_name_information(index, ptr);
		break;

	case EVT_READ_REMOTE_VERSION_COMPLETE:
		remote_version_information(index, ptr);
		break;

	case EVT_READ_REMOTE_FEATURES_COMPLETE:
		remote_features_information(index, ptr);
		break;

	case EVT_REMOTE_HOST_FEATURES_NOTIFY:
		remote_features_notify(index, ptr);
		break;

	case EVT_INQUIRY_COMPLETE:
		evt = (evt_cmd_status *) ptr;
		inquiry_complete(&BDADDR(index), evt->status, FALSE);
		break;

	case EVT_INQUIRY_RESULT:
		inquiry_result(index, eh->plen, ptr);
		break;

	case EVT_INQUIRY_RESULT_WITH_RSSI:
		inquiry_result_with_rssi(index, eh->plen, ptr);
		break;

	case EVT_EXTENDED_INQUIRY_RESULT:
		extended_inquiry_result(index, eh->plen, ptr);
		break;

	case EVT_CONN_COMPLETE:
		conn_complete(index, ptr);
		break;

	case EVT_DISCONN_COMPLETE:
		disconn_complete(index, ptr);
		break;

	case EVT_AUTH_COMPLETE:
		auth_complete(index, ptr);
		break;

	case EVT_SIMPLE_PAIRING_COMPLETE:
		simple_pairing_complete(index, ptr);
		break;

	case EVT_CONN_REQUEST:
		conn_request(index, ptr);
		break;
	case EVT_LE_META_EVENT:
		le_metaevent(index, ptr);
		break;
	case EVT_PIN_CODE_REQ:
		pin_code_request(index, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_REQ:
		link_key_request(index, (bdaddr_t *) ptr);
		break;

	case EVT_LINK_KEY_NOTIFY:
		link_key_notify(index, ptr);
		break;

	case EVT_RETURN_LINK_KEYS:
		return_link_keys(index, ptr);
		break;

	case EVT_IO_CAPABILITY_REQUEST:
		io_capa_request(index, ptr);
		break;

	case EVT_IO_CAPABILITY_RESPONSE:
		io_capa_response(index, ptr);
		break;

	case EVT_USER_CONFIRM_REQUEST:
		user_confirm_request(index, ptr);
		break;

	case EVT_USER_PASSKEY_REQUEST:
		user_passkey_request(index, ptr);
		break;

	case EVT_USER_PASSKEY_NOTIFY:
		user_passkey_notify(index, ptr);
		break;

	case EVT_REMOTE_OOB_DATA_REQUEST:
		remote_oob_data_request(index, ptr);
		break;
	}

	return TRUE;
}

static void start_hci_dev(int index)
{
	GIOChannel *chan = CHANNEL(index);
	GIOCondition cond;
	struct hci_filter flt;

	if (chan)
		return;

	info("Listening for HCI events on hci%d", index);

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_CMD_STATUS, &flt);
	hci_filter_set_event(EVT_CMD_COMPLETE, &flt);
	hci_filter_set_event(EVT_PIN_CODE_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_REQ, &flt);
	hci_filter_set_event(EVT_LINK_KEY_NOTIFY, &flt);
	hci_filter_set_event(EVT_RETURN_LINK_KEYS, &flt);
	hci_filter_set_event(EVT_IO_CAPABILITY_REQUEST, &flt);
	hci_filter_set_event(EVT_IO_CAPABILITY_RESPONSE, &flt);
	hci_filter_set_event(EVT_USER_CONFIRM_REQUEST, &flt);
	hci_filter_set_event(EVT_USER_PASSKEY_REQUEST, &flt);
	hci_filter_set_event(EVT_REMOTE_OOB_DATA_REQUEST, &flt);
	hci_filter_set_event(EVT_USER_PASSKEY_NOTIFY, &flt);
	hci_filter_set_event(EVT_KEYPRESS_NOTIFY, &flt);
	hci_filter_set_event(EVT_SIMPLE_PAIRING_COMPLETE, &flt);
	hci_filter_set_event(EVT_AUTH_COMPLETE, &flt);
	hci_filter_set_event(EVT_REMOTE_NAME_REQ_COMPLETE, &flt);
	hci_filter_set_event(EVT_READ_REMOTE_VERSION_COMPLETE, &flt);
	hci_filter_set_event(EVT_READ_REMOTE_FEATURES_COMPLETE, &flt);
	hci_filter_set_event(EVT_REMOTE_HOST_FEATURES_NOTIFY, &flt);
	hci_filter_set_event(EVT_INQUIRY_COMPLETE, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT_WITH_RSSI, &flt);
	hci_filter_set_event(EVT_EXTENDED_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_CONN_REQUEST, &flt);
	hci_filter_set_event(EVT_CONN_COMPLETE, &flt);
	hci_filter_set_event(EVT_DISCONN_COMPLETE, &flt);
	hci_filter_set_event(EVT_LE_META_EVENT, &flt);
	if (setsockopt(SK(index), SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		error("Can't set filter on hci%d: %s (%d)",
						index, strerror(errno), errno);
		return;
	}

	chan = g_io_channel_unix_new(SK(index));
	cond = G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR;
	WATCH_ID(index) = g_io_add_watch_full(chan, G_PRIORITY_LOW, cond,
						io_security_event,
						GINT_TO_POINTER(index), NULL);
	CHANNEL(index) = chan;
	PIN_LENGTH(index) = -1;

}

/* End of HCI event callbacks */

static gboolean child_exit(GIOChannel *io, GIOCondition cond, void *user_data)
{
	int status, fd = g_io_channel_unix_get_fd(io);
	pid_t child_pid;

	if (read(fd, &child_pid, sizeof(child_pid)) != sizeof(child_pid)) {
		error("child_exit: unable to read child pid from pipe");
		return TRUE;
	}

	if (waitpid(child_pid, &status, 0) != child_pid)
		error("waitpid(%d) failed", child_pid);
	else
		DBG("child %d exited", child_pid);

	return TRUE;
}

static void at_child_exit(void)
{
	pid_t pid = getpid();

	if (write(child_pipe[1], &pid, sizeof(pid)) != sizeof(pid))
		error("unable to write to child pipe");
}

static void device_devup_setup(int index)
{
	struct hci_dev_info di;
	read_stored_link_key_cp cp;

	DBG("hci%d", index);

	if (hci_devinfo(index, &di) < 0)
		return;

	if (ignore_device(&di))
		return;

	bacpy(&BDADDR(index), &di.bdaddr);
	memcpy(FEATURES(index), di.features, 8);

	/* Set page timeout */
	if ((main_opts.flags & (1 << HCID_SET_PAGETO))) {
		write_page_timeout_cp cp;

		cp.timeout = htobs(main_opts.pageto);
		hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT,
					WRITE_PAGE_TIMEOUT_CP_SIZE, &cp);
	}

	bacpy(&cp.bdaddr, BDADDR_ANY);
	cp.read_all = 1;
	hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_READ_STORED_LINK_KEY,
			READ_STORED_LINK_KEY_CP_SIZE, (void *) &cp);

	if (!PENDING(index))
		start_adapter(index);
}

static void init_pending(int index)
{
	hci_set_bit(PENDING_BDADDR, &PENDING(index));
	hci_set_bit(PENDING_VERSION, &PENDING(index));
	hci_set_bit(PENDING_FEATURES, &PENDING(index));
	hci_set_bit(PENDING_NAME, &PENDING(index));
}

static void init_device(int index)
{
	struct hci_dev_req dr;
	int dd;
	pid_t pid;

	DBG("hci%d", index);

	dd = hci_open_dev(index);
	if (dd < 0) {
		error("Unable to open hci%d: %s (%d)", index,
						strerror(errno), errno);
		return;
	}

	if (index > max_dev) {
		max_dev = index;
		devs = g_realloc(devs, sizeof(devs[0]) * (max_dev + 1));
	}

	init_dev_info(index, dd);
	init_pending(index);
	start_hci_dev(index);

	/* Do initialization in the separate process */
	pid = fork();
	switch (pid) {
		case 0:
			atexit(at_child_exit);
			break;
		case -1:
			error("Fork failed. Can't init device hci%d: %s (%d)",
					index, strerror(errno), errno);
		default:
			DBG("child %d forked", pid);
			return;
	}

	memset(&dr, 0, sizeof(dr));
	dr.dev_id = index;

	/* Set link mode */
	dr.dev_opt = main_opts.link_mode;
	if (ioctl(dd, HCISETLINKMODE, (unsigned long) &dr) < 0)
		error("Can't set link mode on hci%d: %s (%d)",
						index, strerror(errno), errno);

	/* Start HCI device */
	if (ioctl(dd, HCIDEVUP, index) < 0 && errno != EALREADY) {
		error("Can't init device hci%d: %s (%d)",
					index, strerror(errno), errno);
		goto fail;
	}

	hci_close_dev(dd);
	exit(0);

fail:
	hci_close_dev(dd);
	exit(1);
}

static void device_devreg_setup(int index)
{
	struct hci_dev_info di;
	gboolean devup;

	DBG("hci%d", index);

	init_device(index);

	memset(&di, 0, sizeof(di));

	if (hci_devinfo(index, &di) < 0)
		return;

	devup = hci_test_bit(HCI_UP, &di.flags);

	if (!ignore_device(&di))
		manager_register_adapter(index, devup);
}

static void device_event(int event, int index)
{
	switch (event) {
	case HCI_DEV_REG:
		info("HCI dev %d registered", index);
		device_devreg_setup(index);
		break;

	case HCI_DEV_UNREG:
		info("HCI dev %d unregistered", index);
		stop_hci_dev(index);
		manager_unregister_adapter(index);
		break;

	case HCI_DEV_UP:
		info("HCI dev %d up", index);
		UP(index) = TRUE;
		device_devup_setup(index);
		break;

	case HCI_DEV_DOWN:
		info("HCI dev %d down", index);
		UP(index) = FALSE;
		PENDING_COD(index) = 0;
		CACHE_ENABLE(index) = TRUE;
		if (!PENDING(index)) {
			manager_stop_adapter(index);
			init_pending(index);
		}
		break;
	}
}

static gboolean init_known_adapters(gpointer user_data)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, err, ctl = GPOINTER_TO_INT(user_data);
	size_t req_size;

	DBG("");

	req_size = HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t);

	dl = g_try_malloc0(req_size);
	if (!dl) {
		error("Can't allocate devlist buffer");
		return FALSE;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, dl) < 0) {
		err = -errno;
		error("Can't get device list: %s (%d)", strerror(-err), -err);
		g_free(dl);
		return FALSE;
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		device_event(HCI_DEV_REG, dr->dev_id);

		if (!hci_test_bit(HCI_UP, &dr->dev_opt))
			continue;

		PENDING(dr->dev_id) = 0;
		hci_set_bit(PENDING_VERSION, &PENDING(dr->dev_id));
		hci_send_cmd(SK(dr->dev_id), OGF_INFO_PARAM,
					OCF_READ_LOCAL_VERSION, 0, NULL);
		device_event(HCI_DEV_UP, dr->dev_id);
	}

	g_free(dl);

	return FALSE;
}

static gboolean io_stack_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	evt_si_device *sd;
	hci_event_hdr *eh;
	int type;
	size_t len;
	GIOError err;

	ptr = buf;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		error("Read from control socket failed: %s (%d)",
						strerror(errno), errno);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	if (eh->evt != EVT_STACK_INTERNAL)
		return TRUE;

	ptr += HCI_EVENT_HDR_SIZE;

	si = (evt_stack_internal *) ptr;
	switch (si->type) {
	case EVT_SI_DEVICE:
		sd = (void *) &si->data;
		device_event(sd->event, sd->dev_id);
		break;
	}

	return TRUE;
}

static int hciops_setup(void)
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	GIOChannel *ctl_io, *child_io;
	int sock, err;

	DBG("");

	if (child_pipe[0] != -1)
		return -EALREADY;

	if (pipe(child_pipe) < 0) {
		err = -errno;
		error("pipe(): %s (%d)", strerror(-err), -err);
		return err;
	}

	child_io = g_io_channel_unix_new(child_pipe[0]);
	g_io_channel_set_close_on_unref(child_io, TRUE);
	child_io_id = g_io_add_watch(child_io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				child_exit, NULL);
	g_io_channel_unref(child_io);

	/* Create and bind HCI socket */
	sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sock < 0) {
		err = -errno;
		error("Can't open HCI socket: %s (%d)", strerror(-err),
								-err);
		return err;
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		err = -errno;
		error("Can't set filter: %s (%d)", strerror(-err), -err);
		return err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		error("Can't bind HCI socket: %s (%d)", strerror(-err), -err);
		return err;
	}

	ctl_io = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(ctl_io, TRUE);

	ctl_io_id = g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	g_io_channel_unref(ctl_io);

	g_idle_add(init_known_adapters, GINT_TO_POINTER(sock));

	return 0;
}

static void hciops_cleanup(void)
{
	int i;

	DBG("");

	for (i = 0; i <= max_dev; i++) {
		if (SK(i) >= 0)
			hci_close_dev(SK(i));
	}

	g_free(devs);
	devs = NULL;
	max_dev = -1;

	if (child_io_id) {
		g_source_remove(child_io_id);
		child_io_id = 0;
	}

	if (ctl_io_id) {
		g_source_remove(ctl_io_id);
		ctl_io_id = 0;
	}

	if (child_pipe[0] >= 0) {
		close(child_pipe[0]);
		child_pipe[0] = -1;
	}

	if (child_pipe[1] >= 0) {
		close(child_pipe[1]);
		child_pipe[1] = -1;
	}
}

static int hciops_start(int index)
{
	int err;

	DBG("hci%d", index);

	if (ioctl(SK(index), HCIDEVUP, index) == 0)
		return 0;

	if (errno == EALREADY)
		return 0;

	err = -errno;
	error("Can't init device hci%d: %s (%d)",
					index, strerror(-err), -err);

	return err;
}

static int hciops_stop(int index)
{
	int err = 0;

	DBG("hci%d", index);

	if (ioctl(SK(index), HCIDEVDOWN, index) == 0)
		goto done; /* on success */

	if (errno != EALREADY) {
		err = -errno;
		error("Can't stop device hci%d: %s (%d)",
				index, strerror(-err), -err);
	}

done:
	return err;
}

static int hciops_set_powered(int index, gboolean powered)
{
	uint8_t mode = SCAN_DISABLED;

	DBG("hci%d powered %d", index, powered);

	if (powered)
		return hciops_start(index);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
					OCF_WRITE_SCAN_ENABLE, 1, &mode) < 0)
		return -errno;

	return hciops_stop(index);
}

static int hciops_connectable(int index)
{
	uint8_t mode = SCAN_PAGE;

	DBG("hci%d", index);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
					OCF_WRITE_SCAN_ENABLE, 1, &mode) < 0)
		return -errno;

	return 0;
}

static int hciops_discoverable(int index)
{
	uint8_t mode = (SCAN_PAGE | SCAN_INQUIRY);

	DBG("hci%d", index);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
								1, &mode) < 0)
		return -errno;

	return 0;
}

static int hciops_set_dev_class(int index, uint8_t major, uint8_t minor)
{
	int err;

	/* Update only the major and minor class bits keeping remaining bits
	 * intact*/
	WANTED_COD(index) &= 0xffe000;
	WANTED_COD(index) |= ((major & 0x1f) << 8) | minor;

	if (WANTED_COD(index) == CURRENT_COD(index) ||
			CACHE_ENABLE(index) || PENDING_COD(index))
		return 0;

	DBG("Changing Major/Minor class to 0x%06x", WANTED_COD(index));

	err = write_class(index, WANTED_COD(index));
	if (err < 0)
		error("Adapter class update failed: %s (%d)",
						strerror(-err), -err);

	return err;
}

static int hciops_start_inquiry(int index, uint8_t length, gboolean periodic)
{
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int err;

	DBG("hci%d length %u periodic %d", index, length, periodic);

	if (periodic) {
		periodic_inquiry_cp cp;

		memset(&cp, 0, sizeof(cp));
		memcpy(&cp.lap, lap, 3);
		cp.max_period = htobs(24);
		cp.min_period = htobs(16);
		cp.length  = length;
		cp.num_rsp = 0x00;

		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
						OCF_PERIODIC_INQUIRY,
						PERIODIC_INQUIRY_CP_SIZE, &cp);
	} else {
		inquiry_cp inq_cp;

		memset(&inq_cp, 0, sizeof(inq_cp));
		memcpy(&inq_cp.lap, lap, 3);
		inq_cp.length = length;
		inq_cp.num_rsp = 0x00;

		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_INQUIRY, INQUIRY_CP_SIZE, &inq_cp);
	}

	if (err < 0)
		err = -errno;

	return err;
}

static int hciops_stop_inquiry(int index)
{
	struct hci_dev_info di;
	int err;

	DBG("hci%d", index);

	if (hci_devinfo(index, &di) < 0)
		return -errno;

	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
						OCF_INQUIRY_CANCEL, 0, 0);
	else
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_EXIT_PERIODIC_INQUIRY, 0, 0);
	if (err < 0)
		err = -errno;

	return err;
}

static int le_set_scan_enable(int index, uint8_t enable)
{
	le_set_scan_enable_cp cp;

	DBG("hci%d enable %u", index, enable);

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;
	cp.filter_dup = 0;

	if (hci_send_cmd(SK(index), OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
				LE_SET_SCAN_ENABLE_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_start_scanning(int index)
{
	le_set_scan_parameters_cp cp;

	DBG("hci%d", index);

	memset(&cp, 0, sizeof(cp));
	cp.type = 0x01;			/* Active scanning */
	cp.interval = htobs(0x0010);
	cp.window = htobs(0x0010);
	cp.own_bdaddr_type = 0;		/* Public address */
	cp.filter = 0;			/* Accept all adv packets */

	if (hci_send_cmd(SK(index), OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS,
				LE_SET_SCAN_PARAMETERS_CP_SIZE, &cp) < 0)
		return -errno;

	return le_set_scan_enable(index, 1);
}

static int hciops_stop_scanning(int index)
{
	DBG("hci%d", index);

	return le_set_scan_enable(index, 0);
}

static int hciops_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cp cp;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pscan_rep_mode = 0x02;

	if (hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_REMOTE_NAME_REQ,
					REMOTE_NAME_REQ_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_set_name(int index, const char *name)
{
	change_local_name_cp cp;

	DBG("hci%d, name %s", index, name);

	memset(&cp, 0, sizeof(cp));
	strncpy((char *) cp.name, name, sizeof(cp.name));

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
				CHANGE_LOCAL_NAME_CP_SIZE, &cp) < 0)
		return -errno;

	memcpy(NAME(index), cp.name, 248);
	update_ext_inquiry_response(index);

	return 0;
}

static int hciops_cancel_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cancel_cp cp;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	if (hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_REMOTE_NAME_REQ_CANCEL,
				REMOTE_NAME_REQ_CANCEL_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_fast_connectable(int index, gboolean enable)
{
	write_page_activity_cp cp;
	uint8_t type;

	DBG("hci%d enable %d", index, enable);

	if (enable) {
		type = PAGE_SCAN_TYPE_INTERLACED;
		cp.interval = 0x0024;	/* 22.5 msec page scan interval */
	} else {
		type = PAGE_SCAN_TYPE_STANDARD;	/* default */
		cp.interval = 0x0800;	/* default 1.28 sec page scan */
	}

	cp.window = 0x0012;	/* default 11.25 msec page scan window */

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_PAGE_ACTIVITY,
					WRITE_PAGE_ACTIVITY_CP_SIZE, &cp) < 0)
		return -errno;
	else if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_WRITE_PAGE_SCAN_TYPE, 1, &type) < 0)
		return -errno;

	return 0;
}

static int hciops_read_clock(int index, int handle, int which, int timeout,
					uint32_t *clock, uint16_t *accuracy)
{
	DBG("hci%d handle %d which %d timeout %d", index, handle, which,
								timeout);

	if (hci_read_clock(SK(index), handle, which, clock, accuracy,
								timeout) < 0)
		return -errno;

	return 0;
}

static int hciops_conn_handle(int index, const bdaddr_t *bdaddr, int *handle)
{
	int err;
	struct hci_conn_info_req *cr;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	bacpy(&cr->bdaddr, bdaddr);
	cr->type = ACL_LINK;

	if (ioctl(SK(index), HCIGETCONNINFO, (unsigned long) cr) < 0) {
		err = -errno;
		goto fail;
	}

	err = 0;
	*handle = htobs(cr->conn_info->handle);

fail:
	g_free(cr);
	return err;
}

static int hciops_read_bdaddr(int index, bdaddr_t *bdaddr)
{
	DBG("hci%d", index);
	bacpy(bdaddr, &BDADDR(index));
	return 0;
}

static int hciops_block_device(int index, bdaddr_t *bdaddr)
{
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	if (ioctl(SK(index), HCIBLOCKADDR, bdaddr) < 0)
		return -errno;

	return 0;
}

static int hciops_unblock_device(int index, bdaddr_t *bdaddr)
{
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	if (ioctl(SK(index), HCIUNBLOCKADDR, bdaddr) < 0)
		return -errno;

	return 0;
}

static int hciops_get_conn_list(int index, GSList **conns)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int err, i;

	DBG("hci%d", index);

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = index;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(SK(index), HCIGETCONNLIST, cl) < 0) {
		err = -errno;
		goto fail;
	}

	err = 0;
	*conns = NULL;

	for (i = 0; i < cl->conn_num; i++, ci++)
		*conns = g_slist_append(*conns, g_memdup(ci, sizeof(*ci)));

fail:
	g_free(cl);
	return err;
}

static int hciops_read_local_version(int index, struct hci_version *ver)
{
	DBG("hci%d", index);
	memcpy(ver, &VER(index), sizeof(*ver));
	return 0;
}

static int hciops_read_local_features(int index, uint8_t *features)
{
	DBG("hci%d", index);
	memcpy(features, FEATURES(index), 8);
	return  0;
}

static int hciops_read_local_ext_features(int index)
{
	uint8_t page_num = 1;

	DBG("hci%d", index);

	if (hci_send_cmd(SK(index), OGF_INFO_PARAM,
				OCF_READ_LOCAL_EXT_FEATURES, 1, &page_num) < 0)
		return -errno;

	return 0;
}

static int hciops_disconnect(int index, uint16_t handle)
{
	disconnect_cp cp;

	DBG("hci%d handle %u", index, handle);

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);
	cp.reason = HCI_OE_USER_ENDED_CONNECTION;

	if (hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_DISCONNECT,
						DISCONNECT_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_remove_bonding(int index, bdaddr_t *bdaddr)
{
	delete_stored_link_key_cp cp;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	/* Delete the link key from the Bluetooth chip */
	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_DELETE_STORED_LINK_KEY,
				DELETE_STORED_LINK_KEY_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_request_authentication(int index, uint16_t handle)
{
	auth_requested_cp cp;

	DBG("hci%d handle %u", index, handle);

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	if (hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_AUTH_REQUESTED,
					AUTH_REQUESTED_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin)
{
	char addr[18];
	int err;

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	if (pin) {
		pin_code_reply_cp pr;
		size_t len = strlen(pin);

		PIN_LENGTH(index) = len;

		memset(&pr, 0, sizeof(pr));
		bacpy(&pr.bdaddr, bdaddr);
		memcpy(pr.pin_code, pin, len);
		pr.pin_len = len;
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
						OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
	} else
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, bdaddr);

	if (err < 0)
		err = -errno;

	return err;
}

static int hciops_confirm_reply(int index, bdaddr_t *bdaddr, gboolean success)
{
	user_confirm_reply_cp cp;
	char addr[18];
	int err;

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s success %d", index, addr, success);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	if (success)
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_USER_CONFIRM_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);
	else
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_USER_CONFIRM_NEG_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);

	if (err < 0)
		err = -errno;

	return err;
}

static int hciops_passkey_reply(int index, bdaddr_t *bdaddr, uint32_t passkey)
{
	char addr[18];
	int err;

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	if (passkey != INVALID_PASSKEY) {
		user_passkey_reply_cp cp;

		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, bdaddr);
		cp.passkey = passkey;

		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_USER_PASSKEY_REPLY,
					USER_PASSKEY_REPLY_CP_SIZE, &cp);
	} else
		err = hci_send_cmd(SK(index), OGF_LINK_CTL,
					OCF_USER_PASSKEY_NEG_REPLY, 6, bdaddr);

	if (err < 0)
		err = -errno;

	return err;
}

static int hciops_get_auth_info(int index, bdaddr_t *bdaddr, uint8_t *auth)
{
	struct hci_auth_info_req req;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d dba %s", index, addr);

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, bdaddr);

	if (ioctl(SK(index), HCIGETAUTHINFO, (unsigned long) &req) < 0)
		return -errno;

	if (auth)
		*auth = req.type;

	return 0;
}

static int hciops_read_scan_enable(int index)
{
	DBG("hci%d", index);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_READ_SCAN_ENABLE,
								0, NULL) < 0)
		return -errno;

	return 0;
}

static int hciops_write_le_host(int index, uint8_t le, uint8_t simul)
{
	write_le_host_supported_cp cp;

	DBG("hci%d le %u simul %u", index, le, simul);

	memset(&cp, 0, sizeof(cp));
	cp.le = le;
	cp.simul = simul;

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_WRITE_LE_HOST_SUPPORTED,
				WRITE_LE_HOST_SUPPORTED_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

struct remote_version_req {
	int index;
	uint16_t handle;
};

static gboolean get_remote_version(gpointer user_data)
{
	struct remote_version_req *req = user_data;
	read_remote_version_cp cp;

	DBG("hci%d handle %u", req->index, req->handle);

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(req->handle);

	hci_send_cmd(SK(req->index), OGF_LINK_CTL, OCF_READ_REMOTE_VERSION,
					READ_REMOTE_VERSION_CP_SIZE, &cp);

	return FALSE;
}

static int hciops_get_remote_version(int index, uint16_t handle,
							gboolean delayed)
{
	struct remote_version_req *req;

	DBG("hci%d handle %u delayed %d", index, handle, delayed);

	req = g_new0(struct remote_version_req, 1);
	req->handle = handle;
	req->index = index;

	if (!delayed) {
		get_remote_version(req);
		g_free(req);
		return 0;
	}

	g_timeout_add_seconds_full(G_PRIORITY_DEFAULT, 1, get_remote_version,
								req, g_free);

	return 0;
}

static int set_service_classes(int index, uint8_t value)
{
	int err;

	/* Update only the service class, keep the limited bit,
	 * major/minor class bits intact */
	WANTED_COD(index) &= 0x00ffff;
	WANTED_COD(index) |= (value << 16);

	/* If the cache is enabled or an existing CoD write is in progress
	 * just bail out */
	if (CACHE_ENABLE(index) || PENDING_COD(index))
		return 0;

	/* If we already have the CoD we want, update EIR and return */
	if (CURRENT_COD(index) == WANTED_COD(index)) {
		update_ext_inquiry_response(index);
		return 0;
	}

	DBG("Changing service classes to 0x%06x", WANTED_COD(index));

	err = write_class(index, WANTED_COD(index));
	if (err < 0)
		error("Adapter class update failed: %s (%d)",
						strerror(-err), -err);

	return err;
}

static int hciops_services_updated(int index)
{
	struct btd_adapter *adapter;
	sdp_list_t *list;
	uint8_t val = 0;

	DBG("hci%d", index);

	adapter = manager_find_adapter(&BDADDR(index));
	if (adapter == NULL)
		return -ENODEV;

	for (list = adapter_get_services(adapter); list; list = list->next) {
		sdp_record_t *rec = list->data;

		if (rec->svclass.type != SDP_UUID16)
			continue;

		switch (rec->svclass.value.uuid16) {
		case DIALUP_NET_SVCLASS_ID:
		case CIP_SVCLASS_ID:
			val |= 0x42;	/* Telephony & Networking */
			break;
		case IRMC_SYNC_SVCLASS_ID:
		case OBEX_OBJPUSH_SVCLASS_ID:
		case OBEX_FILETRANS_SVCLASS_ID:
		case IRMC_SYNC_CMD_SVCLASS_ID:
		case PBAP_PSE_SVCLASS_ID:
			val |= 0x10;	/* Object Transfer */
			break;
		case HEADSET_SVCLASS_ID:
		case HANDSFREE_SVCLASS_ID:
			val |= 0x20;	/* Audio */
			break;
		case CORDLESS_TELEPHONY_SVCLASS_ID:
		case INTERCOM_SVCLASS_ID:
		case FAX_SVCLASS_ID:
		case SAP_SVCLASS_ID:
		/*
		 * Setting the telephony bit for the handsfree audio gateway
		 * role is not required by the HFP specification, but the
		 * Nokia 616 carkit is just plain broken! It will refuse
		 * pairing without this bit set.
		 */
		case HANDSFREE_AGW_SVCLASS_ID:
			val |= 0x40;	/* Telephony */
			break;
		case AUDIO_SOURCE_SVCLASS_ID:
		case VIDEO_SOURCE_SVCLASS_ID:
			val |= 0x08;	/* Capturing */
			break;
		case AUDIO_SINK_SVCLASS_ID:
		case VIDEO_SINK_SVCLASS_ID:
			val |= 0x04;	/* Rendering */
			break;
		case PANU_SVCLASS_ID:
		case NAP_SVCLASS_ID:
		case GN_SVCLASS_ID:
			val |= 0x02;	/* Networking */
			break;
		}
	}

	return set_service_classes(index, val);
}

static int hciops_disable_cod_cache(int index)
{
	DBG("hci%d cache_enable %d", index, CACHE_ENABLE(index));

	if (!CACHE_ENABLE(index))
		return 0;

	DBG("hci%d current_cod 0x%06x wanted_cod 0x%06x", index,
					CURRENT_COD(index), WANTED_COD(index));

	/* Disable and flush svc cache. All successive service class
	 * updates * will be written to the device */
	CACHE_ENABLE(index) = FALSE;

	if (CURRENT_COD(index) == WANTED_COD(index)) {
		update_ext_inquiry_response(index);
		return 0;
	}

	return write_class(index, WANTED_COD(index));
}

static struct btd_adapter_ops hci_ops = {
	.setup = hciops_setup,
	.cleanup = hciops_cleanup,
	.start = hciops_start,
	.stop = hciops_stop,
	.set_powered = hciops_set_powered,
	.set_connectable = hciops_connectable,
	.set_discoverable = hciops_discoverable,
	.set_limited_discoverable = hciops_set_limited_discoverable,
	.start_inquiry = hciops_start_inquiry,
	.stop_inquiry = hciops_stop_inquiry,
	.start_scanning = hciops_start_scanning,
	.stop_scanning = hciops_stop_scanning,
	.resolve_name = hciops_resolve_name,
	.cancel_resolve_name = hciops_cancel_resolve_name,
	.set_name = hciops_set_name,
	.set_dev_class = hciops_set_dev_class,
	.set_fast_connectable = hciops_fast_connectable,
	.read_clock = hciops_read_clock,
	.get_conn_handle = hciops_conn_handle,
	.read_bdaddr = hciops_read_bdaddr,
	.block_device = hciops_block_device,
	.unblock_device = hciops_unblock_device,
	.get_conn_list = hciops_get_conn_list,
	.read_local_version = hciops_read_local_version,
	.read_local_features = hciops_read_local_features,
	.read_local_ext_features = hciops_read_local_ext_features,
	.disconnect = hciops_disconnect,
	.remove_bonding = hciops_remove_bonding,
	.request_authentication = hciops_request_authentication,
	.pincode_reply = hciops_pincode_reply,
	.confirm_reply = hciops_confirm_reply,
	.passkey_reply = hciops_passkey_reply,
	.get_auth_info = hciops_get_auth_info,
	.read_scan_enable = hciops_read_scan_enable,
	.write_le_host = hciops_write_le_host,
	.get_remote_version = hciops_get_remote_version,
	.encrypt_link = hciops_encrypt_link,
	.set_did = hciops_set_did,
	.services_updated = hciops_services_updated,
	.disable_cod_cache = hciops_disable_cod_cache,
};

static int hciops_init(void)
{
	DBG("");
	return btd_register_adapter_ops(&hci_ops, FALSE);
}

static void hciops_exit(void)
{
	DBG("");
	btd_adapter_cleanup_ops(&hci_ops);
}

BLUETOOTH_PLUGIN_DEFINE(hciops, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, hciops_init, hciops_exit)
