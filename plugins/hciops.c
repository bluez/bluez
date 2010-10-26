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

#define HCI_REQ_TIMEOUT         5000

static int child_pipe[2] = { -1, -1 };

static guint child_io_id = 0;
static guint ctl_io_id = 0;

#define SK(index) devs[(index)].sk

static int max_dev = -1;
static struct dev_info {
	int sk;
} *devs = NULL;

static void init_dev_info(int index, int sk)
{
	memset(&devs[index], 0, sizeof(struct dev_info));
	SK(index) = sk;
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

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	cr->type = ACL_LINK;
	bacpy(&cr->bdaddr, dst);

	err = ioctl(SK(index), HCIGETCONNINFO, cr);
	link_mode = cr->conn_info->link_mode;
	handle = cr->conn_info->handle;
	g_free(cr);

	if (err < 0)
		return -errno;

	if (link_mode & HCI_LM_ENCRYPT)
		return -EALREADY;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	if (hci_send_cmd(SK(index), OGF_LINK_CTL, OCF_AUTH_REQUESTED,
				AUTH_REQUESTED_CP_SIZE, &cp) < 0)
		return -errno;

	dd = dup(SK(index));
	if (dd < 0)
		return -errno;

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
		close(dd);
		return -err;
	}

	io = g_io_channel_unix_new(dup(SK(index)));
	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL | G_IO_IN,
			hci_event_watch, cmd, g_free);
	g_io_channel_unref(io);

	return 0;
}

/* End async HCI command handling */

/* Start of HCI event callbacks */

struct g_io_info {
	GIOChannel	*channel;
	int		watch_id;
	int		pin_length;
};

static struct g_io_info io_data[HCI_MAX_DEV];

static int get_handle(int dev, bdaddr_t *sba, bdaddr_t *dba, uint16_t *handle)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	char addr[18];
	int i;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	ba2str(sba, addr);
	cl->dev_id = hci_devid(addr);
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dev, HCIGETCONNLIST, (void *) cl) < 0) {
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

static inline int get_bdaddr(int dev, bdaddr_t *sba, uint16_t handle, bdaddr_t *dba)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	char addr[18];
	int i;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	ba2str(sba, addr);
	cl->dev_id = hci_devid(addr);
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dev, HCIGETCONNLIST, (void *) cl) < 0) {
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

static void link_key_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct hci_auth_info_req req;
	unsigned char key[16];
	char sa[18], da[18];
	uint8_t type;
	int err;

	ba2str(sba, sa); ba2str(dba, da);
	info("link_key_request (sba=%s, dba=%s)", sa, da);

	adapter = manager_find_adapter(sba);
	if (adapter)
		device = adapter_find_device(adapter, da);
	else
		device = NULL;

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, dba);

	err = ioctl(dev, HCIGETAUTHINFO, (unsigned long) &req);
	if (err < 0) {
		if (errno != EINVAL)
			DBG("HCIGETAUTHINFO failed %s (%d)",
						strerror(errno), errno);
		req.type = 0x00;
	}

	DBG("kernel auth requirements = 0x%02x", req.type);

	if (main_opts.debug_keys && device && device_get_debug_key(device, key))
		type = 0x03;
	else if (read_link_key(sba, dba, key, &type) < 0 || type == 0x03) {
		/* Link key not found */
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6, dba);
		return;
	}

	/* Link key found */

	DBG("link key type = 0x%02x", type);

	/* Don't use unauthenticated combination keys if MITM is
	 * required */
	if (type == 0x04 && req.type != 0xff && (req.type & 0x01))
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY,
								6, dba);
	else {
		link_key_reply_cp lr;

		memcpy(lr.link_key, key, 16);
		bacpy(&lr.bdaddr, dba);

		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_REPLY,
						LINK_KEY_REPLY_CP_SIZE, &lr);
	}
}

static void link_key_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_link_key_notify *evt = ptr;
	bdaddr_t *dba = &evt->bdaddr;
	char sa[18], da[18];
	int dev_id, err;
	unsigned char old_key[16];
	uint8_t old_key_type;

	ba2str(sba, sa); ba2str(dba, da);
	info("link_key_notify (sba=%s, dba=%s, type=%d)", sa, da,
							evt->key_type);

	err = read_link_key(sba, dba, old_key, &old_key_type);
	if (err < 0)
		old_key_type = 0xff;

	dev_id = hci_devid(sa);
	if (dev_id < 0)
		err = -errno;
	else {
		err = btd_event_link_key_notify(sba, dba, evt->link_key,
						evt->key_type,
						io_data[dev_id].pin_length,
						old_key_type);
		io_data[dev_id].pin_length = -1;
	}

	if (err < 0) {
		uint16_t handle;

		if (err == -ENODEV)
			btd_event_bonding_process_complete(sba, dba,
							HCI_OE_LOW_RESOURCES);
		else
			btd_event_bonding_process_complete(sba, dba,
							HCI_MEMORY_FULL);

		if (get_handle(dev, sba, dba, &handle) == 0) {
			disconnect_cp cp;

			memset(&cp, 0, sizeof(cp));
			cp.handle = htobs(handle);
			cp.reason = HCI_OE_LOW_RESOURCES;

			hci_send_cmd(dev, OGF_LINK_CTL, OCF_DISCONNECT,
						DISCONNECT_CP_SIZE, &cp);
		}
	}
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

		info("return_link_keys (sba=%s, dba=%s)", sa, da);

		btd_event_returned_link_key(sba, &dba);

		ptr += 22;
	}
}

/* Simple Pairing handling */

static void user_confirm_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_confirm_request *req = ptr;

	if (btd_event_user_confirm(sba, &req->bdaddr,
					btohl(req->passkey)) < 0)
		hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_USER_CONFIRM_NEG_REPLY, 6, ptr);
}

static void user_passkey_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_passkey_request *req = ptr;

	if (btd_event_user_passkey(sba, &req->bdaddr) < 0)
		hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_USER_PASSKEY_NEG_REPLY, 6, ptr);
}

static void user_passkey_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_passkey_notify *req = ptr;

	btd_event_user_notify(sba, &req->bdaddr, btohl(req->passkey));
}

static void remote_oob_data_request(int dev, bdaddr_t *sba, void *ptr)
{
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_REMOTE_OOB_DATA_NEG_REPLY, 6, ptr);
}

static void io_capa_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	char sa[18], da[18];
	uint8_t cap, auth;

	ba2str(sba, sa); ba2str(dba, da);
	info("io_capa_request (sba=%s, dba=%s)", sa, da);

	if (btd_event_get_io_cap(sba, dba, &cap, &auth) < 0) {
		io_capability_neg_reply_cp cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, dba);
		cp.reason = HCI_PAIRING_NOT_ALLOWED;
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_IO_CAPABILITY_NEG_REPLY,
					IO_CAPABILITY_NEG_REPLY_CP_SIZE, &cp);
	} else {
		io_capability_reply_cp cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, dba);
		cp.capability = cap;
		cp.oob_data = 0x00;
		cp.authentication = auth;
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_IO_CAPABILITY_REPLY,
					IO_CAPABILITY_REPLY_CP_SIZE, &cp);
	}
}

static void io_capa_response(int dev, bdaddr_t *sba, void *ptr)
{
	evt_io_capability_response *evt = ptr;
	char sa[18], da[18];

	ba2str(sba, sa); ba2str(&evt->bdaddr, da);
	info("io_capa_response (sba=%s, dba=%s)", sa, da);

	btd_event_set_io_cap(sba, &evt->bdaddr,
				evt->capability, evt->authentication);
}

/* PIN code handling */

void set_pin_length(bdaddr_t *sba, int length)
{
	char addr[18];
	int dev_id;

	ba2str(sba, addr);
	dev_id = hci_devid(addr);

	if (dev_id >= 0)
		io_data[dev_id].pin_length = length;
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
	info("pin_code_request (sba=%s, dba=%s)", sa, da);

	cr = g_malloc0(sizeof(*cr) + sizeof(*ci));

	bacpy(&cr->bdaddr, dba);
	cr->type = ACL_LINK;
	if (ioctl(dev, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		error("Can't get conn info: %s (%d)", strerror(errno), errno);
		goto reject;
	}
	ci = cr->conn_info;

	memset(pin, 0, sizeof(pin));
	pinlen = read_pin_code(sba, dba, pin);

	if (pinlen > 0) {
		set_pin_length(sba, pinlen);
		memcpy(pr.pin_code, pin, pinlen);
		pr.pin_len = pinlen;
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
				PIN_CODE_REPLY_CP_SIZE, &pr);
	} else {
		/* Request PIN from passkey agent */
		if (btd_event_request_pin(dev, sba, ci) < 0)
			goto reject;
	}

	g_free(cr);

	return;

reject:
	g_free(cr);

	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);
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

static void inquiry_complete(bdaddr_t *local, uint8_t status, gboolean periodic)
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

static inline void remote_features_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_remote_host_features_notify *evt = ptr;

	if (evt->features[0] & 0x01)
		btd_event_set_legacy_pairing(sba, &evt->bdaddr, FALSE);
	else
		btd_event_set_legacy_pairing(sba, &evt->bdaddr, TRUE);

	write_features_info(sba, &evt->bdaddr, NULL, evt->features);
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

static void read_local_ext_features_complete(bdaddr_t *sba,
				const read_local_ext_features_rp *rp)
{
	struct btd_adapter *adapter;

	if (rp->status)
		return;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("No matching adapter found");
		return;
	}

	/* Local Extended feature page number is 1 */
	if (rp->page_num != 1)
		return;

	btd_adapter_update_local_ext_features(adapter, rp->features);
}

static inline void cmd_status(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_status *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);

	if (opcode == cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY))
		start_inquiry(sba, evt->status, FALSE);
}

static void read_scan_complete(bdaddr_t *sba, uint8_t status, void *ptr)
{
	struct btd_adapter *adapter;
	read_scan_enable_rp *rp = ptr;

	adapter = manager_find_adapter(sba);

	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	adapter_mode_changed(adapter, rp->enable);
}

static inline void cmd_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_complete *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);
	uint8_t status = *((uint8_t *) ptr + EVT_CMD_COMPLETE_SIZE);

	switch (opcode) {
	case cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_LOCAL_EXT_FEATURES):
		ptr += sizeof(evt_cmd_complete);
		read_local_ext_features_complete(sba, ptr);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_PERIODIC_INQUIRY):
		start_inquiry(sba, status, TRUE);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_EXIT_PERIODIC_INQUIRY):
		inquiry_complete(sba, status, TRUE);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY_CANCEL):
		inquiry_complete(sba, status, FALSE);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_LE_HOST_SUPPORTED):
		write_le_host_complete(sba, status);
		break;
	case cmd_opcode_pack(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE):
		btd_event_le_set_scan_enable_complete(sba, status);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME):
		adapter_setname_complete(sba, status);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE):
		btd_event_setscan_enable_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_SCAN_ENABLE):
		ptr += sizeof(evt_cmd_complete);
		read_scan_complete(sba, status, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV):
		adapter_set_class_complete(sba, status);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE):
		btd_event_write_simple_pairing_mode_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_SIMPLE_PAIRING_MODE):
		ptr += sizeof(evt_cmd_complete);
		btd_event_read_simple_pairing_mode_complete(sba, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_LOCAL_NAME):
		ptr += sizeof(evt_cmd_complete);
		adapter_update_local_name(sba, status, ptr);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL):
		ptr += sizeof(evt_cmd_complete);
		adapter_update_tx_power(sba, status, ptr);
		break;
	};
}

static inline void remote_name_information(int dev, bdaddr_t *sba, void *ptr)
{
	evt_remote_name_req_complete *evt = ptr;
	char name[MAX_NAME_LENGTH + 1];

	memset(name, 0, sizeof(name));

	if (!evt->status)
		memcpy(name, evt->name, MAX_NAME_LENGTH);

	btd_event_remote_name(sba, &evt->bdaddr, evt->status, name);
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

static inline void inquiry_result(int dev, bdaddr_t *sba, int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0]
			| (info->dev_class[1] << 8)
			| (info->dev_class[2] << 16);

		btd_event_inquiry_result(sba, &info->bdaddr, class, 0, NULL);

		update_lastseen(sba, &info->bdaddr);

		ptr += INQUIRY_INFO_SIZE;
	}
}

static inline void inquiry_result_with_rssi(int dev, bdaddr_t *sba,
							int plen, void *ptr)
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

			btd_event_inquiry_result(sba, &info->bdaddr,
						class, info->rssi, NULL);

			update_lastseen(sba, &info->bdaddr);

			ptr += INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE;
		}
	} else {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi *info = ptr;
			uint32_t class = info->dev_class[0]
				| (info->dev_class[1] << 8)
				| (info->dev_class[2] << 16);

			btd_event_inquiry_result(sba, &info->bdaddr,
						class, info->rssi, NULL);

			update_lastseen(sba, &info->bdaddr);

			ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
		}
	}
}

static inline void extended_inquiry_result(int dev, bdaddr_t *sba,
							int plen, void *ptr)
{
	uint8_t num = *(uint8_t *) ptr++;
	int i;

	for (i = 0; i < num; i++) {
		extended_inquiry_info *info = ptr;
		uint32_t class = info->dev_class[0]
			| (info->dev_class[1] << 8)
			| (info->dev_class[2] << 16);

		btd_event_inquiry_result(sba, &info->bdaddr, class,
						info->rssi, info->data);

		update_lastseen(sba, &info->bdaddr);

		ptr += EXTENDED_INQUIRY_INFO_SIZE;
	}
}

static inline void remote_features_information(int dev, bdaddr_t *sba,
								void *ptr)
{
	evt_read_remote_features_complete *evt = ptr;
	bdaddr_t dba;

	if (evt->status)
		return;

	if (get_bdaddr(dev, sba, btohs(evt->handle), &dba) < 0)
		return;

	write_features_info(sba, &dba, evt->features, NULL);
}

static inline void conn_complete(int dev, int dev_id, bdaddr_t *sba, void *ptr)
{
	evt_conn_complete *evt = ptr;
	char filename[PATH_MAX];
	char local_addr[18], peer_addr[18], *str;
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(sba);
	if (!adapter) {
		error("Unable to find matching adapter");
		return;
	}

	if (evt->link_type != ACL_LINK)
		return;

	btd_event_conn_complete(sba, evt->status, btohs(evt->handle),
				&evt->bdaddr);

	if (evt->status)
		return;

	update_lastused(sba, &evt->bdaddr);

	btd_adapter_get_remote_name(adapter, &evt->bdaddr);

	/* check if the remote version needs be requested */
	ba2str(sba, local_addr);
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

static inline void disconn_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_disconn_complete *evt = ptr;

	btd_event_disconn_complete(sba, evt->status, btohs(evt->handle),
					evt->reason);
}

static inline void auth_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_auth_complete *evt = ptr;
	bdaddr_t dba;

	if (get_bdaddr(dev, sba, btohs(evt->handle), &dba) < 0)
		return;

	btd_event_bonding_process_complete(sba, &dba, evt->status);
}

static inline void simple_pairing_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_simple_pairing_complete *evt = ptr;

	btd_event_simple_pairing_complete(sba, &evt->bdaddr, evt->status);
}

static inline void conn_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_conn_request *evt = ptr;
	uint32_t class = evt->dev_class[0] | (evt->dev_class[1] << 8)
				| (evt->dev_class[2] << 16);

	btd_event_remote_class(sba, &evt->bdaddr, class);
}

static inline void le_metaevent(int dev, bdaddr_t *sba, void *ptr)
{
	evt_le_meta_event *meta = ptr;
	le_advertising_info *info;
	uint8_t *rssi, num, i;

	DBG("LE Meta Event");

	if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
		return;

	num = meta->data[0];
	info = (le_advertising_info *) (meta->data + 1);

	for (i = 0; i < num; i++) {
		/* RSSI is last byte of the advertising report event */
		rssi = info->data + info->length;
		btd_event_inquiry_result(sba, &info->bdaddr, 0, *rssi, NULL);
		info = (le_advertising_info *) (rssi + 1);
	}
}

static void stop_hci_dev(int hdev)
{
	GIOChannel *chan = io_data[hdev].channel;

	if (!chan)
		return;

	info("Stopping hci%d event socket", hdev);

	g_source_remove(io_data[hdev].watch_id);
	g_io_channel_unref(io_data[hdev].channel);
	io_data[hdev].watch_id = -1;
	io_data[hdev].channel = NULL;
	io_data[hdev].pin_length = -1;
}

static void delete_channel(GIOChannel *chan)
{
	int i;

	/* Look for the GIOChannel in the table */
	for (i = 0; i < HCI_MAX_DEV; i++)
		if (io_data[i].channel == chan) {
			stop_hci_dev(i);
			return;
		}

	error("IO channel not found in the io_data table");
}

static gboolean io_security_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_dev_info *di = data;
	int type, dev;
	size_t len;
	hci_event_hdr *eh;
	GIOError err;
	evt_cmd_status *evt;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		delete_channel(chan);
		return FALSE;
	}

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		delete_channel(chan);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	ptr += HCI_EVENT_HDR_SIZE;

	dev = g_io_channel_unix_get_fd(chan);

	ioctl(dev, HCIGETDEVINFO, (void *) di);

	if (ignore_device(di))
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

	case EVT_REMOTE_HOST_FEATURES_NOTIFY:
		remote_features_notify(dev, &di->bdaddr, ptr);
		break;

	case EVT_INQUIRY_COMPLETE:
		evt = (evt_cmd_status *) ptr;
		inquiry_complete(&di->bdaddr, evt->status, FALSE);
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
		conn_complete(dev, di->dev_id, &di->bdaddr, ptr);
		break;

	case EVT_DISCONN_COMPLETE:
		disconn_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_AUTH_COMPLETE:
		auth_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_SIMPLE_PAIRING_COMPLETE:
		simple_pairing_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_CONN_REQUEST:
		conn_request(dev, &di->bdaddr, ptr);
		break;
	case EVT_LE_META_EVENT:
		le_metaevent(dev, &di->bdaddr, ptr);
		break;
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

	case EVT_IO_CAPABILITY_REQUEST:
		io_capa_request(dev, &di->bdaddr, (bdaddr_t *) ptr);
		break;

	case EVT_IO_CAPABILITY_RESPONSE:
		io_capa_response(dev, &di->bdaddr, ptr);
		break;

	case EVT_USER_CONFIRM_REQUEST:
		user_confirm_request(dev, &di->bdaddr, ptr);
		break;

	case EVT_USER_PASSKEY_REQUEST:
		user_passkey_request(dev, &di->bdaddr, ptr);
		break;

	case EVT_USER_PASSKEY_NOTIFY:
		user_passkey_notify(dev, &di->bdaddr, ptr);
		break;

	case EVT_REMOTE_OOB_DATA_REQUEST:
		remote_oob_data_request(dev, &di->bdaddr, ptr);
		break;
	}

	return TRUE;
}

static void init_hci_dev(int hdev)
{
	GIOChannel *chan = io_data[hdev].channel;
	struct hci_dev_info *di;
	struct hci_filter flt;
	read_stored_link_key_cp cp;
	int dev;

	if (chan)
		return;

	info("Starting security manager %d", hdev);

	if ((dev = hci_open_dev(hdev)) < 0) {
		error("Can't open device hci%d: %s (%d)",
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
	if (setsockopt(dev, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		error("Can't set filter on hci%d: %s (%d)",
						hdev, strerror(errno), errno);
		close(dev);
		return;
	}

	di = g_new(struct hci_dev_info, 1);
	if (hci_devinfo(hdev, di) < 0) {
		error("Can't get device info: %s (%d)",
							strerror(errno), errno);
		close(dev);
		g_free(di);
		return;
	}

	chan = g_io_channel_unix_new(dev);
	g_io_channel_set_close_on_unref(chan, TRUE);
	io_data[hdev].watch_id = g_io_add_watch_full(chan, G_PRIORITY_LOW,
						G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						io_security_event, di, (GDestroyNotify) g_free);
	io_data[hdev].channel = chan;
	io_data[hdev].pin_length = -1;

	if (ignore_device(di))
		return;

	bacpy(&cp.bdaddr, BDADDR_ANY);
	cp.read_all = 1;

	hci_send_cmd(dev, OGF_HOST_CTL, OCF_READ_STORED_LINK_KEY,
			READ_STORED_LINK_KEY_CP_SIZE, (void *) &cp);
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
	uint16_t policy;

	if (hci_devinfo(index, &di) < 0)
		return;

	if (ignore_device(&di))
		return;

	/* Set page timeout */
	if ((main_opts.flags & (1 << HCID_SET_PAGETO))) {
		write_page_timeout_cp cp;

		cp.timeout = htobs(main_opts.pageto);
		hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT,
					WRITE_PAGE_TIMEOUT_CP_SIZE, &cp);
	}

	/* Set default link policy */
	policy = htobs(main_opts.link_policy);
	hci_send_cmd(SK(index), OGF_LINK_POLICY,
				OCF_WRITE_DEFAULT_LINK_POLICY, 2, &policy);

	init_hci_dev(index);

	/* Return value 1 means ioctl(DEVDOWN) was performed */
	if (manager_start_adapter(index) == 1)
		stop_hci_dev(index);
}

static void init_device(int index)
{
	struct hci_dev_req dr;
	struct hci_dev_info di;
	int dd;
	pid_t pid;

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

	/* Set link policy for BR/EDR HCI devices */
	if (hci_devinfo(index, &di) < 0)
		goto fail;

	if (!ignore_device(&di)) {
		dr.dev_opt = main_opts.link_policy;
		if (ioctl(dd, HCISETLINKPOL, (unsigned long) &dr) < 0 &&
							errno != ENETDOWN) {
			error("Can't set link policy on hci%d: %s (%d)",
						index, strerror(errno), errno);
		}
	}

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
		hci_close_dev(SK(index));
		init_dev_info(index, -1);
		manager_unregister_adapter(index);
		break;

	case HCI_DEV_UP:
		info("HCI dev %d up", index);
		device_devup_setup(index);
		break;

	case HCI_DEV_DOWN:
		info("HCI dev %d down", index);
		manager_stop_adapter(index);
		stop_hci_dev(index);
		break;
	}
}

static int init_known_adapters(int ctl)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, err;
	size_t req_size;

	req_size = HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t);

	dl = g_try_malloc0(req_size);
	if (!dl) {
		error("Can't allocate devlist buffer");
		return -ENOMEM;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, dl) < 0) {
		err = -errno;
		error("Can't get device list: %s (%d)", strerror(-err), -err);
		g_free(dl);
		return err;
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		device_event(HCI_DEV_REG, dr->dev_id);

		if (hci_test_bit(HCI_UP, &dr->dev_opt))
			device_event(HCI_DEV_UP, dr->dev_id);
	}

	g_free(dl);
	return 0;
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

	/* Initialize already connected devices */
	return init_known_adapters(sock);
}

static void hciops_cleanup(void)
{
	int i;

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

static int hciops_powered(int index, gboolean powered)
{
	uint8_t mode = SCAN_DISABLED;

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

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
					OCF_WRITE_SCAN_ENABLE, 1, &mode) < 0)
		return -errno;

	return 0;
}

static int hciops_discoverable(int index)
{
	uint8_t mode = (SCAN_PAGE | SCAN_INQUIRY);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
								1, &mode) < 0)
		return -errno;

	return 0;
}

static int hciops_set_class(int index, uint32_t class)
{
	write_class_of_dev_cp cp;

	memcpy(cp.dev_class, &class, 3);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
					WRITE_CLASS_OF_DEV_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_set_limited_discoverable(int index, uint32_t class,
							gboolean limited)
{
	int num = (limited ? 2 : 1);
	uint8_t lap[] = { 0x33, 0x8b, 0x9e, 0x00, 0x8b, 0x9e };
	write_current_iac_lap_cp cp;

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

	return hciops_set_class(index, class);
}

static int hciops_start_inquiry(int index, uint8_t length, gboolean periodic)
{
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int err;

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

static int hciops_start_scanning(int index)
{
	if (hci_le_set_scan_parameters(SK(index), 0x01, htobs(0x0010),
					htobs(0x0010), 0x00, 0x00) < 0)
		return -errno;

	if (hci_le_set_scan_enable(SK(index), 0x01, 0x00) < 0)
		return -errno;

	return 0;
}

static int hciops_stop_scanning(int index)
{
	if (hci_le_set_scan_enable(SK(index), 0x00, 0x00) < 0)
		return -errno;

	return 0;
}

static int hciops_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cp cp;

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

	memset(&cp, 0, sizeof(cp));
	strncpy((char *) cp.name, name, sizeof(cp.name));

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
				CHANGE_LOCAL_NAME_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_read_name(int index)
{
	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_READ_LOCAL_NAME,
								0, 0) < 0)
		return -errno;

	return 0;
}

static int hciops_cancel_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cancel_cp cp;

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
	if (hci_read_clock(SK(index), handle, which, clock, accuracy,
								timeout) < 0)
		return -errno;

	return 0;
}

static int hciops_conn_handle(int index, const bdaddr_t *bdaddr, int *handle)
{
	int err;
	struct hci_conn_info_req *cr;

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

static int hciops_write_eir_data(int index, uint8_t *data)
{
	write_ext_inquiry_response_cp cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(cp.data, data, 240);

	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_WRITE_EXT_INQUIRY_RESPONSE,
				WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_read_bdaddr(int index, bdaddr_t *bdaddr)
{
	if (hci_read_bd_addr(SK(index), bdaddr, HCI_REQ_TIMEOUT) < 0)
		return -errno;

	return 0;
}

static int hciops_set_event_mask(int index, uint8_t *events, size_t count)
{
	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_SET_EVENT_MASK,
							count, events) < 0)
		return -errno;

	return 0;
}

static int hciops_write_inq_mode(int index, uint8_t mode)
{
	write_inquiry_mode_cp cp;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE,
					WRITE_INQUIRY_MODE_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_read_inq_tx_pwr(int index)
{
	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
			OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL, 0, NULL) < 0)
		return -errno;

	return 0;
}

static int hciops_block_device(int index, bdaddr_t *bdaddr)
{
	if (ioctl(SK(index), HCIBLOCKADDR, bdaddr) < 0)
		return -errno;

	return 0;
}

static int hciops_unblock_device(int index, bdaddr_t *bdaddr)
{
	if (ioctl(SK(index), HCIUNBLOCKADDR, bdaddr) < 0)
		return -errno;

	return 0;
}

static int hciops_get_conn_list(int index, GSList **conns)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int err, i;

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
	if (hci_read_local_version(SK(index), ver, HCI_REQ_TIMEOUT) < 0)
		return -errno;

	return 0;
}

static int hciops_read_local_features(int index, uint8_t *features)
{
	if (hci_read_local_features(SK(index), features,
							HCI_REQ_TIMEOUT) < 0)
		return -errno;

	return  0;
}

static int hciops_read_local_ext_features(int index)
{
	uint8_t page_num = 1;

	if (hci_send_cmd(SK(index), OGF_INFO_PARAM,
				OCF_READ_LOCAL_EXT_FEATURES, 1, &page_num) < 0)
		return -errno;

	return 0;
}

static int hciops_init_ssp_mode(int index, uint8_t *mode)
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

static int hciops_read_link_policy(int index)
{
	if (hci_send_cmd(SK(index), OGF_LINK_POLICY,
				OCF_READ_DEFAULT_LINK_POLICY, 0, NULL) < 0)
		return -errno;

	return 0;
}

static int hciops_disconnect(int index, uint16_t handle)
{
	disconnect_cp cp;

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

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	/* Delete the link key from the Bluetooth chip */
	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_DELETE_STORED_LINK_KEY,
				DELETE_STORED_LINK_KEY_CP_SIZE, &cp) < 0)
		return -errno;

	return 0;
}

static int hciops_request_authentication(int index, uint16_t handle,
							uint8_t *status)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;

	memset(&rp, 0, sizeof(rp));

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(SK(index), &rq, HCI_REQ_TIMEOUT) < 0)
		return -errno;

	if (status)
		*status = rp.status;

	return 0;
}

static int hciops_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin)
{
	int err;

	if (pin) {
		pin_code_reply_cp pr;
		size_t len = strlen(pin);

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
	int err;
	user_confirm_reply_cp cp;

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
	int err;

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
	if (hci_send_cmd(SK(index), OGF_HOST_CTL, OCF_READ_SCAN_ENABLE,
								0, NULL) < 0)
		return -errno;

	return 0;
}

static int hciops_read_ssp_mode(int index)
{
	if (hci_send_cmd(SK(index), OGF_HOST_CTL,
				OCF_READ_SIMPLE_PAIRING_MODE, 0, NULL) < 0)
		return -errno;

	return 0;
}

static int hciops_write_le_host(int index, uint8_t le, uint8_t simul)
{
	write_le_host_supported_cp cp;

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

static struct btd_adapter_ops hci_ops = {
	.setup = hciops_setup,
	.cleanup = hciops_cleanup,
	.start = hciops_start,
	.stop = hciops_stop,
	.set_powered = hciops_powered,
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
	.read_name = hciops_read_name,
	.set_class = hciops_set_class,
	.set_fast_connectable = hciops_fast_connectable,
	.read_clock = hciops_read_clock,
	.get_conn_handle = hciops_conn_handle,
	.write_eir_data = hciops_write_eir_data,
	.read_bdaddr = hciops_read_bdaddr,
	.set_event_mask = hciops_set_event_mask,
	.write_inq_mode = hciops_write_inq_mode,
	.read_inq_tx_pwr = hciops_read_inq_tx_pwr,
	.block_device = hciops_block_device,
	.unblock_device = hciops_unblock_device,
	.get_conn_list = hciops_get_conn_list,
	.read_local_version = hciops_read_local_version,
	.read_local_features = hciops_read_local_features,
	.read_local_ext_features = hciops_read_local_ext_features,
	.init_ssp_mode = hciops_init_ssp_mode,
	.read_link_policy = hciops_read_link_policy,
	.disconnect = hciops_disconnect,
	.remove_bonding = hciops_remove_bonding,
	.request_authentication = hciops_request_authentication,
	.pincode_reply = hciops_pincode_reply,
	.confirm_reply = hciops_confirm_reply,
	.passkey_reply = hciops_passkey_reply,
	.get_auth_info = hciops_get_auth_info,
	.read_scan_enable = hciops_read_scan_enable,
	.read_ssp_mode = hciops_read_ssp_mode,
	.write_le_host = hciops_write_le_host,
	.get_remote_version = hciops_get_remote_version,
	.encrypt_link = hciops_encrypt_link,
};

static int hciops_init(void)
{
	return btd_register_adapter_ops(&hci_ops);
}
static void hciops_exit(void)
{
	btd_adapter_cleanup_ops(&hci_ops);
}

BLUETOOTH_PLUGIN_DEFINE(hciops, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, hciops_init, hciops_exit)
