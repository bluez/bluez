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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "textfile.h"
#include "adapter.h"
#include "dbus-hci.h"

struct g_io_info {
	GIOChannel	*channel;
	int		watch_id;
	int		pin_length;
};

static struct g_io_info io_data[HCI_MAX_DEV];

static int pairing = HCID_PAIRING_MULTI;

static GSList *hci_req_queue = NULL;

struct hci_req_data *hci_req_data_new(int dev_id, const bdaddr_t *dba, uint16_t ogf, uint16_t ocf, int event, const void *cparam, int clen)
{
	struct hci_req_data *data;

	data = g_new0(struct hci_req_data, 1);

	data->cparam = g_malloc(clen);
	memcpy(data->cparam, cparam, clen);

	bacpy(&data->dba, dba);

	data->dev_id = dev_id;
	data->status = REQ_PENDING;
	data->ogf    = ogf;
	data->ocf    = ocf;
	data->event  = event;
	data->clen   = clen;

	return data;
}

static int hci_req_find_by_devid(const void *data, const void *user_data)
{
	const struct hci_req_data *req = data;
	const int *dev_id = user_data;

	return (*dev_id - req->dev_id);
}

static void hci_req_queue_process(int dev_id)
{
	int dd, ret_val;

	/* send the next pending cmd */
	dd = hci_open_dev(dev_id);
	do {
		struct hci_req_data *data;
		GSList *l = g_slist_find_custom(hci_req_queue, &dev_id, hci_req_find_by_devid);

		if (!l)
			break;

		data = l->data;
		data->status = REQ_SENT;

		ret_val = hci_send_cmd(dd, data->ogf, data->ocf, data->clen, data->cparam);
		if (ret_val < 0) {
			hci_req_queue = g_slist_remove(hci_req_queue, data);
			g_free(data->cparam);
			g_free(data);
		}

	} while(ret_val < 0);

	hci_close_dev(dd);
}

void hci_req_queue_append(struct hci_req_data *data)
{
	GSList *l;
	struct hci_req_data *match;


	hci_req_queue = g_slist_append(hci_req_queue, data);

	l = g_slist_find_custom(hci_req_queue, &data->dev_id, hci_req_find_by_devid);
	match = l->data;

	if (match->status == REQ_SENT)
		return;

	hci_req_queue_process(data->dev_id);
}

void hci_req_queue_remove(int dev_id, bdaddr_t *dba)
{
	GSList *cur, *next;
	struct hci_req_data *req;

	for (cur = hci_req_queue; cur != NULL; cur = next) {
		req = cur->data;
		next = cur->next;
		if ((req->dev_id != dev_id) || (bacmp(&req->dba, dba)))
			continue;

		hci_req_queue = g_slist_remove(hci_req_queue, req);
		g_free(req->cparam);
		g_free(req);
	}
}

static void check_pending_hci_req(int dev_id, int event)
{
	struct hci_req_data *data;
	GSList *l;

	if (!hci_req_queue)
		return;

	/* find the first element(pending)*/
	l = g_slist_find_custom(hci_req_queue, &dev_id, hci_req_find_by_devid);

	if (!l)
		return;

	data = l->data;

	/* skip if there is pending confirmation */
	if (data->status == REQ_SENT) {
		if (data->event != event)
			return;

		/* remove the confirmed cmd */
		hci_req_queue = g_slist_remove(hci_req_queue, data);
		g_free(data->cparam);
		g_free(data);
	}

	hci_req_queue_process(dev_id);
}

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
	struct hci_auth_info_req req;
	unsigned char key[16];
	char sa[18], da[18];
	uint8_t type;
	int err;

	ba2str(sba, sa); ba2str(dba, da);
	info("link_key_request (sba=%s, dba=%s)", sa, da);

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, dba);

	err = ioctl(dev, HCIGETAUTHINFO, (unsigned long) &req);
	if (err < 0 && errno != EINVAL)
		debug("HCIGETAUTHINFO failed %s (%d)",
					strerror(errno), errno);
	else
		req.type = 0x00;

	debug("kernel auth requirements = 0x%02x", req.type);

	err = read_link_key(sba, dba, key, &type);
	if (err < 0) {
		/* Link key not found */
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_LINK_KEY_NEG_REPLY, 6, dba);
	} else {
		/* Link key found */
		link_key_reply_cp lr;
		memcpy(lr.link_key, key, 16);
		bacpy(&lr.bdaddr, dba);

		debug("stored link key type = 0x%02x", type);

		if ((type == 0x03 || type == 0x04) && (req.type & 0x01))
			hci_send_cmd(dev, OGF_LINK_CTL,
					OCF_LINK_KEY_NEG_REPLY, 6, dba);
		else
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

	ba2str(sba, sa); ba2str(dba, da);
	info("link_key_notify (sba=%s, dba=%s)", sa, da);

	dev_id = hci_devid(sa);

	err = write_link_key(sba, dba, evt->link_key, evt->key_type,
						io_data[dev_id].pin_length);
	if (err < 0) {
		uint16_t handle;

		error("write_link_key: %s (%d)", strerror(-err), -err);

		hcid_dbus_bonding_process_complete(sba, dba, HCI_MEMORY_FULL);

		if (get_handle(dev, sba, dba, &handle) == 0) {
			disconnect_cp cp;

			memset(&cp, 0, sizeof(cp));
			cp.handle = htobs(handle);
			cp.reason = HCI_OE_LOW_RESOURCES;

			hci_send_cmd(dev, OGF_LINK_CTL, OCF_DISCONNECT,
						DISCONNECT_CP_SIZE, &cp);
		}
	} else
		hcid_dbus_bonding_process_complete(sba, dba, 0);

	io_data[dev_id].pin_length = -1;
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

		ptr += 22;
	}
}

/* Simple Pairing handling */

static void user_confirm_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_confirm_request *req = ptr;

	if (hcid_dbus_user_confirm(sba, &req->bdaddr,
					btohl(req->passkey)) < 0)
		hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_USER_CONFIRM_NEG_REPLY, 6, ptr);
}

static void user_passkey_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_passkey_request *req = ptr;

	if (hcid_dbus_user_passkey(sba, &req->bdaddr) < 0)
		hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_USER_PASSKEY_NEG_REPLY, 6, ptr);
}

static void user_passkey_notify(int dev, bdaddr_t *sba, void *ptr)
{
	evt_user_passkey_notify *req = ptr;

	hcid_dbus_user_notify(sba, &req->bdaddr, btohl(req->passkey));
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

	if (hcid_dbus_get_io_cap(sba, dba, &cap, &auth) < 0) {
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

	hcid_dbus_set_io_cap(sba, &evt->bdaddr,
				evt->capability, evt->authentication);
}

/* PIN code handling */

void set_pin_length(bdaddr_t *sba, int length)
{
	char addr[18];
	int dev_id;

	ba2str(sba, addr);
	dev_id = hci_devid(addr);

	io_data[dev_id].pin_length = length;
}

static void pin_code_request(int dev, bdaddr_t *sba, bdaddr_t *dba)
{
	pin_code_reply_cp pr;
	struct hci_conn_info_req *cr;
	struct hci_conn_info *ci;
	unsigned char key[16];
	char sa[18], da[18], pin[17];
	int err, pinlen;

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

	if (pairing == HCID_PAIRING_ONCE) {
		err = read_link_key(sba, dba, key, NULL);
		if (!err) {
			ba2str(dba, da);
			error("PIN code request for already paired device %s", da);
			goto reject;
		}
	} else if (pairing == HCID_PAIRING_NONE)
		goto reject;

	if (hcid.security == HCID_SEC_AUTO && !ci->out) {
		set_pin_length(sba, hcid.pin_len);
		memcpy(pr.pin_code, hcid.pin_code, hcid.pin_len);
		pr.pin_len = hcid.pin_len;
		hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
	} else {
		if (pinlen > 0) {
			set_pin_length(sba, pinlen);
			memcpy(pr.pin_code, pin, pinlen);
			pr.pin_len = pinlen;
			hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
		} else {
			/* Request PIN from passkey agent */
			if (hcid_dbus_request_pin(dev, sba, ci) < 0)
				goto reject;
		}
	}

	g_free(cr);

	return;

reject:
	g_free(cr);

	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);
}

static inline void cmd_status(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_status *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);

	if (evt->status)
		return;

	if (opcode == cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY))
		hcid_dbus_inquiry_start(sba);
}

static inline void cmd_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_cmd_complete *evt = ptr;
	uint16_t opcode = btohs(evt->opcode);
	uint8_t status;

	switch (opcode) {
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_PERIODIC_INQUIRY):
		status = *((uint8_t *) ptr + EVT_CMD_COMPLETE_SIZE);
		hcid_dbus_periodic_inquiry_start(sba, status);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_EXIT_PERIODIC_INQUIRY):
		status = *((uint8_t *) ptr + EVT_CMD_COMPLETE_SIZE);
		hcid_dbus_periodic_inquiry_exit(sba, status);
		break;
	case cmd_opcode_pack(OGF_LINK_CTL, OCF_INQUIRY_CANCEL):
		hcid_dbus_inquiry_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME):
		hcid_dbus_setname_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE):
		hcid_dbus_setscan_enable_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV):
		hcid_dbus_write_class_complete(sba);
		break;
	case cmd_opcode_pack(OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE):
		hcid_dbus_write_simple_pairing_mode_complete(sba);
		break;
	};
}

static inline void remote_name_information(int dev, bdaddr_t *sba, void *ptr)
{
	evt_remote_name_req_complete *evt = ptr;
	bdaddr_t dba;
	char name[249];

	memset(name, 0, sizeof(name));
	bacpy(&dba, &evt->bdaddr);

	if (!evt->status) {
		char *end;
		memcpy(name, evt->name, 248);
		/* It's ok to cast end between const and non-const since
		 * we know it points to inside of name which is non-const */
		if (!g_utf8_validate(name, -1, (const char **) &end))
			*end = '\0';
		write_device_name(sba, &dba, name);
	}

	hcid_dbus_remote_name(sba, &dba, evt->status, name);
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

		hcid_dbus_inquiry_result(sba, &info->bdaddr, class, 0, NULL);

		update_lastseen(sba, &info->bdaddr);

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

			hcid_dbus_inquiry_result(sba, &info->bdaddr,
						class, info->rssi, NULL);

			update_lastseen(sba, &info->bdaddr);

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

		hcid_dbus_inquiry_result(sba, &info->bdaddr, class,
						info->rssi, info->data);

		update_lastseen(sba, &info->bdaddr);

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

static inline void conn_complete(int dev, int dev_id, bdaddr_t *sba, void *ptr)
{
	evt_conn_complete *evt = ptr;
	char filename[PATH_MAX];
	remote_name_req_cp cp_name;
	struct hci_req_data *data;
	char local_addr[18], peer_addr[18], *str;

	if (evt->link_type != ACL_LINK)
		return;

	hcid_dbus_conn_complete(sba, evt->status, btohs(evt->handle),
				&evt->bdaddr);

	if (evt->status)
		return;

	update_lastused(sba, &evt->bdaddr);

	/* Request remote name */
	memset(&cp_name, 0, sizeof(cp_name));
	bacpy(&cp_name.bdaddr, &evt->bdaddr);
	cp_name.pscan_rep_mode = 0x02;

	data = hci_req_data_new(dev_id, &evt->bdaddr, OGF_LINK_CTL,
				OCF_REMOTE_NAME_REQ, EVT_REMOTE_NAME_REQ_COMPLETE,
				&cp_name, REMOTE_NAME_REQ_CP_SIZE);

	hci_req_queue_append(data);

	/* check if the remote version needs be requested */
	ba2str(sba, local_addr);
	ba2str(&evt->bdaddr, peer_addr);

	create_name(filename, sizeof(filename), STORAGEDIR, local_addr, "manufacturers");

	str = textfile_get(filename, peer_addr);
	if (!str) {
		read_remote_version_cp cp;

		memset(&cp, 0, sizeof(cp));
		cp.handle = evt->handle;

		data = hci_req_data_new(dev_id, &evt->bdaddr, OGF_LINK_CTL,
					OCF_READ_REMOTE_VERSION, EVT_READ_REMOTE_VERSION_COMPLETE,
					&cp, READ_REMOTE_VERSION_CP_SIZE);

		hci_req_queue_append(data);
	} else
		free(str);
}

static inline void disconn_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_disconn_complete *evt = ptr;

	hcid_dbus_disconn_complete(sba, evt->status, btohs(evt->handle),
					evt->reason);
}

static inline void auth_complete(int dev, bdaddr_t *sba, void *ptr)
{
	evt_auth_complete *evt = ptr;
	bdaddr_t dba;

	if (get_bdaddr(dev, sba, btohs(evt->handle), &dba) < 0)
		return;

	if (evt->status)
		hcid_dbus_bonding_process_complete(sba, &dba, evt->status);
}

static inline void conn_request(int dev, bdaddr_t *sba, void *ptr)
{
	evt_conn_request *evt = ptr;
	uint32_t class = evt->dev_class[0] | (evt->dev_class[1] << 8)
				| (evt->dev_class[2] << 16);

	hcid_dbus_remote_class(sba, &evt->bdaddr, class);

	write_remote_class(sba, &evt->bdaddr, class);
}

static gboolean io_security_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_dev_info *di = data;
	int type, dev;
	size_t len;
	hci_event_hdr *eh;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		g_io_channel_unref(chan);
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
		conn_complete(dev, di->dev_id, &di->bdaddr, ptr);
		break;

	case EVT_DISCONN_COMPLETE:
		disconn_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_AUTH_COMPLETE:
		auth_complete(dev, &di->bdaddr, ptr);
		break;

	case EVT_CONN_REQUEST:
		conn_request(dev, &di->bdaddr, ptr);
		break;
	}

	/* Check for pending command request */
	check_pending_hci_req(di->dev_id, eh->evt);

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

void start_security_manager(int hdev)
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
	io_data[hdev].watch_id = g_io_add_watch_full(chan, G_PRIORITY_HIGH,
						G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						io_security_event, di, (GDestroyNotify) g_free);
	io_data[hdev].channel = chan;
	io_data[hdev].pin_length = -1;

	if (hci_test_bit(HCI_RAW, &di->flags))
		return;

	bacpy(&cp.bdaddr, BDADDR_ANY);
	cp.read_all = 1;

	hci_send_cmd(dev, OGF_HOST_CTL, OCF_READ_STORED_LINK_KEY,
			READ_STORED_LINK_KEY_CP_SIZE, (void *) &cp);
}

void stop_security_manager(int hdev)
{
	GIOChannel *chan = io_data[hdev].channel;

	if (!chan)
		return;

	info("Stopping security manager %d", hdev);

	g_source_remove(io_data[hdev].watch_id);
	g_io_channel_unref(io_data[hdev].channel);
	io_data[hdev].watch_id = -1;
	io_data[hdev].channel = NULL;
	io_data[hdev].pin_length = -1;
}

void init_security_data(void)
{
	pairing = hcid.pairing;
}
