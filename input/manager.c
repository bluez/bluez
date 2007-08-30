/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/hidp.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"
#include "textfile.h"

#include "device.h"
#include "server.h"
#include "error.h"
#include "manager.h"
#include "storage.h"

static const char *pnp_uuid	= "00001200-0000-1000-8000-00805f9b34fb";
static const char *hid_uuid	= "00001124-0000-1000-8000-00805f9b34fb";
static const char *headset_uuid	= "00001108-0000-1000-8000-00805f9b34fb";

struct pending_req {
	char		*adapter_path;	/* Local adapter D-Bus path */
	bdaddr_t	src;		/* Local adapter BT address */
	bdaddr_t	dst;		/* Peer BT address */
	DBusConnection	*conn;
	DBusMessage	*msg;
	sdp_record_t	*pnp_rec;
	sdp_record_t	*hid_rec;
	int		ctrl_sock;
};

static GSList *device_paths = NULL;	/* Input registered paths */

static DBusConnection *connection = NULL;

static struct pending_req *pending_req_new(DBusConnection *conn,
			DBusMessage *msg, bdaddr_t *src, bdaddr_t *dst)
{
	char adapter[18], adapter_path[32];
	struct pending_req *pr;
	int dev_id;

	pr = g_try_new0(struct pending_req, 1);
	if (!pr)
		return NULL;

	ba2str(src, adapter);
	dev_id = hci_devid(adapter);
	snprintf(adapter_path, 32, "/org/bluez/hci%d", dev_id);

	pr->adapter_path = g_strdup(adapter_path);
	bacpy(&pr->src, src);
	bacpy(&pr->dst, dst);
	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);

	return pr;
}

static void pending_req_free(struct pending_req *pr)
{
	if (!pr)
		return;

	if (pr->adapter_path)
		g_free(pr->adapter_path);

	if (pr->conn)
		dbus_connection_unref(pr->conn);

	if (pr->msg)
		dbus_message_unref(pr->msg);

	if (pr->pnp_rec)
		sdp_record_free(pr->pnp_rec);

	if (pr->hid_rec)
		sdp_record_free(pr->hid_rec);

	g_free(pr);
}

static int get_record(struct pending_req *pr, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return 0;
}

static int get_handles(struct pending_req *pr, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg  = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);
	
	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return 0;
}

static void epox_endian_quirk(unsigned char *data, int size)
{
	/* USAGE_PAGE (Keyboard)	05 07
	 * USAGE_MINIMUM (0)		19 00
	 * USAGE_MAXIMUM (65280)	2A 00 FF   <= must be FF 00
	 * LOGICAL_MINIMUM (0)		15 00
	 * LOGICAL_MAXIMUM (65280)	26 00 FF   <= must be FF 00
	 */
	unsigned char pattern[] = { 0x05, 0x07, 0x19, 0x00, 0x2a, 0x00, 0xff,
						0x15, 0x00, 0x26, 0x00, 0xff };
	int i;

	if (!data)
		return;

	for (i = 0; i < size - sizeof(pattern); i++) {
		if (!memcmp(data + i, pattern, sizeof(pattern))) {
			data[i + 5] = 0xff;
			data[i + 6] = 0x00;
			data[i + 10] = 0xff;
			data[i + 11] = 0x00;
		}
	}
}

static void extract_hid_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist, *pdlist2;
	uint8_t attr_val;

	pdlist = sdp_data_get(rec, 0x0101);
	pdlist2 = sdp_data_get(rec, 0x0102);
	if (pdlist) {
		if (pdlist2) {
			if (strncmp(pdlist->val.str, pdlist2->val.str, 5)) {
				strncpy(req->name, pdlist2->val.str, 127);
				strcat(req->name, " ");
			}
			strncat(req->name, pdlist->val.str, 127 - strlen(req->name));
		} else
			strncpy(req->name, pdlist->val.str, 127);
	} else {
		pdlist2 = sdp_data_get(rec, 0x0100);
		if (pdlist2)
			strncpy(req->name, pdlist2->val.str, 127);
 	}
 
	pdlist = sdp_data_get(rec, SDP_ATTR_HID_PARSER_VERSION);
	req->parser = pdlist ? pdlist->val.uint16 : 0x0100;
 
	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DEVICE_SUBCLASS);
	req->subclass = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_COUNTRY_CODE);
	req->country = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_VIRTUAL_CABLE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_VIRTUAL_CABLE_UNPLUG);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_BOOT_DEVICE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_BOOT_PROTOCOL_MODE);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);
	if (pdlist) {
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->next;

		req->rd_data = g_try_malloc0(pdlist->unitSize);
		if (req->rd_data) {
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str,
								pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
			epox_endian_quirk(req->rd_data, req->rd_size);
		}
	}
}

static void extract_pnp_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist;

	pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
	req->vendor = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
	req->product = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
	req->version = pdlist ? pdlist->val.uint16 : 0x0000;
}

static gboolean interrupt_connect_cb(GIOChannel *chan,
			GIOCondition cond, struct pending_req *pr)
{
	struct hidp_connadd_req hidp;
	DBusMessage *reply;
	const char *path;
	int isk, ret, err;
	socklen_t len;

	isk = g_io_channel_unix_get_fd(chan);

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		isk = -1;
		goto failed;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		err = EHOSTDOWN;
		error("Hangup or error on HIDP interrupt socket");
		goto failed;

	}

	len = sizeof(ret);
	if (getsockopt(isk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	memset(&hidp, 0, sizeof(struct hidp_connadd_req));
	extract_hid_record(pr->hid_rec, &hidp);
	if (pr->pnp_rec)
		extract_pnp_record(pr->pnp_rec, &hidp);

	store_device_info(&pr->src, &pr->dst, &hidp);

	if (input_device_register(pr->conn, &pr->src,
					&pr->dst, &hidp, &path) < 0) {
		err_failed(pr->conn, pr->msg, "path registration failed");
		goto cleanup;
	}

	dbus_connection_emit_signal(pr->conn, INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceCreated",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	device_paths = g_slist_append(device_paths, g_strdup(path));

	/* Replying to the requestor */
	reply = dbus_message_new_method_return(pr->msg);

	dbus_message_append_args(reply,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);

	send_message_and_unref(pr->conn, reply);

	goto cleanup;
failed:
	err_connection_failed(pr->conn, pr->msg, strerror(err));

cleanup:
	if (isk >= 0)
		close(isk);

	close(pr->ctrl_sock);
	pending_req_free(pr);

	return FALSE;
}

static gboolean control_connect_cb(GIOChannel *chan,
			GIOCondition cond, struct pending_req *pr)
{
	int ret, csk, err;
	socklen_t len;

	csk = g_io_channel_unix_get_fd(chan);

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		csk = -1;
		goto failed;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		err = EHOSTDOWN;
		error("Hangup or error on HIDP control socket");
		goto failed;

	}

	/* Set HID control channel */
	pr->ctrl_sock = csk;

	len = sizeof(ret);
	if (getsockopt(csk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	if (l2cap_connect(&pr->src, &pr->dst, L2CAP_PSM_HIDP_INTR,
			(GIOFunc) interrupt_connect_cb, pr) < 0) {

		err = errno;
		error("L2CAP connect failed:%s (%d)", strerror(errno), errno);
		goto failed;
	}

	return FALSE;

failed:
	if (csk >= 0)
		close(csk);

	err_connection_failed(pr->conn, pr->msg, strerror(err));
	pending_req_free(pr);

	return FALSE;
}

static void finish_sdp_transaction(bdaddr_t *dba) 
{
	char address[18], *addr_ptr = address;
	DBusMessage *msg, *reply;
	DBusError derr;

	ba2str(dba, address);

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"FinishRemoteServiceTransaction");
	if (!msg) {
		error("Unable to allocate new method call");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection, msg,
								-1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) || dbus_set_error_from_message(&derr, reply)) {
		error("FinishRemoteServiceTransaction(%s) failed: %s",
				address, derr.message);
		dbus_error_free(&derr);
		return;
	}

	dbus_message_unref(reply);
}

static void hid_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint8_t *rec_bin;
	int len, scanned;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord failed: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	finish_sdp_transaction(&pr->dst);

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid HID service record length");
		goto fail;
	}

	pr->hid_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!pr->hid_rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (l2cap_connect(&pr->src, &pr->dst, L2CAP_PSM_HIDP_CTRL,
				(GIOFunc) control_connect_cb, pr) < 0) {
		int err = errno;
		error("L2CAP connect failed:%s (%d)", strerror(err), err);
		err_connection_failed(pr->conn, pr->msg, strerror(err));
		goto fail;

	}
	dbus_message_unref(reply);

	return;
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
}

static void hid_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	uint32_t *phandle;
	DBusError derr;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, hid_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);

done:
	dbus_message_unref(reply);
}

static void pnp_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint8_t *rec_bin;
	int len, scanned;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid PnP service record length");
		goto fail;
	}

	pr->pnp_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service search request failed");
		goto fail;
	} else {
		/* Wait handle reply */
		goto done;
	}

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);

done:
	dbus_message_unref(reply);
}

static void pnp_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		/* PnP is optional: Ignore it and request the HID handle  */
		if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("HID service search request failed");
			goto fail;
		}
	} else {
		/* Request PnP record */
		if (get_record(pr, *phandle, pnp_record_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("PnP service attribute request failed");
			goto fail;
		}
	}

	/* Wait HID handle reply or PnP record reply */
	goto done;

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);

done:
	dbus_message_unref(reply);
}

static void headset_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *pr_reply;
	DBusError derr;
	struct pending_req *pr = data;
	uint8_t *rec_bin;
	sdp_record_t *rec;
	sdp_list_t *protos;
	const char *path;
	int len, scanned;
	uint8_t ch;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid headset service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (sdp_get_access_protos(rec, &protos) < 0) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	sdp_record_free(rec);

	if (ch <= 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid RFCOMM channel");
		goto fail;
	}

	/* FIXME: Store the fake input data */

	if (fake_input_register(pr->conn, &pr->src, &pr->dst, ch, &path) < 0) {
		error("D-Bus path registration failed:%s", path);
		err_failed(pr->conn, pr->msg, "Path registration failed");
		goto fail;
	}

	dbus_connection_emit_signal(pr->conn, INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceCreated",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	device_paths = g_slist_append(device_paths, g_strdup(path));

	pr_reply = dbus_message_new_method_return(pr->msg);

	dbus_message_append_args(pr_reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	send_message_and_unref(pr->conn, pr_reply);

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
}

static void headset_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
			"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)",
				derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, headset_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);

done:
	dbus_message_unref(reply);
}

static DBusHandlerResult create_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct pending_req *pr;
	DBusError derr;
	const char *addr;
	bdaddr_t src, dst;
	uint32_t cls = 0;
	int dev_id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Get the default adapter */
	dev_id = hci_get_route(NULL);
	if (dev_id < 0) {
		error("Bluetooth adapter not available");
		return err_failed(conn, msg, "Adapter not available");
	}

	if (hci_devba(dev_id, &src) < 0) {
		error("Can't get local adapter device info");
		return err_failed(conn, msg, "Adapter not available");
	}

	str2ba(addr, &dst);
	if (input_device_is_registered(&src, &dst))
		return err_already_exists(conn, msg, "Input Already exists");

	if (read_device_class(&src, &dst, &cls) < 0) {
		error("Device class not available");
		return err_not_supported(conn, msg);
	}

	pr = pending_req_new(conn, msg, &src, &dst);
	if (!pr)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	switch (cls & 0x1f00) {
		case 0x0500: /* Peripheral */
		case 0x0200: /* Phone */
			if (get_handles(pr, pnp_uuid, pnp_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		case 0x0400: /* Fake input */
			if (get_handles(pr, headset_uuid,
						headset_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		default:
			pending_req_free(pr);
			return err_not_supported(conn, msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult remove_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	GSList *l;
	const char *path;
	int err;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(device_paths, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg, "Input doesn't exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	err = input_device_unregister(conn, path);
	if (err < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, strerror(-err));
	}

	g_free(l->data);
	device_paths = g_slist_remove(device_paths, l->data);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_devices(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, iter_array;
	DBusMessage *reply;
	GSList *paths;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (paths = device_paths; paths != NULL; paths = paths->next) {
		const char *ppath = paths->data;
		dbus_message_iter_append_basic(&iter_array,
					DBUS_TYPE_STRING, &ppath);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return send_message_and_unref(conn, reply);
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	info("Unregistered manager path");

	g_slist_foreach(device_paths, (GFunc) free, NULL);

	g_slist_free(device_paths);
}

/*
 * Stored inputs registration functions
 */

static void stored_input(char *key, char *value, void *data)
{
	const char *path;
	struct hidp_connadd_req hidp; 
	bdaddr_t dst, *src = data;

	str2ba(key, &dst);

	memset(&hidp, 0, sizeof(struct hidp_connadd_req));

	if (parse_stored_device_info(value, &hidp) < 0)
		return;

	/*
	 * Repeated entries for the same remote device are
	 * acceptable since the source is different.
	 */
	if (input_device_register(connection, src, &dst, &hidp, &path) < 0)
		goto cleanup;

	device_paths = g_slist_append(device_paths, g_strdup(path));
cleanup:
	if (hidp.rd_data)
		g_free(hidp.rd_data);
}

/* hidd to input transition function */
static void stored_hidd(char *key, char *value, void *data)
{
	struct hidp_connadd_req hidp; 
	char *str, filename[PATH_MAX + 1], addr[18];
	bdaddr_t dst, *src = data;

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "input");

	str = textfile_get(filename, key);
	if (str) {
		/* Skip: entry found in input file */
		free(str);
		return;
	}

	memset(&hidp, 0, sizeof(struct hidp_connadd_req));

	if (parse_stored_hidd(value, &hidp) < 0)
		return;

	str2ba(key, &dst);
	store_device_info(src, &dst, &hidp);
	if (hidp.rd_data)
		g_free(hidp.rd_data);
}

static void register_stored_inputs(void)
{
	char dirname[PATH_MAX + 1];
	char filename[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;
	bdaddr_t src;

	snprintf(dirname, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		str2ba(de->d_name, &src);

		/* move the hidd entries to the input storage */
		create_name(filename, PATH_MAX, STORAGEDIR,
						de->d_name, "hidd");
		textfile_foreach(filename, stored_hidd, &src);

		/* load the input stored devices */
		create_name(filename, PATH_MAX, STORAGEDIR,
						de->d_name, "input");

		textfile_foreach(filename, stored_input, &src);
	}

	closedir(dir);
}

static DBusMethodVTable manager_methods[] = {
	{ "ListDevices",	list_devices,	"",	"as"	},
	{ "CreateDevice",	create_device,	"s",	"s"	},
	{ "RemoveDevice",	remove_device,	"s",	""	},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable manager_signals[] = {
	{ "DeviceCreated",	"s"	},
	{ "DeviceRemoved",	"s"	},
	{ NULL, NULL }
};

int input_init(DBusConnection *conn)
{
	dbus_connection_set_exit_on_disconnect(conn, TRUE);

	if (!dbus_connection_create_object_path(conn, INPUT_PATH,
						NULL, manager_unregister)) {
		error("D-Bus failed to register %s path", INPUT_PATH);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, INPUT_PATH,
						INPUT_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL)) {
		error("Failed to register %s interface to %s",
				INPUT_MANAGER_INTERFACE, INPUT_PATH);
		dbus_connection_destroy_object_path(connection, INPUT_PATH);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	info("Registered input manager path:%s", INPUT_PATH);

	/* Register well known HID devices */
	register_stored_inputs();

	server_start(connection);

	return 0;
}

void input_exit(void)
{
	dbus_connection_destroy_object_path(connection, INPUT_PATH);

	server_stop();

	dbus_connection_unref(connection);

	connection = NULL;
}
