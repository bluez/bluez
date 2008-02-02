/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "hcid.h"
#include "dbus-common.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "dbus-error.h"
#include "error.h"
#include "dbus-test.h"

#define L2INFO_TIMEOUT (2 * 1000)

enum {
	AUDIT_STATE_MTU = 0,
	AUDIT_STATE_FEATURES
};

struct audit {
	bdaddr_t peer;
	bdaddr_t local;

	/* We need to store the path instead of a pointer to the data
	 * because by the time the audit is processed the adapter
	 * might have gotten removed. Storing only the path allows us to
	 * detect this scenario */
	char adapter_path[PATH_MAX];

	char *requestor;
	DBusConnection *conn;

	GIOChannel *io;
	guint io_id;

	guint timeout;

	int state;

	uint16_t mtu_result;
	uint16_t mtu;

	uint16_t mask_result;
	uint32_t mask;
};

static GSList *audits = NULL;

static gboolean l2raw_connect_complete(GIOChannel *io, GIOCondition cond,
					struct audit *audit);

static struct audit *audit_new(DBusConnection *conn, DBusMessage *msg,
				bdaddr_t *peer, bdaddr_t *local)
{
	struct audit *audit;
	const char *path;
	const char *requestor;

	path = dbus_message_get_path(msg);
	requestor = dbus_message_get_sender(msg);

	audit = g_new0(struct audit, 1);

	audit->requestor = g_strdup(requestor);

	bacpy(&audit->peer, peer);
	bacpy(&audit->local, local);
	strncpy(audit->adapter_path, path, sizeof(audit->adapter_path) - 1);
	audit->conn = dbus_connection_ref(conn);

	return audit;
}

static void audit_free(struct audit *audit)
{
	g_free(audit->requestor);
	dbus_connection_unref(audit->conn);
	g_free(audit);
}

static void send_audit_status(struct audit *audit, const char *name)
{
	char addr[18], *addr_ptr = addr;

	ba2str(&audit->peer, addr);

	dbus_connection_emit_signal(audit->conn, audit->adapter_path,
					TEST_INTERFACE, name,
					DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);
}

static void audit_requestor_exited(const char *name, struct audit *audit)
{
	debug("AuditRemoteDevice requestor %s exited", name);
	audits = g_slist_remove(audits, audit);
	if (audit->io) {
		struct adapter *adapter = NULL;

		send_audit_status(audit, "AuditRemoteDeviceComplete");

		dbus_connection_get_object_user_data(audit->conn,
							audit->adapter_path,
							(void *) &adapter);
		if (adapter)
			bacpy(&adapter->agents_disabled, BDADDR_ANY);

		g_io_channel_close(audit->io);
	}
	if (audit->timeout)
		g_source_remove(audit->timeout);
	audit_free(audit);
}

int audit_addr_cmp(const void *a, const void *b)
{
	const struct audit *audit = a;
	const bdaddr_t *addr = b;

	return bacmp(&audit->peer, addr);
}

static gboolean audit_in_progress(void)
{
	GSList *l;

	for (l = audits; l != NULL; l = l->next) {
		struct audit *audit = l->data;
		if (audit->io)
			return TRUE;
	}

	return FALSE;
}

static gboolean l2raw_input_timer(struct audit *audit)
{
	error("l2raw_input_timer: Timed out while waiting for input");

	send_audit_status(audit, "AuditRemoteDeviceComplete");

	g_io_channel_close(audit->io);
	audits = g_slist_remove(audits, audit);
	name_listener_remove(audit->conn, audit->requestor,
				(name_cb_t) audit_requestor_exited, audit);
	audit_free(audit);

	return FALSE;
}

static void handle_mtu_response(struct audit *audit, const l2cap_info_rsp *rsp)
{
	audit->mtu_result = btohs(rsp->result);

	switch (audit->mtu_result) {
	case 0x0000:
		audit->mtu = btohs(bt_get_unaligned((uint16_t *) rsp->data));
		debug("Connectionless MTU size is %d", audit->mtu);
		break;
	case 0x0001:
		debug("Connectionless MTU is not supported");
		break;
	}
}

static void handle_features_response(struct audit *audit, const l2cap_info_rsp *rsp)
{
	audit->mask_result = btohs(rsp->result);

	switch (audit->mask_result) {
	case 0x0000:
		audit->mask = btohl(bt_get_unaligned((uint32_t *) rsp->data));
		debug("Extended feature mask is 0x%04x", audit->mask);
		if (audit->mask & 0x01)
			debug("  Flow control mode");
		if (audit->mask & 0x02)
			debug("  Retransmission mode");
		if (audit->mask & 0x04)
			debug("  Bi-directional QoS");
		break;
	case 0x0001:
		debug("Extended feature mask is not supported");
		break;
	}
}

static gboolean l2raw_data_callback(GIOChannel *io, GIOCondition cond, struct audit *audit)
{
	unsigned char buf[48];
	l2cap_cmd_hdr *cmd = (l2cap_cmd_hdr *) buf;
	l2cap_info_req *req = (l2cap_info_req *) (buf + L2CAP_CMD_HDR_SIZE);
	l2cap_info_rsp *rsp = (l2cap_info_rsp *) (buf + L2CAP_CMD_HDR_SIZE);
	int sk, ret, expected;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(io);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	sk = g_io_channel_unix_get_fd(io);

	memset(buf, 0, sizeof(buf));

	if (audit->state == AUDIT_STATE_MTU)
		expected = L2CAP_CMD_HDR_SIZE + L2CAP_INFO_RSP_SIZE + 2;
	else
		expected = L2CAP_CMD_HDR_SIZE + L2CAP_INFO_RSP_SIZE + 4;

	ret = recv(sk, buf, expected, 0);
	if (ret < 0) {
		error("Can't receive info response: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (ret < L2CAP_CMD_HDR_SIZE) {
		error("Too little data for l2cap response");
		goto failed;
	}

	if (cmd->code != L2CAP_INFO_RSP)
		return TRUE;

	if (ret < L2CAP_CMD_HDR_SIZE + L2CAP_INFO_RSP_SIZE) {
		error("Too little data for l2cap info response");
		goto failed;
	}

	switch (audit->state) {
	case AUDIT_STATE_MTU:
		if (rsp->type != htobs(0x0001))
			return TRUE;

		if (audit->timeout) {
			g_source_remove(audit->timeout);
			audit->timeout = 0;
		}

		handle_mtu_response(audit, rsp);

		memset(buf, 0, sizeof(buf));
		cmd->code  = L2CAP_INFO_REQ;
		cmd->ident = 43;
		cmd->len   = htobs(2);
		req->type  = htobs(0x0002);

		if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_REQ_SIZE, 0) < 0) {
			error("Can't send info request:", strerror(errno), errno);
			goto failed;
		}

		audit->timeout = g_timeout_add(L2INFO_TIMEOUT, (GSourceFunc)
						l2raw_input_timer, audit);

		audit->state = AUDIT_STATE_FEATURES;

		return TRUE;

	case AUDIT_STATE_FEATURES:
		if (rsp->type != htobs(0x0002))
			return TRUE;

		if (audit->timeout) {
			g_source_remove(audit->timeout);
			audit->timeout = 0;
		}

		handle_features_response(audit, rsp);
		break;
	}

	write_l2cap_info(&audit->local, &audit->peer,
				audit->mtu_result, audit->mtu,
				audit->mask_result, audit->mask);

failed:
	if (audit->timeout) {
		g_source_remove(audit->timeout);
		audit->timeout = 0;
	}

	send_audit_status(audit, "AuditRemoteDeviceComplete");

	g_io_channel_close(io);
	g_io_channel_unref(io);
	audits = g_slist_remove(audits, audit);
	name_listener_remove(audit->conn, audit->requestor,
				(name_cb_t) audit_requestor_exited, audit);

	process_audits_list(audit->adapter_path);

	audit_free(audit);

	return FALSE;
}

static gboolean l2raw_connect_complete(GIOChannel *io, GIOCondition cond, struct audit *audit)
{
	unsigned char buf[48];
	l2cap_cmd_hdr *cmd = (l2cap_cmd_hdr *) buf;
	l2cap_info_req *req = (l2cap_info_req *) (buf + L2CAP_CMD_HDR_SIZE);
	socklen_t len;
	int sk, ret;
	struct adapter *adapter = NULL;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(io);
		return FALSE;
	}

	dbus_connection_get_object_user_data(audit->conn, audit->adapter_path,
						(void *) &adapter);
	if (adapter)
		bacpy(&adapter->agents_disabled, BDADDR_ANY);

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Error on raw l2cap socket");
		goto failed;
	}

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		error("Can't get socket error: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (ret != 0) {
		error("l2raw_connect failed: %s (%d)", strerror(ret), ret);
		goto failed;
	}

	debug("AuditRemoteDevice: connected");

	/* Send L2CAP info request */
	memset(buf, 0, sizeof(buf));
	cmd->code  = L2CAP_INFO_REQ;
	cmd->ident = 42;
	cmd->len   = htobs(2);
	req->type  = htobs(0x0001);

	if (send(sk, buf, L2CAP_CMD_HDR_SIZE + L2CAP_INFO_REQ_SIZE, 0) < 0) {
		error("Can't send info request: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	audit->timeout = g_timeout_add(L2INFO_TIMEOUT, (GSourceFunc)
			l2raw_input_timer, audit);

	audit->io_id = g_io_add_watch(audit->io,
					G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
					(GIOFunc) l2raw_data_callback, audit);

	return FALSE;

failed:
	send_audit_status(audit, "AuditRemoteDeviceFailed");

	g_io_channel_close(io);
	g_io_channel_unref(io);
	audits = g_slist_remove(audits, audit);
	name_listener_remove(audit->conn, audit->requestor,
				(name_cb_t) audit_requestor_exited, audit);
	audit_free(audit);

	return FALSE;
}

static DBusHandlerResult audit_remote_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError err;
	bdaddr_t peer, local;
	const char *address;
	struct audit *audit;
	struct adapter *adapter = data;
	gboolean queue;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg, NULL);
	}

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(address, &peer);
	str2ba(adapter->address, &local);

	pending_remote_name_cancel(adapter);

	if (adapter->bonding)
		return error_bonding_in_progress(conn, msg);

	if (g_slist_find_custom(adapter->pin_reqs, &peer, pin_req_cmp))
		return error_bonding_in_progress(conn, msg);

	if (!read_l2cap_info(&local, &peer, NULL, NULL, NULL, NULL))
		return error_audit_already_exists(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Just return if an audit for the same device is already queued */
	if (g_slist_find_custom(audits, &peer, audit_addr_cmp))
		return send_message_and_unref(conn, reply);

	if (adapter->discov_active || (adapter->pdiscov_active && !adapter->pinq_idle))
		queue = TRUE;
	else
		queue = audit_in_progress();

	audit = audit_new(conn, msg, &peer, &local);
	if (!audit) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!queue) {
		int sk;

		sk = l2raw_connect(adapter->address, &peer);
		if (sk < 0) {
			audit_free(audit);
			dbus_message_unref(reply);
			return error_connection_attempt_failed(conn, msg, 0);
		}

		bacpy(&adapter->agents_disabled, &peer);

		audit->io = g_io_channel_unix_new(sk);
		audit->io_id = g_io_add_watch(audit->io,
						G_IO_OUT | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						(GIOFunc) l2raw_connect_complete, audit);
	}

	name_listener_add(conn, dbus_message_get_sender(msg),
				(name_cb_t) audit_requestor_exited, audit);

	audits = g_slist_append(audits, audit);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult cancel_audit_remote_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	DBusError err;
	const char *address;
	bdaddr_t peer, local;
	GSList *l;
	struct audit *audit;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg, NULL);
	}

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(address, &peer);
	str2ba(adapter->address, &local);

	l = g_slist_find_custom(audits, &peer, audit_addr_cmp);
	if (!l)
		return error_not_in_progress(conn, msg, "Audit not in progress");

	audit = l->data;

	/* Check that the audit wasn't for another adapter */
	if (bacmp(&audit->local, &local))
		return error_not_in_progress(conn, msg, "Audit not in progress");

	if (strcmp(audit->requestor, dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	if (audit->io) {
		send_audit_status(audit, "AuditRemoteDeviceComplete");
		bacpy(&adapter->agents_disabled, BDADDR_ANY);
		g_io_channel_close(audit->io);
	}
	if (audit->timeout)
		g_source_remove(audit->timeout);

	audits = g_slist_remove(audits, audit);
	name_listener_remove(audit->conn, audit->requestor,
				(name_cb_t) audit_requestor_exited, audit);
	audit_free(audit);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_l2cap_feature_mask(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	DBusError err;
	const char *address;
	bdaddr_t peer, local;
	uint32_t mask;
	uint16_t result;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg, NULL);
	}

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(address, &peer);
	str2ba(adapter->address, &local);

	if (read_l2cap_info(&local, &peer, NULL, NULL, &result, &mask) < 0)
		return error_not_available(conn, msg);

	if (result)
		return error_not_supported(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &mask,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_l2cap_mtu_size(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	DBusMessage *reply;
	DBusError err;
	const char *address;
	bdaddr_t peer, local;
	uint16_t result, mtu;

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg, NULL);
	}

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	str2ba(address, &peer);
	str2ba(adapter->address, &local);

	if (read_l2cap_info(&local, &peer, &result, &mtu, NULL, NULL) < 0)
		return error_not_available(conn, msg);

	if (result)
		return error_not_supported(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &mtu,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable test_methods[] = {
	{ "AuditRemoteDevice",		audit_remote_device,
		"s",	""	},
	{ "CancelAuditRemoteDevice",	cancel_audit_remote_device,
		"s",	""	},
	{ "GetL2capFeatureMask",	get_l2cap_feature_mask,
		"s",	"u"	},
	{ "GetL2capMtuSize",		get_l2cap_mtu_size,
		"s",	"q"	},
	{ NULL, NULL, NULL, NULL }
};

dbus_bool_t test_init(DBusConnection *conn, const char *path)
{
	if (!hcid_dbus_use_experimental())
		return TRUE;

	return dbus_connection_register_interface(conn, path, TEST_INTERFACE,
							test_methods,
							NULL, NULL);
}

void process_audits_list(const char *adapter_path)
{
	GSList *l, *next;

	for (l = audits; l != NULL; l = next) {
		struct adapter *adapter;
		struct audit *audit;
		int sk;

		audit = l->data;
		next = l->next;

		if (strcmp(adapter_path, audit->adapter_path))
			continue;

		if (audit->io)
			return;

		adapter = NULL;

		dbus_connection_get_object_user_data(audit->conn,
							audit->adapter_path,
							(void *) &adapter);

		if (!adapter) {
			audits = g_slist_remove(audits, audit);
			name_listener_remove(audit->conn, audit->requestor,
					(name_cb_t) audit_requestor_exited, audit);
			audit_free(audit);
			continue;
		}

		if (adapter->discov_active || (adapter->pdiscov_active
					&& !adapter->pinq_idle))
			continue;

		sk = l2raw_connect(adapter->address, &audit->peer);
		if (sk < 0) {
			send_audit_status(audit, "AuditRemoteDeviceFailed");
			audits = g_slist_remove(audits, audit);
			name_listener_remove(audit->conn, audit->requestor,
					(name_cb_t) audit_requestor_exited, audit);
			audit_free(audit);
			continue;
		}

		bacpy(&adapter->agents_disabled, &audit->peer);

		audit->io = g_io_channel_unix_new(sk);
		audit->io_id = g_io_add_watch(audit->io,
						G_IO_OUT | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						(GIOFunc) l2raw_connect_complete, audit);
		return;
	}
}
