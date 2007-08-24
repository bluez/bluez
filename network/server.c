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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/bnep.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"
#include "error.h"
#include "textfile.h"
#include "dbus-helper.h"

#define NETWORK_SERVER_INTERFACE "org.bluez.network.Server"

#include "bridge.h"
#include "common.h"
#include "manager.h"
#include "server.h"

static GIOChannel *bnep_io = NULL;

/* Pending Authorization */
struct pending_auth {
	char			*addr;		/* Bluetooth Address */
	GIOChannel		*io;		/* BNEP connection setup io channel */
	int			attempts;	/* BNEP setup conn requests counter */
};

/* Main server structure */
struct network_server {
	bdaddr_t		src;		/* Bluetooth Local Address */
	char			*iface;		/* Routing interface */
	char			*name;		/* Server service name */
	char			*range;		/* IP Address range */
	char			*path;		/* D-Bus path */
	gboolean		enable;		/* Enable flag*/
	gboolean		secure;		/* Security flag*/
	uint32_t		record_id;	/* Service record id */
	uint16_t		id;		/* Service class identifier */
	DBusConnection		*conn;		/* D-Bus connection */
	struct pending_auth	*pauth;		/* Pending incomming connection/authorization */
};

static char netdev[16] = "bnep%d";

static int store_property(bdaddr_t *src, uint16_t id,
			const char *key, const char *value)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	ba2str(src, addr);
	if (id == BNEP_SVC_NAP)
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "nap");
	else if (id == BNEP_SVC_GN)
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "gn");
	else if (id == BNEP_SVC_PANU)
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "panu");

	return textfile_put(filename, key, value);
}

static void pending_auth_free(struct pending_auth *pauth)
{
	if (!pauth)
		return;
	if (pauth->addr)
		g_free(pauth->addr);
	if (pauth->io) {
		g_io_channel_close(pauth->io);
		g_io_channel_unref(pauth->io);
	}
	g_free(pauth);
}

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

static int create_server_record(sdp_buf_t *buf, const char *name,
					uint16_t id, dbus_bool_t secure)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, pan, l2cap, bnep;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];
	sdp_data_t *v, *p;
	uint16_t psm = BNEP_PSM, version = 0x0100;
	uint16_t security_desc = (secure ? 0x0001 : 0x0000);
	uint16_t net_access_type = 0xfffe;
	uint32_t max_net_access_rate = 0;
	const char *desc = "BlueZ PAN service";
	sdp_record_t record;
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	p = sdp_data_alloc(SDP_UINT16, &psm);
	proto[0] = sdp_list_append(proto[0], p);
	apseq    = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&bnep, BNEP_UUID);
	proto[1] = sdp_list_append(NULL, &bnep);
	v = sdp_data_alloc(SDP_UINT16, &version);
	proto[1] = sdp_list_append(proto[1], v);

	/* Supported protocols */
	{
		uint16_t ptype[] = { 
			0x0800,  /* IPv4 */
			0x0806,  /* ARP */
		};
		sdp_data_t *head, *pseq;
		int p;

		for (p = 0, head = NULL; p < 2; p++) {
			sdp_data_t *data = sdp_data_alloc(SDP_UINT16, &ptype[p]);
			if (head)
				sdp_seq_append(head, data);
			else
				head = data;
		}
		pseq = sdp_data_alloc(SDP_SEQ16, head);
		proto[1] = sdp_list_append(proto[1], pseq);
	}

	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(&record, aproto);

	add_lang_attr(&record);

	sdp_attr_add_new(&record, SDP_ATTR_SECURITY_DESC,
				SDP_UINT16, &security_desc);

	if (id == BNEP_SVC_NAP) {
		sdp_uuid16_create(&pan, NAP_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(&record, svclass);

		sdp_uuid16_create(&profile[0].uuid, NAP_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(&record, pfseq);

		sdp_set_info_attr(&record, name, NULL, desc);

		sdp_attr_add_new(&record, SDP_ATTR_NET_ACCESS_TYPE,
					SDP_UINT16, &net_access_type);
		sdp_attr_add_new(&record, SDP_ATTR_MAX_NET_ACCESSRATE,
					SDP_UINT32, &max_net_access_rate);
	} else {
		/* BNEP_SVC_GN */
		sdp_uuid16_create(&pan, GN_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(&record, svclass);

		sdp_uuid16_create(&profile[0].uuid, GN_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(&record, pfseq);
		
		sdp_set_info_attr(&record, name, NULL, desc);
	}

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(p);
	sdp_data_free(v);
	sdp_list_free(apseq, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(svclass, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static int send_bnep_ctrl_rsp(GIOChannel *chan, uint16_t response)
{
	struct bnep_control_rsp rsp;
	GIOError gerr;
	gsize n;

	rsp.type = BNEP_CONTROL;
	rsp.ctrl = BNEP_SETUP_CONN_RSP;
	rsp.resp = htons(response);

	gerr = g_io_channel_write(chan, (gchar *)&rsp, sizeof(rsp), &n);

	return -gerr;
}

static void cancel_authorization(struct network_server *ns)
{
	DBusMessage *msg;
	const char *paddress;
	const char *uuid = "";

	if (!ns->pauth)
		return;

	paddress = ns->pauth->addr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!msg) {
		error("Unable to allocate new method call");
		return;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddress,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	send_message_and_unref(ns->conn, msg);
}

static void authorization_callback(DBusPendingCall *pcall, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(pcall);
	char devname[16];
	DBusError derr;
	uint16_t response;
	int sk;

	if (!ns->pauth) {
		dbus_message_unref(reply);
		dbus_pending_call_unref(pcall);
		return;
	}

	sk = g_io_channel_unix_get_fd(ns->pauth->io);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Access denied: %s", derr.message);
		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			cancel_authorization(ns);
		}
		response = BNEP_CONN_NOT_ALLOWED;
		dbus_error_free(&derr);
		goto failed;
	}

	memset(devname, 0, 16);
	strncpy(devname, netdev, 16);

	if (bnep_connadd(sk, ns->id, devname) < 0) {
		response = BNEP_CONN_NOT_ALLOWED;
		goto failed;
	}

	info("Authorization succedded. New connection: %s", devname);
	response = BNEP_SUCCESS;

	if (bridge_add_interface("pan0", devname) < 0) {
		error("Can't add %s to the bridge: %s(%d)",
				devname, strerror(errno), errno);
		response = BNEP_CONN_NOT_ALLOWED;
		goto failed;
	}

	bnep_if_up(devname, TRUE);
	bnep_if_up("pan0", TRUE);

	/* FIXME: Enable routing if applied */

	/* FIXME: send the D-Bus message to notify the new bnep iface */

failed:
	send_bnep_ctrl_rsp(ns->pauth->io, response);

	pending_auth_free(ns->pauth);
	ns->pauth = NULL;

	close(sk);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pcall);
}

static int authorize_connection(struct network_server *ns)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *uuid = ""; /* FIXME: */

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RequestAuthorization");
	if (!msg) {
		error("Unable to allocat new RequestAuthorization method call");
		return -ENOMEM;
	}

	debug("Requesting authorization for %s UUID:%s", ns->pauth->addr, uuid);

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &ns->pauth->addr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(ns->conn, msg, &pending, -1) == FALSE) {
		error("Sending of authorization request failed");
		return -EACCES;
	}

	dbus_pending_call_set_notify(pending, authorization_callback, ns, NULL);
	dbus_message_unref(msg);

	return 0;
}

static gboolean connect_setup_event(GIOChannel *chan,
					GIOCondition cond, gpointer data)
{
	struct network_server *ns = data;
	struct bnep_setup_conn_req *req;
	unsigned char pkt[BNEP_MTU];
	gsize n;
	GIOError gerr;
	uint8_t *pservice;
	uint16_t role, response;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Hangup or error on BNEP socket");
		cancel_authorization(ns);
		return FALSE;
	}

	gerr = g_io_channel_read(chan, (gchar *)pkt, sizeof(pkt) - 1, &n);
	if (gerr != G_IO_ERROR_NONE)
		return FALSE;

	if (n < sizeof(*req)) {
		error("Invalid BNEP packet size");
		return FALSE;
	}

	req = (void *)pkt;
	if (req->type != BNEP_CONTROL || req->ctrl != BNEP_SETUP_CONN_REQ) {
		error("Invalid BNEP control packet content");
		return FALSE;
	}

	if (++ns->pauth->attempts > 1) {
		/*
		 * Ignore repeated BNEP setup connection request: there
		 * is a pending authorization request for this device.
		 */
		return TRUE;
	}

	/* 
	 * FIXME: According to BNEP SPEC the UUID size can be
	 * 2-16 bytes. Currently only 2 bytes size is supported
	 */
	if (req->uuid_size != 2) {
		response = BNEP_CONN_INVALID_SVC; 
		goto reply;
	}

	pservice = req->service;
	/* Getting destination service: considering 2 bytes size */
	role = ntohs(bt_get_unaligned((uint16_t *) pservice));

	pservice += req->uuid_size;
	/* Getting source service: considering 2 bytes size */
	role = ntohs(bt_get_unaligned((uint16_t *) pservice));

	/*
	 * FIXME: Check if the connection already exists. Check if the
	 * BNEP SPEC allows return "connection not allowed" for this case
	 */

	/* Wait authorization before reply success */
	if (authorize_connection(ns) < 0) {
		response = BNEP_CONN_NOT_ALLOWED;
		goto reply;

	}

	return TRUE;
reply:
	send_bnep_ctrl_rsp(chan, response);
	return FALSE;
}

static void connect_setup_destroy(gpointer data)
{
	struct network_server *ns = data;

	if (ns->pauth) {
		pending_auth_free(ns->pauth);
		ns->pauth = NULL;
	}
}

static gboolean connect_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	struct network_server *ns = data;
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	char peer[18];
	bdaddr_t dst;
	unsigned short psm;
	int sk, nsk;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Hangup or error on L2CAP socket PSM 15");
		g_io_channel_close(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &addrlen);
	if (nsk < 0)
		return TRUE;

	bacpy(&dst, &addr.l2_bdaddr);
	psm = btohs(addr.l2_psm);

	/* FIXME: Maybe keep a list of connected devices */

	ba2str(&dst, peer);
	if (ns->pauth) {
		GIOChannel *io;
		error("Rejecting %s(pending authorization)", peer);
		io = g_io_channel_unix_new(nsk);
		send_bnep_ctrl_rsp(io, BNEP_CONN_NOT_ALLOWED);
		g_io_channel_close(io);
		g_io_channel_unref(io);
		return TRUE;
	}

	info("Connection from:%s on PSM %d", peer, psm);

	/* Setting the pending incomming connection setup */
	ns->pauth = g_new0(struct pending_auth, 1);
	ns->pauth->addr = g_strdup(peer);
	ns->pauth->io = g_io_channel_unix_new(nsk);

	g_io_channel_set_close_on_unref(ns->pauth->io, FALSE);

	/* New watch for BNEP setup */
	g_io_add_watch_full(ns->pauth->io, G_PRIORITY_DEFAULT,
		G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
		connect_setup_event, ns, &connect_setup_destroy);

	return TRUE;
}

int server_init(struct network_server *ns)
{
	struct l2cap_options l2o;
	struct sockaddr_l2 l2a;
	socklen_t olen;
	int sk, lm, err;

	/* Create L2CAP socket and bind it to PSM BNEP */
	sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		err = errno;
		error("Cannot create L2CAP socket. %s(%d)",
					strerror(err), err);
		return -err;
	}

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, BDADDR_ANY);
	l2a.l2_psm = htobs(BNEP_PSM);

	if (bind(sk, (struct sockaddr *) &l2a, sizeof(l2a))) {
		err = errno;
		error("Bind failed. %s(%d)", strerror(err), err);
		goto fail;
	}

	/* Setup L2CAP options according to BNEP spec */
	memset(&l2o, 0, sizeof(l2o));
	olen = sizeof(l2o);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &olen) < 0) {
		err = errno;
		error("Failed to get L2CAP options. %s(%d)",
					strerror(err), err);
		goto fail;
	}

	l2o.imtu = l2o.omtu = BNEP_MTU;
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o)) < 0) {
		err = errno;
		error("Failed to set L2CAP options. %s(%d)",
					strerror(err), err);
		goto fail;
	}

	/* Set link mode */
	lm = (ns->secure ? L2CAP_LM_SECURE : 0);
	if (lm && setsockopt(sk, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm)) < 0) {
		err = errno;
		error("Failed to set link mode. %s(%d)",
					strerror(err), err);
		goto fail;
	}

	if (listen(sk, 1) < 0) {
		err = errno;
		error("Listen failed. %s(%d)", strerror(err), err);
		goto fail;
	}

	bnep_io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(bnep_io, FALSE);

	g_io_add_watch(bnep_io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							connect_event, ns);

	return 0;
fail:

	close(sk);
	errno = err;
	return -err;
}

static uint32_t add_server_record(struct network_server *ns)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;
	sdp_buf_t buf;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	if (create_server_record(&buf, ns->name, ns->id, ns->secure) < 0) {
		error("Unable to allocate new service record");
		dbus_message_unref(msg);
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&buf.data, buf.data_size, DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(ns->conn, msg, -1, &derr);

	free(buf.data);
	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) || dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr, DBUS_TYPE_UINT32, &rec_id,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s", derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	debug("add_server_record: got record id 0x%x", rec_id);

	return rec_id;
}

static int update_server_record(struct network_server *ns)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	sdp_buf_t buf;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "UpdateServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return -ENOMEM;
	}

	if (create_server_record(&buf, ns->name, ns->id, ns->secure) < 0) {
		error("Unable to allocate new service record");
		dbus_message_unref(msg);
		return -1;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_UINT32, &ns->record_id,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&buf.data, buf.data_size, DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(ns->conn, msg, -1, &derr);

	free(buf.data);
	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) || dbus_set_error_from_message(&derr, reply)) {
		error("Update service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return -1;
	}

	dbus_message_unref(reply);

	return 0;
}

static int remove_server_record(DBusConnection *conn, uint32_t rec_id)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return -ENOMEM;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_UINT32, &rec_id,
			DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		error("Removing service record 0x%x failed: %s",
						rec_id, derr.message);
		dbus_error_free(&derr);
		return -1;
	}

	dbus_message_unref(reply);

	return 0;
}

static DBusHandlerResult get_uuid(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	const char *uuid;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	uuid = bnep_uuid(ns->id);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static int record_and_listen(struct network_server *ns)
{
	int err;

	/* Add the service record */
	ns->record_id = add_server_record(ns);
	if (!ns->record_id) {
		error("Unable to register the server(0x%x) service record", ns->id);
		return -EIO;
	}

	if (bnep_io == NULL && (err = server_init(ns)) < 0)
		return -err;

	return 0;
}

static DBusHandlerResult enable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	int err;

	if (ns->enable)
		return err_already_exists(conn, msg, "Server already enabled");

	if (bacmp(&ns->src, BDADDR_ANY) == 0) {
		int dev_id;

		dev_id = hci_get_route(NULL);
		if ((dev_id < 0) || (hci_devba(dev_id, &ns->src) < 0))
			return err_failed(conn, msg, "Adapter not available");

		/* Store the server info */
		server_store(conn, ns->path);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Add the service record and listen l2cap */
	if ((err = record_and_listen(ns)) < 0)
		return err_failed(conn, msg, strerror(-err));

	store_property(&ns->src, ns->id, "enabled", "1");

	dbus_connection_emit_signal(conn, ns->path, NETWORK_SERVER_INTERFACE,
					"Enabled", DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult disable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!ns->enable)
		return err_failed(conn, msg, "Not enabled");

	/* Remove the service record */
	if (ns->record_id) {
		remove_server_record(conn, ns->record_id);
		ns->record_id = 0;
	}

	ns->enable = FALSE;

	store_property(&ns->src, ns->id, "enabled", "0");

	dbus_connection_emit_signal(conn, ns->path, NETWORK_SERVER_INTERFACE,
					"Disabled", DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	const char *name;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (!name || (strlen(name) == 0))
		return err_invalid_args(conn, msg, "Invalid name");

	if (ns->name)
		g_free(ns->name);
	ns->name = g_strdup(name);

	if (ns->enable) {
		if (update_server_record(ns) < 0) {
			dbus_message_unref(reply);
			return err_failed(conn, msg,
				"Service record attribute update failed");
		}
	}

	store_property(&ns->src, ns->id, "name", ns->name);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	char name[] = "";
	const char *pname = (ns->name ? ns->name : name);
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_address_range(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult set_routing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	const char *iface;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &iface,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* FIXME: Check if the interface is valid/UP */
	if (!iface || (strlen(iface) == 0))
		return err_invalid_args(conn, msg, "Invalid interface");

	if (ns->iface)
		g_free(ns->iface);
	ns->iface = g_strdup(iface);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_security(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	dbus_bool_t secure;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_BOOLEAN, &secure,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	ns->secure = secure;
	if (ns->enable) {
		if (update_server_record(ns) < 0) {
			dbus_message_unref(reply);
			return err_failed(conn, msg,
				"Service record attribute update failed");
		}
	}

	store_property(&ns->src, ns->id, "secure", "1");

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_security(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &ns->secure,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_info(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *uuid;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "name",
			DBUS_TYPE_STRING, &ns->name);

	uuid = bnep_uuid(ns->id);
	dbus_message_iter_append_dict_entry(&dict, "uuid",
			DBUS_TYPE_STRING, &uuid);

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static void server_free(struct network_server *ns)
{
	if (!ns)
		return;

	/* FIXME: Missing release/free all bnepX interfaces */
	if (ns->record_id)
		remove_server_record(ns->conn, ns->record_id);

	if (ns->iface)
		g_free(ns->iface);

	if (ns->name)
		g_free(ns->name);

	if (ns->range)
		g_free(ns->range);

	if (ns->path)
		g_free(ns->path);

	if (ns->conn)
		dbus_connection_unref(ns->conn);

	g_free(ns);
}

static void server_unregister(DBusConnection *conn, void *data)
{
	struct network_server *ns = data;

	info("Unregistered server path:%s", ns->path);

	server_free(ns);

	if (bnep_io != NULL) {
		g_io_channel_close(bnep_io);
		g_io_channel_unref(bnep_io);
		bnep_io = NULL;
	}
}

static DBusMethodVTable server_methods[] = {
	{ "GetUUID",		get_uuid,		"",	"s"	},
	{ "Enable",		enable,			"",	""	},
	{ "Disable",		disable,		"",	""	},
	{ "SetName",		set_name,		"s",	""	},
	{ "GetName",		get_name,		"",	"s"	},
	{ "SetAddressRange",	set_address_range,	"ss",	""	},
	{ "SetRouting",		set_routing,		"s",	""	},
	{ "SetSecurity",	set_security,		"b",	""	},
	{ "GetSecurity",	get_security,		"",	"b"	},
	{ "GetInfo",		get_info,		"",	"{sv}"	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable server_signals[] = {
	{ "Enabled",	""	},
	{ "Disabled",	""	},
	{ NULL, NULL }
};

int server_register(DBusConnection *conn, const char *path,
					bdaddr_t *src, uint16_t id)
{
	struct network_server *ns;

	if (!conn || !path)
		return -EINVAL;

	ns = g_new0(struct network_server, 1);

	if (!dbus_connection_create_object_path(conn, path, ns,
						server_unregister)) {
		error("D-Bus failed to register %s path", path);
		server_free(ns);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, path,
						NETWORK_SERVER_INTERFACE,
						server_methods,
						server_signals, NULL)) {
		error("D-Bus failed to register %s interface",
				NETWORK_SERVER_INTERFACE);
		dbus_connection_destroy_object_path(conn, path);
		return -1;
	}

	/* Setting a default name */
	if (id == BNEP_SVC_NAP)
		ns->name = g_strdup("BlueZ NAP service");
	else if (id == BNEP_SVC_GN)
		ns->name = g_strdup("BlueZ GN service");
	else
		ns->name = g_strdup("BlueZ PANU service");

	ns->path = g_strdup(path);
	ns->id = id;
	ns->conn = dbus_connection_ref(conn);
	bacpy(&ns->src, src);

	info("Registered server path:%s", path);

	return 0;
}

int server_register_from_file(DBusConnection *conn, const char *path,
		const bdaddr_t *src, uint16_t id, const char *filename)
{
	struct network_server *ns;
	char *str;

	ns = g_new0(struct network_server, 1);

	if (!dbus_connection_create_object_path(conn, path, ns,
						server_unregister)) {
		error("D-Bus failed to register %s path", path);
		server_free(ns);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, path,
						NETWORK_SERVER_INTERFACE,
						server_methods,
						server_signals, NULL)) {
		error("D-Bus failed to register %s interface",
				NETWORK_SERVER_INTERFACE);
		dbus_connection_destroy_object_path(conn, path);
		return -1;
	}

	bacpy(&ns->src, src);
	ns->path = g_strdup(path);
	ns->id = id;
	ns->conn = dbus_connection_ref(conn);
	ns->name = textfile_get(filename, "name");
	if (!ns->name) {
		/* Name is mandatory */
		server_free(ns);
		return -1;
	}

	ns->secure = FALSE;
	str = textfile_get(filename, "secure");
	if (str) {
		if (strcmp("1", str) == 0)
			ns->secure = TRUE;
		g_free(str);
	}

	ns->range = textfile_get(filename, "address_range");
	ns->iface = textfile_get(filename, "routing");

	info("Registered server path:%s", path);

	str = textfile_get(filename, "enabled");
	if (str) {
		if (strcmp("1", str) == 0)
			record_and_listen(ns);
		g_free(str);
	}

	return 0;
}

int server_store(DBusConnection *conn, const char *path)
{
	struct network_server *ns;
	char filename[PATH_MAX + 1];
	char addr[18];

	if (!dbus_connection_get_object_user_data(conn, path, (void *) &ns))
		return -ENOENT;

	ba2str(&ns->src, addr);
	if (ns->id == BNEP_SVC_NAP)
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "nap");
	else if (ns->id == BNEP_SVC_GN)
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "gn");
	else
		create_name(filename, PATH_MAX, STORAGEDIR, addr, "panu");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	textfile_put(filename, "name", ns->name);

	if (ns->iface)
		textfile_put(filename, "routing", ns->iface);

	if (ns->range)
		textfile_put(filename, "range", ns->range);

	textfile_put(filename, "secure", ns->secure ? "1": "0");

	textfile_put(filename, "enabled", ns->enable ? "1": "0");

	return 0;
}

int server_find_data(DBusConnection *conn,
		const char *path, const char *pattern)
{
	struct network_server *ns;
	const char *uuid;

	if (!dbus_connection_get_object_user_data(conn, path, (void *) &ns))
		return -1;

	if (ns->name && strcasecmp(pattern, ns->name) == 0)
		return 0;

	if (ns->iface && strcasecmp(pattern, ns->iface) == 0)
		return 0;

	uuid = bnep_name(ns->id);
	if (uuid && strcasecmp(pattern, uuid) == 0)
		return 0;

	if (bnep_service_id(pattern) == ns->id)
		return 0;

	return -1;
}
