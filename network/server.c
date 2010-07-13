/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/bnep.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <netinet/in.h>

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"
#include "../src/adapter.h"

#include "log.h"
#include "error.h"
#include "sdpd.h"
#include "btio.h"
#include "glib-helper.h"

#include "common.h"
#include "server.h"

#define NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer"
#define SETUP_TIMEOUT		1

/* Pending Authorization */
struct network_session {
	bdaddr_t	dst;		/* Remote Bluetooth Address */
	GIOChannel	*io;		/* Pending connect channel */
	guint		watch;		/* BNEP socket watch */
};

struct network_adapter {
	struct btd_adapter *adapter;	/* Adapter pointer */
	GIOChannel	*io;		/* Bnep socket */
	struct network_session *setup;	/* Setup in progress */
	GSList		*servers;	/* Server register to adapter */
};

/* Main server structure */
struct network_server {
	bdaddr_t	src;		/* Bluetooth Local Address */
	char		*iface;		/* DBus interface */
	char		*name;		/* Server service name */
	char		*bridge;	/* Bridge name */
	uint32_t	record_id;	/* Service record id */
	uint16_t	id;		/* Service class identifier */
	GSList		*sessions;	/* Active connections */
	struct network_adapter *na;	/* Adapter reference */
	guint		watch_id;	/* Client service watch */
};

static DBusConnection *connection = NULL;
static GSList *adapters = NULL;
static gboolean security = TRUE;

static struct network_adapter *find_adapter(GSList *list,
					struct btd_adapter *adapter)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_adapter *na = l->data;

		if (na->adapter == adapter)
			return na;
	}

	return NULL;
}

static struct network_server *find_server(GSList *list, uint16_t id)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_server *ns = l->data;

		if (ns->id == id)
			return ns;
	}

	return NULL;
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

static sdp_record_t *server_record_new(const char *name, uint16_t id)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, pan, l2cap, bnep;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];
	sdp_data_t *v, *p;
	uint16_t psm = BNEP_PSM, version = 0x0100;
	uint16_t security_desc = (security ? 0x0001 : 0x0000);
	uint16_t net_access_type = 0xfffe;
	uint32_t max_net_access_rate = 0;
	const char *desc = "Network service";
	sdp_record_t *record;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	record->attrlist = NULL;
	record->pattern = NULL;

	switch (id) {
	case BNEP_SVC_NAP:
		sdp_uuid16_create(&pan, NAP_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, NAP_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, name, NULL, desc);

		sdp_attr_add_new(record, SDP_ATTR_NET_ACCESS_TYPE,
					SDP_UINT16, &net_access_type);
		sdp_attr_add_new(record, SDP_ATTR_MAX_NET_ACCESSRATE,
					SDP_UINT32, &max_net_access_rate);
		break;
	case BNEP_SVC_GN:
		sdp_uuid16_create(&pan, GN_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, GN_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, name, NULL, desc);
		break;
	case BNEP_SVC_PANU:
		sdp_uuid16_create(&pan, PANU_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, PANU_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, name, NULL, desc);
		break;
	default:
		sdp_record_free(record);
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

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
	sdp_set_access_protos(record, aproto);

	add_lang_attr(record);

	sdp_attr_add_new(record, SDP_ATTR_SECURITY_DESC,
				SDP_UINT16, &security_desc);

	sdp_data_free(p);
	sdp_data_free(v);
	sdp_list_free(apseq, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(svclass, NULL);
	sdp_list_free(pfseq, NULL);

	return record;
}

static ssize_t send_bnep_ctrl_rsp(int sk, uint16_t val)
{
	struct bnep_control_rsp rsp;

	rsp.type = BNEP_CONTROL;
	rsp.ctrl = BNEP_SETUP_CONN_RSP;
	rsp.resp = htons(val);

	return send(sk, &rsp, sizeof(rsp), 0);
}

static int server_connadd(struct network_server *ns,
				struct network_session *session,
				uint16_t dst_role)
{
	char devname[16];
	int err, nsk;

	memset(devname, 0, sizeof(devname));
	strcpy(devname, "bnep%d");

	nsk = g_io_channel_unix_get_fd(session->io);
	err = bnep_connadd(nsk, dst_role, devname);
	if (err < 0)
		return err;

	info("Added new connection: %s", devname);

	if (bnep_add_to_bridge(devname, ns->bridge) < 0) {
		error("Can't add %s to the bridge %s: %s(%d)",
				devname, ns->bridge, strerror(errno), errno);
		return -EPERM;
	}

	bnep_if_up(devname);

	ns->sessions = g_slist_append(ns->sessions, session);

	return 0;
}

static uint16_t bnep_setup_chk(uint16_t dst_role, uint16_t src_role)
{
	/* Allowed PAN Profile scenarios */
	switch (dst_role) {
	case BNEP_SVC_NAP:
	case BNEP_SVC_GN:
		if (src_role == BNEP_SVC_PANU)
			return 0;
		return BNEP_CONN_INVALID_SRC;
	case BNEP_SVC_PANU:
		if (src_role == BNEP_SVC_PANU ||
				src_role == BNEP_SVC_GN ||
				src_role == BNEP_SVC_NAP)
			return 0;

		return BNEP_CONN_INVALID_SRC;
	}

	return BNEP_CONN_INVALID_DST;
}

static uint16_t bnep_setup_decode(struct bnep_setup_conn_req *req,
				uint16_t *dst_role, uint16_t *src_role)
{
	uint8_t *dest, *source;

	dest = req->service;
	source = req->service + req->uuid_size;

	switch (req->uuid_size) {
	case 2: /* UUID16 */
		*dst_role = ntohs(bt_get_unaligned((uint16_t *) dest));
		*src_role = ntohs(bt_get_unaligned((uint16_t *) source));
		break;
	case 4: /* UUID32 */
	case 16: /* UUID128 */
		*dst_role = ntohl(bt_get_unaligned((uint32_t *) dest));
		*src_role = ntohl(bt_get_unaligned((uint32_t *) source));
		break;
	default:
		return BNEP_CONN_INVALID_SVC;
	}

	return 0;
}

static void session_free(void *data)
{
	struct network_session *session = data;

	if (session->watch)
		g_source_remove(session->watch);

	if (session->io)
		g_io_channel_unref(session->io);

	g_free(session);
}

static void setup_destroy(void *user_data)
{
	struct network_adapter *na = user_data;
	struct network_session *setup = na->setup;

	if (!setup)
		return;

	na->setup = NULL;

	session_free(setup);
}

static gboolean bnep_setup(GIOChannel *chan,
			GIOCondition cond, gpointer user_data)
{
	struct network_adapter *na = user_data;
	struct network_server *ns;
	uint8_t packet[BNEP_MTU];
	struct bnep_setup_conn_req *req = (void *) packet;
	uint16_t src_role, dst_role, rsp = BNEP_CONN_NOT_ALLOWED;
	int n, sk;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Hangup or error on BNEP socket");
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	/* Reading BNEP_SETUP_CONNECTION_REQUEST_MSG */
	n = read(sk, packet, sizeof(packet));
	if (n < 0) {
		error("read(): %s(%d)", strerror(errno), errno);
		return FALSE;
	}

	if (req->type != BNEP_CONTROL || req->ctrl != BNEP_SETUP_CONN_REQ)
		return FALSE;

	rsp = bnep_setup_decode(req, &dst_role, &src_role);
	if (rsp)
		goto reply;

	rsp = bnep_setup_chk(dst_role, src_role);
	if (rsp)
		goto reply;

	ns = find_server(na->servers, dst_role);
	if (!ns) {
		error("Server unavailable: (0x%x)", dst_role);
		goto reply;
	}

	if (!ns->record_id) {
		error("Service record not available");
		goto reply;
	}

	if (!ns->bridge) {
		error("Bridge interface not configured");
		goto reply;
	}

	if (server_connadd(ns, na->setup, dst_role) < 0)
		goto reply;

	na->setup = NULL;

	rsp = BNEP_SUCCESS;

reply:
	send_bnep_ctrl_rsp(sk, rsp);

	return FALSE;
}

static void connect_event(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct network_adapter *na = user_data;

	if (err) {
		error("%s", err->message);
		setup_destroy(na);
		return;
	}

	g_io_channel_set_close_on_unref(chan, TRUE);

	na->setup->watch = g_io_add_watch_full(chan, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				bnep_setup, na, setup_destroy);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct network_adapter *na = user_data;
	GError *err = NULL;

	if (derr) {
		error("Access denied: %s", derr->message);
		goto reject;
	}

	if (!bt_io_accept(na->setup->io, connect_event, na, NULL,
							&err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto reject;
	}

	return;

reject:
	g_io_channel_shutdown(na->setup->io, TRUE, NULL);
	setup_destroy(na);
}

static void confirm_event(GIOChannel *chan, gpointer user_data)
{
	struct network_adapter *na = user_data;
	struct network_server *ns;
	int perr;
	bdaddr_t src, dst;
	char address[18];
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	DBG("BNEP: incoming connect from %s", address);

	if (na->setup) {
		error("Refusing connect from %s: setup in progress", address);
		goto drop;
	}

	ns = find_server(na->servers, BNEP_SVC_NAP);
	if (!ns)
		goto drop;

	if (!ns->record_id)
		goto drop;

	if (!ns->bridge)
		goto drop;

	na->setup = g_new0(struct network_session, 1);
	bacpy(&na->setup->dst, &dst);
	na->setup->io = g_io_channel_ref(chan);

	perr = btd_request_authorization(&src, &dst, BNEP_SVC_UUID,
					auth_cb, na);
	if (perr < 0) {
		error("Refusing connect from %s: %s (%d)", address,
				strerror(-perr), -perr);
		setup_destroy(na);
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

int server_init(DBusConnection *conn, gboolean secure)
{
	security = secure;
	connection = dbus_connection_ref(conn);

	return 0;
}

void server_exit(void)
{
	dbus_connection_unref(connection);
	connection = NULL;
}

static uint32_t register_server_record(struct network_server *ns)
{
	sdp_record_t *record;

	record = server_record_new(ns->name, ns->id);
	if (!record) {
		error("Unable to allocate new service record");
		return 0;
	}

	if (add_record_to_server(&ns->src, record) < 0) {
		error("Failed to register service record");
		sdp_record_free(record);
		return 0;
	}

	DBG("got record id 0x%x", record->handle);

	return record->handle;
}


static inline DBusMessage *failed(DBusMessage *msg, const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				description);
}

static inline DBusMessage *invalid_arguments(DBusMessage *msg,
					const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
				description);
}

static void server_disconnect(DBusConnection *conn, void *user_data)
{
	struct network_server *ns = user_data;

	ns->watch_id = 0;

	if (ns->record_id) {
		remove_record_from_server(ns->record_id);
		ns->record_id = 0;
	}

	g_free(ns->bridge);
	ns->bridge = NULL;
}

static DBusMessage *register_server(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	const char *uuid, *bridge;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &uuid,
				DBUS_TYPE_STRING, &bridge, DBUS_TYPE_INVALID))
		return NULL;

	if (g_strcmp0(uuid, "nap"))
		return failed(msg, "Invalid UUID");

	if (ns->record_id)
		return failed(msg, "Already registered");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	ns->record_id = register_server_record(ns);
	if (!ns->record_id)
		return failed(msg, "SDP record registration failed");

	g_free(ns->bridge);
	ns->bridge = g_strdup(bridge);

	ns->watch_id = g_dbus_add_disconnect_watch(conn,
					dbus_message_get_sender(msg),
					server_disconnect, ns, NULL);

	return reply;
}

static DBusMessage *unregister_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	const char *uuid;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID))
		return NULL;

	if (g_strcmp0(uuid, "nap"))
		return failed(msg, "Invalid UUID");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	g_dbus_remove_watch(conn, ns->watch_id);

	server_disconnect(conn, ns);

	return reply;
}

static void adapter_free(struct network_adapter *na)
{
	if (na->io != NULL) {
		g_io_channel_shutdown(na->io, TRUE, NULL);
		g_io_channel_unref(na->io);
	}

	setup_destroy(na);
	btd_adapter_unref(na->adapter);
	g_free(na);
}

static void server_free(struct network_server *ns)
{
	if (!ns)
		return;

	/* FIXME: Missing release/free all bnepX interfaces */
	if (ns->record_id)
		remove_record_from_server(ns->record_id);

	g_free(ns->iface);
	g_free(ns->name);
	g_free(ns->bridge);

	if (ns->sessions) {
		g_slist_foreach(ns->sessions, (GFunc) session_free, NULL);
		g_slist_free(ns->sessions);
	}

	g_free(ns);
}

static void path_unregister(void *data)
{
	struct network_server *ns = data;
	struct network_adapter *na = ns->na;

	DBG("Unregistered interface %s on path %s",
		ns->iface, adapter_get_path(na->adapter));

	na->servers = g_slist_remove(na->servers, ns);
	server_free(ns);

	if (na->servers)
		return;

	adapters = g_slist_remove(adapters, na);
	adapter_free(na);
}

static GDBusMethodTable server_methods[] = {
	{ "Register",	"ss",	"",	register_server		},
	{ "Unregister",	"s",	"",	unregister_server	},
	{ }
};

static struct network_adapter *create_adapter(struct btd_adapter *adapter)
{
	struct network_adapter *na;
	GError *err = NULL;
	bdaddr_t src;

	na = g_new0(struct network_adapter, 1);
	na->adapter = btd_adapter_ref(adapter);

	adapter_get_address(adapter, &src);

	na->io = bt_io_listen(BT_IO_L2CAP, NULL, confirm_event, na,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_PSM, BNEP_PSM,
				BT_IO_OPT_OMTU, BNEP_MTU,
				BT_IO_OPT_IMTU, BNEP_MTU,
				BT_IO_OPT_SEC_LEVEL,
				security ? BT_IO_SEC_MEDIUM : BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!na->io) {
		error("%s", err->message);
		g_error_free(err);
		adapter_free(na);
		return NULL;
	}

	return na;
}

int server_register(struct btd_adapter *adapter)
{
	struct network_adapter *na;
	struct network_server *ns;
	const char *path;

	na = find_adapter(adapters, adapter);
	if (!na) {
		na = create_adapter(adapter);
		if (!na)
			return -EINVAL;
		adapters = g_slist_append(adapters, na);
	}

	ns = find_server(na->servers, BNEP_SVC_NAP);
	if (ns)
		return 0;

	ns = g_new0(struct network_server, 1);

	ns->iface = g_strdup(NETWORK_SERVER_INTERFACE);
	ns->name = g_strdup("Network service");

	path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(connection, path, ns->iface,
					server_methods, NULL, NULL,
					ns, path_unregister)) {
		error("D-Bus failed to register %s interface",
				ns->iface);
		server_free(ns);
		return -1;
	}

	adapter_get_address(adapter, &ns->src);
	ns->id = BNEP_SVC_NAP;
	ns->na = na;
	ns->record_id = 0;
	na->servers = g_slist_append(na->servers, ns);

	DBG("Registered interface %s on path %s", ns->iface, path);

	return 0;
}

int server_unregister(struct btd_adapter *adapter)
{
	struct network_adapter *na;
	struct network_server *ns;
	uint16_t id = BNEP_SVC_NAP;

	na = find_adapter(adapters, adapter);
	if (!na)
		return -EINVAL;

	ns = find_server(na->servers, id);
	if (!ns)
		return -EINVAL;

	g_dbus_unregister_interface(connection, adapter_get_path(adapter),
					ns->iface);

	return 0;
}
