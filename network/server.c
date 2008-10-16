/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include "logging.h"
#include "error.h"
#include "sdpd.h"
#include "glib-helper.h"

#include "bridge.h"
#include "common.h"

#define NETWORK_PEER_INTERFACE "org.bluez.NetworkPeer"
#define NETWORK_HUB_INTERFACE "org.bluez.NetworkHub"
#define NETWORK_ROUTER_INTERFACE "org.bluez.NetworkRouter"
#define SETUP_TIMEOUT		1000

/* Pending Authorization */
struct setup_session {
	char		*address;	/* Remote Bluetooth Address */
	uint16_t	dst_role;	/* Destination role */
	uint16_t	src_role;	/* Source role */
	int		nsk;		/* L2CAP socket */
	guint		watch;		/* BNEP socket watch */
};

struct timeout {
	guint	id;		/* Timeout id */
	guint	watch;		/* BNEP socket watch */
};

struct network_adapter {
	bdaddr_t	src;		/* Bluetooth Local Address */
	char		*path;		/* D-Bus path */
	GIOChannel	*io;		/* Bnep socket */
	struct timeout	*to;		/* Socket timeout */
	GSList		*servers;	/* Server register to adapter */
};

/* Main server structure */
struct network_server {
	char		*iface;		/* DBus interface */
	char		*name;		/* Server service name */
	char		*range;		/* IP Address range */
	gboolean	enable;		/* Enable flag */
	uint32_t	record_id;	/* Service record id */
	uint16_t	id;		/* Service class identifier */
	GSList		*clients;	/* Active connections */
	struct network_adapter *na;	/* Adapter reference */
};

static DBusConnection *connection = NULL;
static struct setup_session *setup = NULL;
static GSList *adapters = NULL;
static const char *prefix = NULL;
static gboolean security = TRUE;

static struct network_adapter *find_adapter(GSList *list, const char *path)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_adapter *na = l->data;

		if (g_str_equal(na->path, path))
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

static struct setup_session *setup_session_new(gchar *address,
		uint16_t dst_role, uint16_t src_role, int nsk, guint watch)
{
	struct setup_session *setup;

	setup = g_new0(struct setup_session, 1);
	setup->address = g_strdup(address);
	setup->dst_role = dst_role;
	setup->src_role = src_role;
	setup->nsk = nsk;
	setup->watch = watch;

	return setup;
}

static void setup_session_free(struct setup_session *setup)
{
	g_source_remove(setup->watch);
	g_free(setup->address);
	g_free(setup);
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
	const char *desc = "BlueZ PAN service";
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

static int server_connadd(struct network_server *ns, int nsk,
			const gchar *address, uint16_t dst_role)
{
	char devname[16];
	const char *bridge;
	int err;

	/* Server can be disabled in the meantime */
	if (ns->enable == FALSE)
		return -EPERM;

	memset(devname, 0, 16);
	strncpy(devname, prefix, strlen(prefix));

	err = bnep_connadd(nsk, dst_role, devname);
	if (err < 0)
		return err;

	info("Added new connection: %s", devname);

	bridge = bridge_get_name(ns->id);
	if (bridge) {
		if (bridge_add_interface(ns->id, devname) < 0) {
			error("Can't add %s to the bridge %s: %s(%d)",
					devname, bridge, strerror(errno),
					errno);
			return -EPERM;
		}

		bnep_if_up(devname, 0);
	} else
		bnep_if_up(devname, ns->id);

	ns->clients = g_slist_append(ns->clients, g_strdup(address));

	return 0;
}

static void req_auth_cb(DBusError *derr, void *user_data)
{
	struct network_server *ns = user_data;
	uint16_t val;

	if (!setup) {
		info("Authorization cancelled: Client exited");
		return;
	}

	if (derr) {
		error("Access denied: %s", derr->message);

		val = BNEP_CONN_NOT_ALLOWED;
		goto done;
	}

	if (server_connadd(ns, setup->nsk,
			setup->address, setup->dst_role) < 0)
		val = BNEP_CONN_NOT_ALLOWED;
	else
		val = BNEP_SUCCESS;

done:
	send_bnep_ctrl_rsp(setup->nsk, val);
	setup_session_free(setup);
	setup = NULL;
}

static int authorize_connection(struct network_server *ns, const char *address)
{
	struct network_adapter *na = ns->na;
	const char *uuid;
	bdaddr_t dst;
	int ret_val;

	uuid = bnep_uuid(ns->id);
	str2ba(address, &dst);

	ret_val = btd_request_authorization(&na->src, &dst, uuid,
				req_auth_cb, ns);

	return ret_val;
}

static uint16_t inline bnep_setup_chk(uint16_t dst_role, uint16_t src_role)
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

static gboolean bnep_setup(GIOChannel *chan,
			GIOCondition cond, gpointer user_data)
{
	struct network_adapter *na = user_data;
	struct timeout *to = na->to;
	struct network_server *ns;
	uint8_t packet[BNEP_MTU];
	struct bnep_setup_conn_req *req = (void *) packet;
	struct sockaddr_l2 sa;
	socklen_t size;
	char address[18];
	uint16_t rsp, src_role, dst_role;
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

	size = sizeof(sa);
	if (getsockname(sk, (struct sockaddr *) &sa, &size) < 0) {
		rsp = BNEP_CONN_NOT_ALLOWED;
		goto reply;
	}

	ba2str(&sa.l2_bdaddr, address);
	ns = find_server(na->servers, dst_role);
	if (!ns || ns->enable == FALSE) {
		error("Server unavailable: %s (0x%x)", address, dst_role);
		rsp = BNEP_CONN_NOT_ALLOWED;
		goto reply;
	}

	if (getpeername(sk, (struct sockaddr *) &sa, &size) < 0) {
		rsp = BNEP_CONN_NOT_ALLOWED;
		goto reply;
	}

	ba2str(&sa.l2_bdaddr, address);

	if (setup) {
		error("Connection rejected: Pending authorization");
		rsp = BNEP_CONN_NOT_ALLOWED;
		goto reply;
	}

	setup = setup_session_new(address, dst_role, src_role, sk, to->watch);

	/* Wait authorization before reply success */
	if (authorize_connection(ns, address) < 0) {
		setup_session_free(setup);
		setup = NULL;
		rsp = BNEP_CONN_NOT_ALLOWED;
		goto reply;
	}

	g_source_remove(to->id);
	to->id = 0;

	return TRUE;

reply:
	send_bnep_ctrl_rsp(sk, rsp);

	return FALSE;
}

static void setup_destroy(void *user_data)
{
	struct network_adapter *na = user_data;
	struct timeout *to = na->to;

	if (to->id)
		g_source_remove(to->id);

	g_free(to);
}

static gboolean timeout_cb(void *user_data)
{
	struct timeout *to = user_data;

	to->id = 0;
	g_source_remove(to->watch);

	return FALSE;
}

static void connect_event(GIOChannel *chan, int err, const bdaddr_t *src,
				const bdaddr_t *dst, gpointer user_data)
{
	struct network_adapter *na = user_data;

	if (err < 0) {
		error("accept(): %s(%d)", strerror(errno), errno);
		return;
	}

	g_io_channel_set_close_on_unref(chan, TRUE);

	/*
	 * BNEP_SETUP_CONNECTION_REQUEST_MSG shall be received and
	 * user shall authorize the incomming connection before
	 * the time expires.
	 */
	na->to = g_malloc0(sizeof(struct timeout));
	na->to->id = g_timeout_add(SETUP_TIMEOUT, timeout_cb, na->to);
	na->to->watch = g_io_add_watch_full(chan, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				bnep_setup, na, setup_destroy);
	g_io_channel_unref(chan);

	return;
}

int server_init(DBusConnection *conn, const char *iface_prefix,
		gboolean secure)
{
	security = secure;
	connection = dbus_connection_ref(conn);
	prefix = iface_prefix;

	if (bridge_create(BNEP_SVC_GN) < 0)
		error("Can't create GN bridge");

	return 0;
}

void server_exit()
{
	if (bridge_remove(BNEP_SVC_GN) < 0)
		error("Can't remove GN bridge");

	dbus_connection_unref(connection);
	connection = NULL;
}

static uint32_t register_server_record(struct network_server *ns)
{
	struct network_adapter *na = ns->na;
	sdp_record_t *record;

	record = server_record_new(ns->name, ns->id);
	if (!record) {
		error("Unable to allocate new service record");
		return 0;
	}

	if (add_record_to_server(&na->src, record) < 0) {
		error("Failed to register service record");
		sdp_record_free(record);
		return 0;
	}

	debug("register_server_record: got record id 0x%x", record->handle);

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

static DBusMessage *enable(DBusConnection *conn,
			DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	if (ns->enable)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".AlreadyExist",
						"Server already enabled");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	/* Add the service record */
	ns->record_id = register_server_record(ns);
	if (!ns->record_id) {
		dbus_message_unref(reply);
		return failed(msg, "Service record registration failed");
	}

	ns->enable = TRUE;

	return reply;
}

static void kill_connection(void *data, void *udata)
{
	const char *address = data;
	bdaddr_t dst;

	str2ba(address, &dst);
	bnep_kill_connection(&dst);
}

static DBusMessage *disable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (!ns->enable)
		return failed(msg, "Not enabled");

	/* Remove the service record */
	if (ns->record_id) {
		remove_record_from_server(ns->record_id);
		ns->record_id = 0;
	}

	ns->enable = FALSE;

	g_slist_foreach(ns->clients, (GFunc) kill_connection, NULL);

	return reply;
}

static DBusMessage *set_name(DBusConnection *conn, DBusMessage *msg,
				const char *name, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (!name || (strlen(name) == 0))
		return invalid_arguments(msg, "Invalid name");

	if (ns->name)
		g_free(ns->name);
	ns->name = g_strdup(name);

	if (ns->enable && ns->record_id) {
		uint32_t handle = register_server_record(ns);
		if (!handle) {
			dbus_message_unref(reply);
			return failed(msg,
				"Service record attribute update failed");
		}

		remove_record_from_server(ns->record_id);
		ns->record_id = handle;
	}

	return reply;
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *uuid;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Name", DBUS_TYPE_STRING, &ns->name);

	uuid = bnep_uuid(ns->id);
	dict_append_entry(&dict, "Uuid", DBUS_TYPE_STRING, &uuid);

	dict_append_entry(&dict, "Enabled", DBUS_TYPE_BOOLEAN, &ns->enable);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return invalid_arguments(msg, "Not a dict");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return invalid_arguments(msg, "Key not a string");

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return invalid_arguments(msg, "Value not a variant");
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Name", property)) {
		const char *name;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_arguments(msg, "Value not string");
		dbus_message_iter_get_basic(&sub, &name);

		return set_name(conn, msg, name, data);
	} else if (g_str_equal("Enabled", property)) {
		gboolean enabled;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return invalid_arguments(msg, "Value not boolean");
		dbus_message_iter_get_basic(&sub, &enabled);

		return enabled ? enable(conn, msg, data) :
				disable(conn, msg, data);
	}

	return invalid_arguments(msg, "Property does not exist");
}

static void adapter_free(struct network_adapter *na)
{
	if (na->io != NULL) {
		g_io_channel_close(na->io);
		g_io_channel_unref(na->io);
	}

	g_free(na->path);
	g_free(na);
}

static void server_free(struct network_server *ns)
{
	if (!ns)
		return;

	/* FIXME: Missing release/free all bnepX interfaces */
	if (ns->record_id)
		remove_record_from_server(ns->record_id);

	if (ns->iface)
		g_free(ns->iface);

	if (ns->name)
		g_free(ns->name);

	if (ns->range)
		g_free(ns->range);

	if (ns->clients) {
		g_slist_foreach(ns->clients, (GFunc) g_free, NULL);
		g_slist_free(ns->clients);
	}

	g_free(ns);
}

static void path_unregister(void *data)
{
	struct network_server *ns = data;
	struct network_adapter *na = ns->na;

	info("Unregistered interface %s on path %s",
		ns->iface, na->path);

	na->servers = g_slist_remove(na->servers, ns);
	server_free(ns);

	if (na->servers)
		return;

	adapters = g_slist_remove(adapters, na);
	adapter_free(na);
}

static GDBusMethodTable server_methods[] = {
	{ "SetProperty",	"sv",	"",	set_property },
	{ "GetProperties",	"",	"a{sv}",get_properties },
	{ }
};

static GDBusSignalTable server_signals[] = {
	{ "PropertyChanged",		"sv"		},
	{ }
};

static struct network_adapter *create_adapter(const char *path, bdaddr_t *src)
{
	struct network_adapter *na;
	int lm = 0;

	if (security)
		lm |= L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT;

	na = g_new0(struct network_adapter, 1);
	na->path = g_strdup(path);
	bacpy(&na->src, src);

	na->io = bt_l2cap_listen(src, BNEP_PSM, BNEP_MTU, lm,
			connect_event, na);
	if (!na->io) {
		adapter_free(na);
		return NULL;
	}

	g_io_channel_set_close_on_unref(na->io, FALSE);

	return na;
}

int server_register(const char *path, bdaddr_t *src, uint16_t id)
{
	struct network_adapter *na;
	struct network_server *ns;

	na = find_adapter(adapters, path);
	if (!na) {
		na = create_adapter(path, src);
		if (!na)
			return -EINVAL;
		adapters = g_slist_append(adapters, na);
	}

	ns = find_server(na->servers, id);
	if (ns)
		return 0;

	ns = g_new0(struct network_server, 1);

	switch (id) {
	case BNEP_SVC_PANU:
		ns->iface = g_strdup(NETWORK_PEER_INTERFACE);
		ns->name = g_strdup("BlueZ PANU service");
		break;
	case BNEP_SVC_GN:
		ns->iface = g_strdup(NETWORK_HUB_INTERFACE);
		ns->name = g_strdup("BlueZ GN service");
		break;
	case BNEP_SVC_NAP:
		ns->iface = g_strdup(NETWORK_ROUTER_INTERFACE);
		ns->name = g_strdup("BlueZ NAP service");
		break;
	}

	if (!g_dbus_register_interface(connection, path, ns->iface,
					server_methods, server_signals, NULL,
					ns, path_unregister)) {
		error("D-Bus failed to register %s interface",
				ns->iface);
		server_free(ns);
		return -1;
	}

	ns->id = id;
	ns->na = na;
	ns->record_id = register_server_record(ns);
	ns->enable = TRUE;
	na->servers = g_slist_append(na->servers, ns);

	info("Registered interface %s on path %s", ns->iface, path);

	return 0;
}

int server_unregister(const char *path, uint16_t id)
{
	struct network_adapter *na;
	struct network_server *ns;

	na = find_adapter(adapters, path);
	if (!na)
		return -EINVAL;

	ns = find_server(na->servers, id);
	if (!ns)
		return -EINVAL;

	g_dbus_unregister_interface(connection, path, ns->iface);

	return 0;
}
