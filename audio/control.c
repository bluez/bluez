/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C)  2007 Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C)  2007 Nokia Corporation
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

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <netinet/in.h>

#include <glib.h>
#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/l2cap.h>

#include "logging.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "control.h"

#define AVCTP_PSM 23

static DBusConnection *connection = NULL;

static uint32_t tg_record_id = 0;
static uint32_t ct_record_id = 0;

static GIOChannel *avctp_server = NULL;

static GSList *sessions = NULL;

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));

struct avrcp_header {
	uint8_t code:4;
	uint8_t _hdr0:4;
	uint8_t subunit_id:3;
	uint8_t subunit_type:5;
	uint8_t opcode;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));

struct avrcp_header {
	uint8_t _hdr0:4;
	uint8_t code:4;
	uint8_t subunit_type:5;
	uint8_t subunit_id:3;
	uint8_t opcode;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

struct avctp {
	bdaddr_t src;
	bdaddr_t dst;

	int sock;

	guint io;

	uint16_t mtu;

	DBusPendingCall *pending_auth;
};

static int avrcp_ct_record(sdp_buf_t *buf)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM, ver = 0x0103, feat = 0x000f;
	int ret = 0;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrct, AV_REMOTE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrct);
	sdp_set_service_classes(&record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(&record, "AVRCP CT", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static int avrcp_tg_record(sdp_buf_t *buf)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM, ver = 0x0103, feat = 0x000f;
	int ret = 0;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrtg);
	sdp_set_service_classes(&record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(&record, "AVRCP TG", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static GIOChannel *avctp_server_socket(void)
{
	int sock, lm;
	struct sockaddr_l2 addr;
	GIOChannel *io;

	sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sock < 0) {
		error("AVCTP server socket: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	lm = L2CAP_LM_SECURE;
	if (setsockopt(sock, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm)) < 0) {
		error("AVCTP server setsockopt: %s (%d)", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, BDADDR_ANY);
	addr.l2_psm = htobs(AVCTP_PSM);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("AVCTP server bind: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	if (listen(sock, 4) < 0) {
		error("AVCTP server listen: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	io = g_io_channel_unix_new(sock);
	if (!io) {
		error("Unable to allocate new io channel");
		close(sock);
		return NULL;
	}

	return io;
}

static struct avctp *find_session(bdaddr_t *src, bdaddr_t *dst)
{
	GSList *l;

	for (l = sessions; l != NULL; l = g_slist_next(l)) {
		struct avctp *s = l->data;

		if (bacmp(src, &s->src) || bacmp(dst, &s->dst))
			continue;

		return s;
	}

	return NULL;
}

static void avctp_unref(struct avctp *session)
{
	sessions = g_slist_remove(sessions, session);
	if (session->sock >= 0)
		close(session->sock);
	if (session->io)
		g_source_remove(session->io);
	g_free(session);
}

static struct avctp *avctp_get(bdaddr_t *src, bdaddr_t *dst)
{
	struct avctp *session;

	assert(src != NULL);
	assert(dst != NULL);

	session = find_session(src, dst);
	if (session) {
		if (session->pending_auth)
			return NULL;
		else
			return session;
	}

	session = g_new0(struct avctp, 1);

	session->sock = -1;
	bacpy(&session->src, src);
	bacpy(&session->dst, dst);

	sessions = g_slist_append(sessions, session);

	return session;
}

static gboolean session_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct avctp *session = data;
	char buf[1024];
	struct avctp_header *avctp;
	struct avrcp_header *avrcp;
	int ret;

	if (!(cond | G_IO_IN))
		goto failed;

	ret = read(session->sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	debug("Got %d bytes of data for AVCTP session %p", ret, session);

	if (ret < sizeof(struct avctp_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	avctp = (struct avctp_header *) buf;

	debug("AVCTP transaction %u, packet type %u, C/R %u, IPID %u, "
			"PID 0x%04X",
			avctp->transaction, avctp->packet_type,
			avctp->cr, avctp->ipid, ntohs(avctp->pid));

	ret -= sizeof(struct avctp_header);
	if (ret < sizeof(struct avrcp_header)) {
		error("Too small AVRCP packet");
		goto failed;
	}

	avrcp = (struct avrcp_header *) (buf + sizeof(struct avctp_header));

	debug("AVRCP %s 0x%01X, subunit_type 0x%02X, subunit_id 0x%01X, "
			"opcode 0x%02X", avctp->cr ? "response" : "command",
			avrcp->code, avrcp->subunit_type, avrcp->subunit_id,
			avrcp->opcode);

	return TRUE;

failed:
	debug("AVCTP session %p got disconnected", session);
	avctp_unref(session);
	return FALSE;
}

static void auth_cb(DBusPendingCall *call, void *data)
{
	GIOChannel *io;
	struct avctp *session = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_pending_call_unref(session->pending_auth);
	session->pending_auth = NULL;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Access denied: %s", err.message);

		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			manager_cancel_authorize(&session->dst,
							ADVANCED_AUDIO_UUID,
							NULL);
		}

		avctp_unref(session);

		dbus_message_unref(reply);

		return;
	}

	g_source_remove(session->io);

	io = g_io_channel_unix_new(session->sock);
	session->io = g_io_add_watch(io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) session_cb, session);
	g_io_channel_unref(io);
}

static gboolean avctp_server_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	socklen_t size;
	struct sockaddr_l2 addr;
	struct l2cap_options l2o;
	bdaddr_t src, dst;
	struct avctp *session;
	GIOChannel *io;
	GIOCondition flags = G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	char address[18];

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on AVCTP server socket");
		g_io_channel_close(chan);
		raise(SIGTERM);
		return FALSE;
	}

	srv_sk = g_io_channel_unix_get_fd(chan);

	size = sizeof(struct sockaddr_l2);
	cli_sk = accept(srv_sk, (struct sockaddr *) &addr, &size);
	if (cli_sk < 0) {
		error("AVCTP accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	bacpy(&dst, &addr.l2_bdaddr);

	ba2str(&dst, address);
	debug("AVCTP: incoming connect from %s", address);

	size = sizeof(struct sockaddr_l2);
	if (getsockname(cli_sk, (struct sockaddr *) &addr, &size) < 0) {
		error("getsockname: %s (%d)", strerror(errno), errno);
		close(cli_sk);
		return TRUE;
	}

	bacpy(&src, &addr.l2_bdaddr);

	memset(&l2o, 0, sizeof(l2o));
	size = sizeof(l2o);
	if (getsockopt(cli_sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &size) < 0) {
		error("getsockopt(L2CAP_OPTIONS): %s (%d)", strerror(errno),
			errno);
		close(cli_sk);
		return TRUE;
	}

	session = avctp_get(&src, &dst);

	if (session->sock >= 0) {
		error("Refusing unexpected connect from %s", address);
		close(cli_sk);
		return TRUE;
	}

	if (avdtp_is_connected(&src, &dst))
		goto proceed;

	if (!manager_authorize(&dst, AVRCP_TARGET_UUID, auth_cb, session,
				&session->pending_auth)) {
		close(cli_sk);
		avctp_unref(session);
		return TRUE;
	}

proceed:
	session->mtu = l2o.imtu;
	session->sock = cli_sk;

	io = g_io_channel_unix_new(session->sock);
	if (!session->pending_auth)
		flags |= G_IO_IN;
	session->io = g_io_add_watch(io, flags, (GIOFunc) session_cb, session);
	g_io_channel_unref(io);

	return TRUE;
}

int control_init(DBusConnection *conn)
{
	sdp_buf_t buf;

	if (avctp_server)
		return 0;

	connection = dbus_connection_ref(conn);

	if (avrcp_tg_record(&buf) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	tg_record_id = add_service_record(conn, &buf);
	free(buf.data);

	if (!tg_record_id) {
		error("Unable to register AVRCP target service record");
		return -1;
	}

	if (avrcp_ct_record(&buf) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	ct_record_id = add_service_record(conn, &buf);
	free(buf.data);

	if (!ct_record_id) {
		error("Unable to register AVRCP controller service record");
		return -1;
	}

	avctp_server = avctp_server_socket();
	if (!avctp_server)
		return -1;

	g_io_add_watch(avctp_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			(GIOFunc) avctp_server_cb, NULL);

	return 0;
}

void control_exit(void)
{
	if (!avctp_server)
		return;

	g_io_channel_close(avctp_server);
	g_io_channel_unref(avctp_server);
	avctp_server = NULL;

	remove_service_record(connection, ct_record_id);
	ct_record_id = 0;

	remove_service_record(connection, ct_record_id);
	ct_record_id = 0;

	dbus_connection_unref(connection);
	connection = NULL;
}

