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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"
#include "manager.h"
#include "error.h"

static gboolean disable_hfp = FALSE;
static gboolean sco_over_hci = TRUE;

static uint32_t hs_record_id = 0;
static uint32_t hf_record_id = 0;

static GIOChannel *hs_server = NULL;
static GIOChannel *hf_server = NULL;

static DBusConnection *connection = NULL;

static int gateway_hsp_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *channel;
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Headset Audio Gateway", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(channel);
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

static int gateway_hfp_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint16_t u16 = 0x0009;
	sdp_data_t *channel, *features;
	uint8_t netid = 0x01;
	sdp_data_t *network = sdp_data_alloc(SDP_UINT8, &netid);
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0105;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	features = sdp_data_alloc(SDP_UINT16, &u16);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(&record, SDP_ATTR_EXTERNAL_NETWORK, network);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(channel);
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

static uint32_t gateway_add_ag_record(uint8_t channel, sdp_buf_t *buf)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
						&buf->data, buf->data_size,
							DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
							msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
			dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr, DBUS_TYPE_UINT32, &rec_id,
							DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s",
								derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	debug("add_ag_record: got record id 0x%x", rec_id);

	return rec_id;
}

static int gateway_remove_ag_record(uint32_t rec_id)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT32, &rec_id,
							DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection,
							msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		error("Removing service record 0x%x failed: %s",
						rec_id, derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	return 0;
}

static void send_cancel_auth(struct device *device)
{
	DBusMessage *cancel;
	char addr[18], *address = addr;
	const char *uuid;

	if (headset_get_type(device) == SVC_HEADSET)
		uuid = HSP_AG_UUID;
	else
		uuid = HFP_AG_UUID;

	cancel = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!cancel) {
		error("Unable to allocate new method call");
		return;
	}

	ba2str(&device->dst, addr);

	dbus_message_append_args(cancel, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID);

	send_message_and_unref(connection, cancel);
}

static void auth_cb(DBusPendingCall *call, void *data)
{
	struct device *device = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Access denied: %s", err.message);
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			send_cancel_auth(device);
		}
		dbus_error_free(&err);
		headset_close_rfcomm(device);
	} else {
		char hs_address[18];

		headset_set_state(device, HEADSET_STATE_CONNECTED);

		ba2str(&device->dst, hs_address);

		debug("Accepted headset connection from %s for %s",
						hs_address, device->path);
	}

	dbus_message_unref(reply);
}

static gboolean gateway_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;
	char hs_address[18], *address = hs_address;
	const char *uuid;
	struct device *device;
	DBusMessage *auth;
	DBusPendingCall *pending;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		g_io_channel_close(chan);
		raise(SIGTERM);
		return FALSE;
	}

	srv_sk = g_io_channel_unix_get_fd(chan);

	size = sizeof(struct sockaddr_rc);
	cli_sk = accept(srv_sk, (struct sockaddr *) &addr, &size);
	if (cli_sk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	device = manager_device_connected(&addr.rc_bdaddr);
	if (!device) {
		close(cli_sk);
		return TRUE;
	}

	if (headset_get_state(device) > HEADSET_STATE_DISCONNECTED) {
		debug("Refusing new connection since one already exists");
		close(cli_sk);
		return TRUE;
	}

	if (headset_connect_rfcomm(device, cli_sk) < 0) {
		error("Allocating new GIOChannel failed!");
		close(cli_sk);
		return TRUE;
	}

	if (chan == hs_server) {
		headset_set_type(device, SVC_HEADSET);
		uuid = HSP_AG_UUID;
	} else {
		headset_set_type(device, SVC_HANDSFREE);
		uuid = HFP_AG_UUID;
	}

	auth = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"RequestAuthorization");
	if (!auth) {
		error("Unable to allocate RequestAuthorization method call");
		goto failed;
	}

	ba2str(&device->dst, hs_address);

	dbus_message_append_args(auth, DBUS_TYPE_STRING, &address,
						DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, auth, &pending, -1)) {
		error("Sending of authorization request failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, auth_cb, device, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(auth);

	return TRUE;

failed:
	headset_close_rfcomm(device);

	return TRUE;
}

static GIOChannel *server_socket(uint8_t *channel)
{
	int sock, lm;
	struct sockaddr_rc addr;
	socklen_t sa_len;
	GIOChannel *io;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0) {
		error("server socket: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	lm = RFCOMM_LM_SECURE;
	if (setsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
		error("server setsockopt: %s (%d)", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = channel ? *channel : 0;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("server bind: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	if (listen(sock, 1) < 0) {
		error("server listen: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	sa_len = sizeof(struct sockaddr_rc);
	getsockname(sock, (struct sockaddr *) &addr, &sa_len);
	*channel = addr.rc_channel;

	io = g_io_channel_unix_new(sock);
	if (!io) {
		error("Unable to allocate new io channel");
		close(sock);
		return NULL;
	}

	return io;
}

int gateway_init(DBusConnection *conn, gboolean no_hfp, gboolean sco_hci)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;
	sdp_buf_t buf;

	connection = dbus_connection_ref(conn);

	hs_server = server_socket(&chan);
	if (!hs_server)
		return -1;

	if (gateway_hsp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hs_record_id = gateway_add_ag_record(chan, &buf);
	free(buf.data);
	if (!hs_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hs_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hs_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						(GIOFunc) gateway_io_cb, NULL);

	disable_hfp = no_hfp;

	sco_over_hci = sco_hci;

	if (disable_hfp)
		return 0;

	chan = DEFAULT_HF_AG_CHANNEL;

	hf_server = server_socket(&chan);
	if (!hf_server)
		return -1;

	if (gateway_hfp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hf_record_id = gateway_add_ag_record(chan, &buf);
	free(buf.data);
	if (!hf_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hf_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hf_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						(GIOFunc) gateway_io_cb, NULL);

	return 0;
}

void gateway_exit(void)
{
	if (hs_record_id) {
		gateway_remove_ag_record(hs_record_id);
		hs_record_id = 0;
	}

	if (hs_server) {
		g_io_channel_unref(hs_server);
		hs_server = NULL;
	}

	if (hf_record_id) {
		gateway_remove_ag_record(hf_record_id);
		hf_record_id = 0;
	}

	if (hf_server) {
		g_io_channel_unref(hf_server);
		hf_server = NULL;
	}

	dbus_connection_unref(connection);
	connection = NULL;
}
