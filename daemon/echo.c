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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"

static sdp_session_t *sdp_session = NULL;
static sdp_record_t *sdp_record = NULL;

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[672];
	gsize len, written;
	GIOError err;

	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err == G_IO_ERROR_AGAIN)
		return TRUE;

	g_io_channel_write(chan, (const gchar *) buf, len, &written);

	return TRUE;
}

static void authorization_callback(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	GIOChannel *io = data;
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply)) {
		error("Access to the service has been %s", err.message);
		dbus_error_free(&err);
	} else {
		info("Accepting incoming connection");
		g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR,
						session_event, NULL);
	}

	g_io_channel_unref(io);

	dbus_message_unref(reply);
}

static int request_authorization(DBusConnection *conn,
					GIOChannel *io, const char *address)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *path = "";

	info("Requesting authorization for %s", address);

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RequestAuthorization");
	if (!msg) {
		error("Allocation of method message failed");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(conn, msg, &pending, -1) == FALSE) {
		error("Sending of authorization request failed");
		return -1;
	}

	dbus_pending_call_set_notify(pending, authorization_callback, io, NULL);

	dbus_message_unref(msg);

	return 0;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusConnection *conn = data;
	GIOChannel *io;
	struct sockaddr_rc addr;
	socklen_t optlen;
	char address[18];
	int sk, nsk;

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0)
		return TRUE;

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	ba2str(&addr.rc_bdaddr, address);

	if (request_authorization(conn, io, address) < 0) {
		close(nsk);
		return TRUE;
	}

	return TRUE;
}

static GIOChannel *setup_rfcomm(DBusConnection *conn, uint8_t channel)
{
	GIOChannel *io;
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return NULL;
	}

	if (listen(sk, 10) < 0) {
		close(sk);
		return NULL;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN, connect_event, conn);

	return io;
}

static int setup_sdp(uint8_t channel)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, l2cap, rfcomm, spp;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];

	sdp_session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!sdp_session) {
		error("Connection to SDP server failed");
		return -1;
	}

	sdp_record = sdp_record_alloc();
	if (!sdp_record) {
		error("Allocation of service record failed");
		return -1;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(sdp_record, root);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq    = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	proto[1] = sdp_list_append(proto[1], sdp_data_alloc(SDP_UINT8, &channel));
	apseq    = sdp_list_append(apseq, proto[1]);

	aproto   = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(sdp_record, aproto);

	sdp_uuid16_create(&spp, SERIAL_PORT_SVCLASS_ID);
	svclass = sdp_list_append(NULL, &spp);
	sdp_set_service_classes(sdp_record, svclass);

	sdp_uuid16_create(&profile[0].uuid, SERIAL_PORT_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(sdp_record, pfseq);

	sdp_set_info_attr(sdp_record, "Echo service", NULL, NULL);

	if (sdp_record_register(sdp_session, sdp_record, 0) < 0) {
		error("Registration of service record failed");
		sdp_record_free(sdp_record);
		sdp_record = NULL;
		return -1;
	}

	return 0;
}

static int register_standalone(DBusConnection *conn)
{
	DBusMessage *msg, *reply;
	const char *ident = "echo", *name = "Echo service", *desc = "";

	info("Registering service");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RegisterService");
	if (!msg) {
		error("Allocation of method message failed");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &ident,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &desc, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, NULL);
	if (!reply) {
		error("Registration of service failed");
		return -1;
	}

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return 0;
}

static GMainLoop *main_loop = NULL;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void sig_hup(int sig)
{
}

int main(int argc, char *argv[])
{
	DBusConnection *system_bus;
	GIOChannel *server_io;
	struct sigaction sa;

	start_logging("echo", "Bluetooth echo service ver %s", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	system_bus = init_dbus(NULL, NULL, NULL);
	if (!system_bus) {
		error("Connection to system bus failed");
		g_main_loop_unref(main_loop);
		exit(1);
	}

	server_io = setup_rfcomm(system_bus, 23);
	if (!server_io) {
		error("Creation of server channel failed");
		dbus_connection_unref(system_bus);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	setup_sdp(23);

	if (argc > 1 && !strcmp(argv[1], "-s"))
		register_standalone(system_bus);

	g_main_loop_run(main_loop);

	g_io_channel_unref(server_io);

	dbus_connection_unref(system_bus);

	if (sdp_record) {
		if (sdp_record_unregister(sdp_session, sdp_record) < 0)
			sdp_record_free(sdp_record);
	}

	sdp_close(sdp_session);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
