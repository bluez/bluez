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

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hidp.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"

#include "server.h"
#include "storage.h"

struct session_data {
	bdaddr_t src;
	bdaddr_t dst;
	int ctrl_sk;
	int intr_sk;
};

static GSList *sessions = NULL;
static DBusConnection *connection = NULL;

static struct session_data *find_session(bdaddr_t *src, bdaddr_t *dst)
{
	GSList *list;

	for (list = sessions; list != NULL; list = list->next) {
		struct session_data *session = list->data;

		if (!bacmp(&session->src, src) && !bacmp(&session->dst, dst))
			return session;
	}

	return NULL;
}

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		return FALSE;

	return TRUE;
}

static void create_device(struct session_data *session)
{
	struct hidp_connadd_req req;
	char addr[18];
	int ctl, err, timeout = 30;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP interface");
		goto cleanup;
	}

	ba2str(&session->dst, addr);

	memset(&req, 0, sizeof(req));
	req.ctrl_sock = session->ctrl_sk;
	req.intr_sock = session->intr_sk;
	req.flags     = 0;
	req.idle_to   = timeout * 60;

	if (get_stored_device_info(&session->src, &session->dst, &req) < 0) {
		error("Rejected connection from unknown device %s", addr);
		goto cleanup;
	}

	if (req.subclass & 0x40) {
		if (encrypt_link(&session->src, &session->dst) < 0) {
			if (req.rd_data)
				free(req.rd_data);
			goto cleanup;
		}
	}

	info("New input device %s (%s)", addr, req.name);

	err = ioctl(ctl, HIDPCONNADD, &req);

	close(ctl);

	if (req.rd_data)
		free(req.rd_data);

cleanup:
	sessions = g_slist_remove(sessions, session);

	close(session->intr_sk);
	close(session->ctrl_sk);

	g_free(session);
}

static void cancel_authorization(const char *addr)
{
	DBusMessage *msg;
	const char *uuid = "";

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!msg) {
		error("Unable to allocate new method call");
		return;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &addr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	send_message_and_unref(connection, msg);
}

static void authorization_callback(DBusPendingCall *pcall, void *data)
{
	struct session_data *session = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(pcall);
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Access denied: %s", derr.message);
		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY)) {
			char addr[18];
			memset(addr, 0, sizeof(addr));
			ba2str(&session->dst, addr);
			cancel_authorization(addr);
		}
		dbus_error_free(&derr);

		sessions = g_slist_remove(sessions, session);

		close(session->intr_sk);
		close(session->ctrl_sk);

		g_free(session);

		goto failed;
	}

	create_device(session);
failed:
	dbus_message_unref(reply);
	dbus_pending_call_unref(pcall);
}

static int authorize_device(struct session_data *session)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;
	const char *uuid = ""; /* FIXME: */

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RequestAuthorization");
	if (!msg) {
		error("Unable to allocat new RequestAuthorization method call");
		return -ENOMEM;
	}

	memset(addr, 0, sizeof(addr));
	ba2str(&session->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection,
				msg, &pending, -1) == FALSE)
		return -EACCES;

	dbus_pending_call_set_notify(pending, authorization_callback, session, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void create_watch(int sk, struct session_data *session)
{
	GIOChannel *io;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						session_event, session);

	g_io_channel_unref(io);
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct session_data *session;
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	bdaddr_t src, dst;
	unsigned char psm;
	int sk, nsk;

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &addrlen);
	if (nsk < 0)
		return TRUE;

	bacpy(&dst, &addr.l2_bdaddr);
	psm = btohs(addr.l2_psm);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getsockname(nsk, (struct sockaddr *) &addr, &addrlen) < 0) {
		close(nsk);
		return TRUE;
	}

	bacpy(&src, &addr.l2_bdaddr);

	debug("Incoming connection on PSM %d", psm);

	session = find_session(&src, &dst);
	if (session) {
		if (psm == 19) {
			session->intr_sk = nsk;
			if (authorize_device(session) < 0) {
				error("Authorization request failed");
				sessions = g_slist_remove(sessions, session);

				close(session->intr_sk);
				close(session->ctrl_sk);

				g_free(session);

				return TRUE;
			}
			debug("Waiting authorization ...");
		} else {
			error("Control channel already established");
			close(nsk);
		}
	} else {
		if (psm == 17) {
			session = g_new0(struct session_data, 1);

			bacpy(&session->src, &src);
			bacpy(&session->dst, &dst);
			session->ctrl_sk = nsk;
			session->intr_sk = -1;

			sessions = g_slist_append(sessions, session);

			create_watch(nsk, session);
		} else {
			error("No control channel available");
			close(nsk);
		}
	}

	return TRUE;
}

static GIOChannel *setup_l2cap(unsigned int psm)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, BDADDR_ANY);
	addr.l2_psm = htobs(psm);

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

	g_io_add_watch(io, G_IO_IN, connect_event, NULL);

	return io;
}

static GIOChannel *ctrl_io = NULL;
static GIOChannel *intr_io = NULL;

int server_start(DBusConnection *conn)
{
	ctrl_io = setup_l2cap(17);
	if (!ctrl_io) {
		error("Failed to listen on control channel");
		return -1;
	}

	intr_io = setup_l2cap(19);
	if (!intr_io) {
		error("Failed to listen on interrupt channel");
		g_io_channel_unref(ctrl_io);
		ctrl_io = NULL;
	}

	connection = conn;

	return 0;
}

void server_stop(void)
{
	if (intr_io)
		g_io_channel_unref(intr_io);

	if (ctrl_io)
		g_io_channel_unref(ctrl_io);
}
