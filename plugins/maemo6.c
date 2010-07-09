/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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

#include <glib.h>
#include <dbus/dbus.h>

#include "adapter.h"
#include "plugin.h"
#include "log.h"
#include "gdbus.h"

/* from mce/mode-names.h */
#define MCE_RADIO_STATE_BLUETOOTH	(1 << 3)

/* from mce/dbus-names.h */
#define MCE_SERVICE			"com.nokia.mce"
#define MCE_REQUEST_IF			"com.nokia.mce.request"
#define MCE_SIGNAL_IF			"com.nokia.mce.signal"
#define MCE_REQUEST_PATH		"/com/nokia/mce/request"
#define MCE_SIGNAL_PATH			"/com/nokia/mce/signal"
#define MCE_RADIO_STATES_GET		"get_radio_states"
#define MCE_RADIO_STATES_SIG		"radio_states_ind"

static guint watch_id;
static DBusConnection *conn = NULL;

static gboolean mce_signal_callback(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter args;
	uint32_t sigvalue;
	struct btd_adapter *adapter = user_data;

	DBG("received mce signal");

	if (!dbus_message_iter_init(message, &args))
		error("message has no arguments");
	else if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		error("argument is not uint32");
	else {
		dbus_message_iter_get_basic(&args, &sigvalue);
		DBG("got signal with value %u", sigvalue);

		if (sigvalue & MCE_RADIO_STATE_BLUETOOTH)
			btd_adapter_switch_online(adapter);
		else
			btd_adapter_switch_offline(adapter);
	}

	return TRUE;
}

static void read_radio_states_cb(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	dbus_uint32_t radio_states;
	struct btd_adapter *adapter = user_data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("mce replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (dbus_message_get_args(reply, &err,
				DBUS_TYPE_UINT32, &radio_states,
				DBUS_TYPE_INVALID) == FALSE) {
		error("unable to parse get_radio_states reply: %s, %s",
							err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (radio_states & MCE_RADIO_STATE_BLUETOOTH)
		btd_adapter_switch_online(adapter);

done:
	dbus_message_unref(reply);
}

static int mce_probe(struct btd_adapter *adapter)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	DBG("path %s", adapter_get_path(adapter));

	msg = dbus_message_new_method_call(MCE_SERVICE, MCE_REQUEST_PATH,
					MCE_REQUEST_IF, MCE_RADIO_STATES_GET);

	if (!dbus_connection_send_with_reply(conn, msg, &call, -1)) {
		error("calling %s failed", MCE_RADIO_STATES_GET);
		dbus_message_unref(msg);
		return -1;
	}

	dbus_pending_call_set_notify(call, read_radio_states_cb, adapter, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	watch_id = g_dbus_add_signal_watch(conn, NULL, MCE_SIGNAL_PATH,
					MCE_SIGNAL_IF, MCE_RADIO_STATES_SIG,
					mce_signal_callback, adapter, NULL);
	return 0;
}

static void mce_remove(struct btd_adapter *adapter)
{
	DBG("path %s", adapter_get_path(adapter));

	if (watch_id > 0)
		g_dbus_remove_watch(conn, watch_id);
}

static struct btd_adapter_driver mce_driver = {
	.name	= "mce",
	.probe	= mce_probe,
	.remove	= mce_remove,
};

static int maemo6_init(void)
{
	DBG("init maemo6 plugin");

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		error("Unable to connect to D-Bus");
		return -1;
	}

	return btd_register_adapter_driver(&mce_driver);
}

static void maemo6_exit(void)
{
	DBG("exit maemo6 plugin");

	if (conn != NULL)
		dbus_connection_unref(conn);

	btd_unregister_adapter_driver(&mce_driver);
}

BLUETOOTH_PLUGIN_DEFINE(maemo6, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, maemo6_init, maemo6_exit)
