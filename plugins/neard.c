/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Tieto Poland
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
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>

#include "plugin.h"
#include "log.h"
#include "dbus-common.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "eir.h"
#include "storage.h"
#include "agent.h"
#include "hcid.h"

#define NEARD_NAME "org.neard"
#define NEARD_PATH "/"
#define NEARD_MANAGER_INTERFACE "org.neard.Manager"
#define AGENT_INTERFACE "org.neard.HandoverAgent"
#define AGENT_PATH "/org/bluez/neard_handover_agent"
#define ERROR_INTERFACE "org.neard.HandoverAgent.Error"

static guint watcher_id = 0;
static gboolean agent_registered = FALSE;
static gboolean agent_register_postpone = FALSE;

/* For NFC mimetype limits max OOB EIR size */
#define NFC_OOB_EIR_MAX UINT8_MAX

static DBusMessage *error_reply(DBusMessage *msg, int error)
{
	switch (error) {
	case ENOTSUP:
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotSupported",
						"Operation is not supported");

	case ENOENT:
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NoSuchDevice",
							"No such device");

	case EINPROGRESS:
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
						"Operation already in progress");

	case ENONET:
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Disabled",
							"Device disabled");

	default:
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"%s", strerror(error));
	}
}

static void register_agent_cb(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError err;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("neard manager replied with an error: %s, %s",
						err.name, err.message);
		dbus_error_free(&err);
		dbus_message_unref(reply);

		g_dbus_unregister_interface(btd_get_dbus_connection(),
						AGENT_PATH, AGENT_INTERFACE);
		return;
	}

	dbus_message_unref(reply);
	agent_registered = TRUE;
}

static void register_agent(void)
{
	DBusMessage *message;
	DBusPendingCall *call;
	const gchar *path = AGENT_PATH;

	message = dbus_message_new_method_call(NEARD_NAME, NEARD_PATH,
			NEARD_MANAGER_INTERFACE, "RegisterHandoverAgent");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(btd_get_dbus_connection(),
							message, &call, -1)) {
		error("D-Bus send failed");
		return;
	}

	dbus_pending_call_set_notify(call, register_agent_cb, NULL, NULL);
	dbus_pending_call_unref(call);
}

static void unregister_agent(void)
{
	DBusMessage *message;
	const gchar *path = AGENT_PATH;

	agent_registered = FALSE;

	message = dbus_message_new_method_call(NEARD_NAME, NEARD_PATH,
			NEARD_MANAGER_INTERFACE, "UnregisterHandoverAgent");

	if (!message) {
		error("Couldn't allocate D-Bus message");
		goto unregister;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID);

	if (!g_dbus_send_message(btd_get_dbus_connection(), message))
		error("D-Bus send failed");

unregister:
	g_dbus_unregister_interface(btd_get_dbus_connection(), AGENT_PATH,
							AGENT_INTERFACE);
}

static void read_local_complete(struct btd_adapter *adapter, uint8_t *hash,
					uint8_t *randomizer, void *user_data)
{
	DBusMessage *msg = user_data;
	DBusMessage *reply;

	DBG("");

	if (!agent_registered) {
		dbus_message_unref(msg);

		if (agent_register_postpone) {
			agent_register_postpone = FALSE;
			register_agent();
		}

		return;
	}

	if (hash && randomizer) {
		int len;
		uint8_t eir[NFC_OOB_EIR_MAX];
		uint8_t *peir = eir;
		DBusMessageIter iter;
		DBusMessageIter dict;

		len = eir_create_oob(adapter_get_address(adapter),
				btd_adapter_get_name(adapter),
				btd_adapter_get_class(adapter), hash,
				randomizer, main_opts.did_vendor,
				main_opts.did_product, main_opts.did_version,
				main_opts.did_source,
				btd_adapter_get_services(adapter), eir);

		reply = dbus_message_new_method_return(msg);

		dbus_message_iter_init_append(reply, &iter);

		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

		dict_append_array(&dict, "EIR", DBUS_TYPE_BYTE, &peir, len);

		dbus_message_iter_close_container(&iter, &dict);

	} else {
		reply = error_reply(msg, EIO);
	}

	dbus_message_unref(msg);

	if (!g_dbus_send_message(btd_get_dbus_connection(), reply))
		error("D-Bus send failed");
}

static void bonding_complete(struct btd_adapter *adapter, bdaddr_t *bdaddr,
					uint8_t status, void *user_data)
{
	DBusMessage *msg = user_data;
	DBusMessage *reply;

	DBG("");

	if (!agent_registered) {
		dbus_message_unref(msg);

		if (agent_register_postpone) {
			agent_register_postpone = FALSE;
			register_agent();
		}

		return;
	}

	if (status)
		reply = error_reply(msg, EIO);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	dbus_message_unref(msg);

	if (!g_dbus_send_message(btd_get_dbus_connection(), reply))
		error("D-Bus send failed");
}

/* returns 1 if pairing is not needed */
static int process_eir(struct btd_adapter *adapter, uint8_t *eir, size_t size,
							bdaddr_t *remote)
{
	struct btd_device *device;
	struct eir_data eir_data;
	char remote_address[18];

	DBG("size %zu", size);

	memset(&eir_data, 0, sizeof(eir_data));

	if (eir_parse_oob(&eir_data, eir, size) < 0)
		return -EINVAL;

	ba2str(&eir_data.addr, remote_address);

	DBG("hci%u remote:%s", adapter_get_dev_id(adapter), remote_address);

	device = adapter_find_device(adapter, remote_address);

	/* If already paired do nothing */
	if (device && device_is_paired(device)) {
		DBG("already paired");
		eir_data_free(&eir_data);
		return 1;
	}

	/* Pairing in progress... */
	if (device && device_is_bonding(device, NULL)) {
		DBG("pairing in progress");
		eir_data_free(&eir_data);
		return -EINPROGRESS;
	}

	/* If we have unpaired device hanging around, purge it */
	if (device)
		adapter_remove_device(adapter, device, TRUE);

	/* store OOB data */
	if (eir_data.class != 0)
		write_remote_class(adapter_get_address(adapter),
					&eir_data.addr, eir_data.class);

	/* TODO handle incomplete name? */
	if (eir_data.name)
		write_device_name(adapter_get_address(adapter), &eir_data.addr,
						BDADDR_BREDR, eir_data.name);

	if (eir_data.hash)
		btd_adapter_add_remote_oob_data(adapter, &eir_data.addr,
					eir_data.hash, eir_data.randomizer);

	/* TODO handle UUIDs? */

	if (remote)
		bacpy(remote, &eir_data.addr);

	eir_data_free(&eir_data);

	return 0;
}

static int process_params(DBusMessage *msg, struct btd_adapter *adapter,
							bdaddr_t *remote)
{
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessageIter value;
	DBusMessageIter entry;
	const char *key;
	int type;

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(&iter, &dict);

	type = dbus_message_iter_get_arg_type(&dict);
	if (type != DBUS_TYPE_DICT_ENTRY) {
		if (!remote && type == DBUS_TYPE_INVALID)
			return 1;

		return -EINVAL;
	}

	dbus_message_iter_recurse(&dict, &entry);

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
		return -EINVAL;

	dbus_message_iter_get_basic(&entry, &key);
	dbus_message_iter_next(&entry);

	dbus_message_iter_recurse(&entry, &value);

	/* All keys have byte array type values */
	if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	if (strcasecmp(key, "EIR") == 0) {
		DBusMessageIter array;
		uint8_t *eir;
		int size;

		dbus_message_iter_recurse(&value, &array);
		dbus_message_iter_get_fixed_array(&array, &eir, &size);

		return process_eir(adapter, eir, size, remote);
	} else if (strcasecmp(key, "nokia.com:bt") == 0) {
		/* TODO add support for Nokia BT 2.0 proprietary stuff */
		return -ENOTSUP;
	}

	return -EINVAL;
}

static int check_adapter(struct btd_adapter *adapter)
{
	gboolean pairable;

	if (!adapter)
		return -ENOENT;

	if (btd_adapter_check_oob_handler(adapter))
		return -EINPROGRESS;

	btd_adapter_get_mode(adapter, NULL, NULL, NULL, &pairable);

	if (!pairable || !adapter_get_agent(adapter))
		return -ENOENT;

	if (!btd_adapter_ssp_enabled(adapter))
		return -ENOTSUP;

	return 0;
}

static DBusMessage *push_oob(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter;
	struct agent *agent;
	struct oob_handler *handler;
	bdaddr_t remote;
	int ret;

	DBG("");

	adapter = manager_get_default_adapter();
	ret = check_adapter(adapter);
	if (ret < 0)
		return error_reply(msg, -ret);

	ret = process_params(msg, adapter, &remote);
	if (ret < 0)
		return error_reply(msg, -ret);

	/* already paired, reply immediately */
	if (ret > 0)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	agent = adapter_get_agent(adapter);

	ret = adapter_create_bonding(adapter, &remote, BDADDR_BREDR,
					agent_get_io_capability(agent));
	if (ret < 0)
		return error_reply(msg, -ret);

	handler = g_new0(struct oob_handler, 1);
	handler->bonding_cb = bonding_complete;
	bacpy(&handler->remote_addr, &remote);
	handler->user_data = dbus_message_ref(msg);

	btd_adapter_set_oob_handler(adapter, handler);

	return NULL;
}

static DBusMessage *request_oob(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct btd_adapter *adapter;
	struct oob_handler *handler;
	int ret;

	DBG("");

	adapter = manager_get_default_adapter();
	ret = check_adapter(adapter);
	if (ret < 0)
		return error_reply(msg, -ret);

	ret = process_params(msg, adapter, NULL);
	if (ret < 0)
		return error_reply(msg, -ret);

	ret = btd_adapter_read_local_oob_data(adapter);
	if (ret < 0)
		return error_reply(msg, -ret);

	handler = g_new0(struct oob_handler, 1);
	handler->read_local_cb = read_local_complete;
	handler->user_data = dbus_message_ref(msg);

	btd_adapter_set_oob_handler(adapter, handler);

	return NULL;
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("");

	agent_registered = FALSE;
	g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable neard_methods[] = {
	{ GDBUS_ASYNC_METHOD("RequestOOB",
			GDBUS_ARGS({ "data", "a{sv}" }),
			GDBUS_ARGS({ "data", "a{sv}" }), request_oob) },
	{ GDBUS_ASYNC_METHOD("PushOOB",
			GDBUS_ARGS({ "data", "a{sv}"}), NULL, push_oob) },
	{ GDBUS_METHOD("Release", NULL, NULL, release) },
	{ }
};

static void neard_appeared(DBusConnection *conn, void *user_data)
{
	struct btd_adapter *adapter;

	DBG("");

	if (!g_dbus_register_interface(conn, AGENT_PATH, AGENT_INTERFACE,
						neard_methods,
						NULL, NULL, NULL, NULL)) {
		error("neard interface init failed on path " AGENT_PATH);
		return;
	}

	/*
	 * If there is pending action ongoing when neard appeared, possibly
	 * due to neard crash or release before action was completed, postpone
	 * register until action is finished.
	 */
	adapter = manager_get_default_adapter();
	if (adapter && btd_adapter_check_oob_handler(adapter))
		agent_register_postpone = TRUE;
	else
		register_agent();
}

static void neard_vanished(DBusConnection *conn, void *user_data)
{
	DBG("");

	/* neard existed without unregistering agent */
	if (agent_registered) {
		agent_registered = FALSE;
		g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);
	}
}

static int neard_init(void)
{
	DBG("Setup neard plugin");

	watcher_id = g_dbus_add_service_watch(btd_get_dbus_connection(),
						NEARD_NAME, neard_appeared,
						neard_vanished, NULL, NULL);
	if (watcher_id == 0)
		return -ENOMEM;

	return 0;
}

static void neard_exit(void)
{
	DBG("Cleanup neard plugin");

	g_dbus_remove_watch(btd_get_dbus_connection(), watcher_id);
	watcher_id = 0;

	if (agent_registered)
		unregister_agent();
}

BLUETOOTH_PLUGIN_DEFINE(neard, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						neard_init, neard_exit)
