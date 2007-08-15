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
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <glib.h>
#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"
#include "textfile.h"

#include "ipc.h"
#include "device.h"
#include "avdtp.h"
#include "headset.h"
#include "sink.h"

static DBusHandlerResult device_get_address(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *device = data;
	DBusMessage *reply;
	char address[18], *ptr = address;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	ba2str(&device->dst, address);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
							DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, array_iter;
	struct device *device = data;
	DBusMessage *reply;
	const char *iface;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING,
						&array_iter);

	if (device->headset &&
			headset_get_state(device) >= HEADSET_STATE_CONNECTED) {
		iface = AUDIO_HEADSET_INTERFACE;
		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &iface);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable device_methods[] = {
	{ "GetAddress",			device_get_address,	"",	"s" },
	{ "GetConnectedInterfaces",	device_get_connected,	"",	"s" },
	{ NULL, NULL, NULL, NULL }
};

static void device_free(struct device *dev)
{
	if (dev->headset)
		headset_free(dev);

	if (dev->sink)
		sink_free(dev);

	if (dev->conn)
		dbus_connection_unref(dev->conn);

	if (dev->adapter_path)
		g_free(dev->adapter_path);

	if (dev->path)
		g_free(dev->path);

	g_free(dev);
}

static void device_unregister(DBusConnection *conn, void *data)
{
	struct device *device = data;

	info("Unregistered device path:%s", device->path);

	device_free(device);
}

char *find_adapter(DBusConnection *conn, bdaddr_t *src)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	char address[18], *addr_ptr = address;
	char *path, *ret;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Manager",
						"FindAdapter");
	if (!msg) {
		error("Unable to allocate new method call");
		return NULL;
	}

	ba2str(src, address);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
				 DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1,
								&derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
				dbus_set_error_from_message(&derr, reply)) {
		error("FindAdapter(%s) failed: %s", address, derr.message);
		dbus_error_free(&derr);
		return NULL;
	}

	dbus_error_init(&derr);
	dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Unable to get message args");
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return FALSE;
	}

	ret = g_strdup(path);

	dbus_message_unref(reply);

	debug("Got path %s for adapter with address %s", ret, address);

	return ret;
}

struct device *device_register(DBusConnection *conn,
					const char *path, bdaddr_t *bda)
{
	struct device *dev;
	bdaddr_t src;
	int dev_id;
	char *adapter_path;

	if (!conn || !path)
		return NULL;

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0))
		return NULL;

	adapter_path = find_adapter(conn, &src);
	if (!adapter_path)
		return NULL;

	dev = g_new0(struct device, 1);

	if (!dbus_connection_create_object_path(conn, path, dev,
							device_unregister)) {
		error("D-Bus failed to register %s path", path);
		device_free(dev);
		return NULL;
	}

	if (!dbus_connection_register_interface(conn, path,
			AUDIO_DEVICE_INTERFACE, device_methods, NULL, NULL)) {
		error("Failed to register %s interface to %s",
					AUDIO_DEVICE_INTERFACE, path);
		dbus_connection_destroy_object_path(conn, path);
		return NULL;
	}

	dev->path = g_strdup(path);
	bacpy(&dev->dst, bda);
	bacpy(&dev->src, &src);
	dev->conn = dbus_connection_ref(conn);
	dev->adapter_path = adapter_path;

	return dev;
}

int device_store(struct device *dev, gboolean is_default)
{
	char value[64];
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	int offset = 0;

	if (!dev->path)
		return -EINVAL;

	ba2str(&dev->dst, dst_addr);
	ba2str(&dev->src, src_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "audio");
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (is_default)
		textfile_put(filename, "default", dst_addr);
	if (dev->headset) {
		snprintf(value, 64, "headset ");
		offset += strlen("headset ");
	}
	if (dev->gateway) {
		snprintf(value + offset, 64 - offset, "gateway ");
		offset += strlen("gateway ");
	}
	if (dev->sink) {
		snprintf(value + offset, 64 - offset, "sink ");
		offset += strlen("sink ");
	}
	if (dev->source) {
		snprintf(value + offset, 64 - offset, "source ");
		offset += strlen("source ");
	}
	if (dev->control) {
		snprintf(value + offset, 64 - offset, "control ");
		offset += strlen("control ");
	}
	if (dev->target)
		snprintf(value + offset, 64 - offset, "target");

	return textfile_put(filename, dst_addr, value);
}

int device_remove_stored(struct device *dev)
{
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];

	ba2str(&dev->dst, dst_addr);
	ba2str(&dev->src, src_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "audio");

	return textfile_del(filename, dst_addr);
}

void device_finish_sdp_transaction(struct device *dev)
{
	char address[18], *addr_ptr = address;
	DBusMessage *msg, *reply;
	DBusError derr;

	ba2str(&dev->dst, address);

	msg = dbus_message_new_method_call("org.bluez", dev->adapter_path,
						"org.bluez.Adapter",
						"FinishRemoteServiceTransaction");
	if (!msg) {
		error("Unable to allocate new method call");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
				 DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(dev->conn,
							msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
				dbus_set_error_from_message(&derr, reply)) {
		error("FinishRemoteServiceTransaction(%s) failed: %s",
						address, derr.message);
		dbus_error_free(&derr);
		return;
	}

	dbus_message_unref(reply);
}

int device_get_config(struct device *dev, int sock, struct ipc_packet *req,
			int pkt_len, struct ipc_data_cfg **rsp, int *fd)
{
	if (dev->sink && sink_is_active(dev))
		return sink_get_config(dev, sock, req, pkt_len, rsp, fd);
	else if (dev->headset && headset_is_active(dev))
		return headset_get_config(dev, sock, req, pkt_len, rsp, fd);
	else if (dev->sink)
		return sink_get_config(dev, sock, req, pkt_len, rsp, fd);
	else if (dev->headset)
		return headset_get_config(dev, sock, req, pkt_len, rsp, fd);

	return -EINVAL;
}

static avdtp_state_t ipc_to_avdtp_state(uint8_t ipc_state)
{
	switch (ipc_state) {
	case STATE_DISCONNECTED:
		return AVDTP_STATE_IDLE;
	case STATE_CONNECTING:
		return AVDTP_STATE_CONFIGURED;
	case STATE_CONNECTED:
		return AVDTP_STATE_OPEN;
	case STATE_STREAM_STARTING:
	case STATE_STREAMING:
		return AVDTP_STATE_STREAMING;
	default:
		error("Unknown ipc state");
		return AVDTP_STATE_IDLE;
	}
}

static headset_state_t ipc_to_hs_state(uint8_t ipc_state)
{
	switch (ipc_state) {
	case STATE_DISCONNECTED:
		return HEADSET_STATE_DISCONNECTED;
	case STATE_CONNECTING:
		return HEADSET_STATE_CONNECT_IN_PROGRESS;
	case STATE_CONNECTED:
		return HEADSET_STATE_CONNECTED;
	case STATE_STREAM_STARTING:
		return HEADSET_STATE_PLAY_IN_PROGRESS;
	case STATE_STREAMING:
		return HEADSET_STATE_PLAYING;
	default:
		error("Unknown ipc state");
		return HEADSET_STATE_DISCONNECTED;
	}
}

void device_set_state(struct device *dev, uint8_t state)
{
	if (dev->sink && sink_is_active(dev))
		sink_set_state(dev, ipc_to_avdtp_state(state));
	else if (dev->headset && headset_is_active(dev))
		headset_set_state(dev, ipc_to_hs_state(state));
}

static uint8_t avdtp_to_ipc_state(avdtp_state_t state)
{
	switch (state) {
	case AVDTP_STATE_IDLE:
		return STATE_DISCONNECTED;
	case AVDTP_STATE_CONFIGURED:
		return STATE_CONNECTING;
	case AVDTP_STATE_OPEN:
		return STATE_CONNECTED;
	case AVDTP_STATE_STREAMING:
		return STATE_STREAMING;
	default:
		error("Unknown avdt state");
		return AVDTP_STATE_IDLE;
	}
}

static uint8_t hs_to_ipc_state(headset_state_t state)
{
	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		return STATE_DISCONNECTED;
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		return STATE_CONNECTING;
	case HEADSET_STATE_CONNECTED:
		return STATE_CONNECTED;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		return STATE_STREAMING;
	default:
		error("Unknown headset state");
		return AVDTP_STATE_IDLE;
	}
}

uint8_t device_get_state(struct device *dev)
{
	avdtp_state_t sink_state;
	headset_state_t hs_state;

	if (dev->sink && sink_is_active(dev)) {
		sink_state = sink_get_state(dev);
		return avdtp_to_ipc_state(sink_state);
	}
	else if (dev->headset && headset_is_active(dev)) {
		hs_state = headset_get_state(dev);
		return hs_to_ipc_state(hs_state);
	}

	return STATE_DISCONNECTED;
}
