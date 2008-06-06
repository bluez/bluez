/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"

#include "error.h"
#include "ipc.h"
#include "device.h"
#include "avdtp.h"
#include "control.h"
#include "headset.h"
#include "sink.h"

static DBusMessage *device_get_address(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	char address[18], *ptr = address;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	ba2str(&device->dst, address);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
							DBUS_TYPE_INVALID);

	return reply;
}

static char *get_dev_name(DBusConnection *conn, const bdaddr_t *src,
			const bdaddr_t *bda)
{
	char address[18], filename[PATH_MAX + 1];

	ba2str(src, address);

	/* check if it is in the cache */
	create_name(filename, PATH_MAX, STORAGEDIR, address, "names");

	ba2str(bda, address);
	return textfile_caseget(filename, address);
}

static DBusMessage *device_get_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct audio_device *dev = data;
	DBusMessage *reply;
	const char *name = dev->name ? dev->name : "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *device_get_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	char address[18], *ptr = address;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	ba2str(&device->src, address);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
							DBUS_TYPE_INVALID);

	return reply;
}


static DBusMessage *device_get_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, array_iter;
	struct audio_device *device = data;
	DBusMessage *reply;
	const char *iface;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

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

	return reply;
}

static GDBusMethodTable device_methods[] = {
	{ "GetAddress",			"",	"s",	device_get_address },
	{ "GetName",			"",	"s",	device_get_name },
	{ "GetAdapter",			"",	"s",	device_get_adapter },
	{ "GetConnectedInterfaces",	"",	"as",	device_get_connected },
	{ }
};

static void device_free(struct audio_device *dev)
{
	if (dev->headset)
		headset_free(dev);

	if (dev->sink)
		sink_free(dev);

	if (dev->control)
		control_free(dev);

	if (dev->conn)
		dbus_connection_unref(dev->conn);

	g_free(dev->adapter_path);
	g_free(dev->path);
	g_free(dev->name);

	g_free(dev);
}

static void device_unregister(void *data)
{
	struct audio_device *device = data;

	info("Unregistered device path:%s", device->path);

	device_free(device);
}

struct audio_device *device_register(DBusConnection *conn,
					const char *path, const bdaddr_t *bda)
{
	struct audio_device *dev;
	bdaddr_t src;
	int dev_id;

	if (!conn || !path)
		return NULL;

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0))
		return NULL;

	dev = g_new0(struct audio_device, 1);

	/* FIXME just to maintain compatibility */
	dev->adapter_path = g_strdup_printf("/org/bluez/hci%d", dev_id);
	if (!dev->adapter_path) {
		device_free(dev);
		return NULL;
	}

	if (!g_dbus_register_interface(conn, path,
					AUDIO_DEVICE_INTERFACE,
					device_methods, NULL, NULL,
					dev, device_unregister)) {
		error("Failed to register %s interface to %s",
					AUDIO_DEVICE_INTERFACE, path);
		device_free(dev);
		return NULL;
	}

	dev->name = get_dev_name(conn, &src, bda);
	dev->path = g_strdup(path);
	bacpy(&dev->dst, bda);
	bacpy(&dev->src, &src);
	bacpy(&dev->store, &src);
	dev->conn = dbus_connection_ref(conn);

	return dev;
}

int device_store(struct audio_device *dev, gboolean is_default)
{
	char value[64];
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	int offset = 0;

	if (!dev->path)
		return -EINVAL;

	ba2str(&dev->dst, dst_addr);
	ba2str(&dev->store, src_addr);

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

int device_remove_stored(struct audio_device *dev)
{
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];

	ba2str(&dev->dst, dst_addr);
	ba2str(&dev->store, src_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "audio");

	return textfile_del(filename, dst_addr);
}

void device_finish_sdp_transaction(struct audio_device *dev)
{
	char address[18], *addr_ptr = address;
	DBusMessage *msg;

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

	dbus_connection_send(dev->conn, msg, NULL);

	dbus_message_unref(msg);
}

#if 0
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

uint8_t device_get_state(struct audio_device *dev)
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
	else if (dev->control && control_is_active(dev))
		return STATE_CONNECTED;

	return STATE_DISCONNECTED;
}
#endif

gboolean device_is_connected(struct audio_device *dev, const char *interface)
{
	if (!interface) {
		if ((dev->sink || dev->source) &&
			avdtp_is_connected(&dev->src, &dev->dst))
			return TRUE;

		if (dev->headset && headset_is_active(dev))
			return TRUE;
	}
	else if (!strcmp(interface, AUDIO_SINK_INTERFACE) && dev->sink &&
			avdtp_is_connected(&dev->src, &dev->dst))
		return TRUE;
	else if (!strcmp(interface, AUDIO_SOURCE_INTERFACE) && dev->source &&
			avdtp_is_connected(&dev->src, &dev->dst))
		return TRUE;
	else if (!strcmp(interface, AUDIO_HEADSET_INTERFACE) && dev->headset &&
			headset_is_active(dev))
		return TRUE;
	else if (!strcmp(interface, AUDIO_CONTROL_INTERFACE) && dev->headset &&
			control_is_active(dev))
		return TRUE;

	return FALSE;
}
