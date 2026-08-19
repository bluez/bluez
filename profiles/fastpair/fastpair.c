// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026 Matthias Kurz
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "bluetooth/uuid.h"

#include "btio/btio.h"
#include "src/adapter.h"
#include "src/battery.h"
#include "src/device.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"

#include "message-stream.h"

#define FASTPAIR_BATTERY_SOURCE "Fast Pair Message Stream"
#define FASTPAIR_RECONNECT_MIN 1
#define FASTPAIR_RECONNECT_MAX 60

struct fastpair {
	int ref_count;
	struct btd_service *service;
	GIOChannel *io;
	guint io_id;
	guint reconnect_id;
	guint disconnect_id;
	unsigned int reconnect_delay;
	gint64 connected_since;
	bool handling_bredr_disconnect;
	bool battery_update_received;
	struct fastpair_message_stream *stream;
	struct btd_battery *batteries[FASTPAIR_BATTERY_COUNT];
	bool registration_failed[FASTPAIR_BATTERY_COUNT];
};

static unsigned int service_state_id;

static const char *battery_identifiers[FASTPAIR_BATTERY_COUNT] = {
	"left",
	"right",
	"case",
};

static struct fastpair *fastpair_ref(struct fastpair *fastpair)
{
	__sync_fetch_and_add(&fastpair->ref_count, 1);

	return fastpair;
}

static void fastpair_unref(void *data)
{
	struct fastpair *fastpair = data;

	if (__sync_sub_and_fetch(&fastpair->ref_count, 1))
		return;

	g_free(fastpair);
}

static void fastpair_cancel_reconnect(struct fastpair *fastpair)
{
	if (!fastpair->reconnect_id)
		return;

	g_source_remove(fastpair->reconnect_id);
	fastpair->reconnect_id = 0;
}

static void fastpair_unregister_batteries(struct fastpair *fastpair)
{
	unsigned int i;

	for (i = 0; i < FASTPAIR_BATTERY_COUNT; i++) {
		if (!fastpair->batteries[i])
			continue;

		btd_battery_unregister(fastpair->batteries[i]);
		fastpair->batteries[i] = NULL;
	}

	memset(fastpair->registration_failed, 0,
					sizeof(fastpair->registration_failed));
}

static void fastpair_invalidate_batteries(struct fastpair *fastpair)
{
	unsigned int i;

	for (i = 0; i < FASTPAIR_BATTERY_COUNT; i++) {
		if (!fastpair->batteries[i])
			continue;

		btd_battery_update(fastpair->batteries[i],
						FASTPAIR_BATTERY_UNKNOWN);
		btd_battery_update_charging(fastpair->batteries[i],
						FASTPAIR_CHARGING_UNKNOWN);
	}
}

static void fastpair_handle_bredr_disconnect(struct fastpair *fastpair);

static void fastpair_device_disconnected(struct btd_device *device,
					 gboolean removal, void *user_data)
{
	struct fastpair *fastpair = user_data;

	DBG("%s disconnected%s", device_get_path(device),
					removal ? " and removed" : "");

	fastpair->disconnect_id = 0;
	fastpair_handle_bredr_disconnect(fastpair);
}

static void fastpair_watch_disconnect(struct fastpair *fastpair)
{
	struct btd_device *device;

	if (fastpair->handling_bredr_disconnect || fastpair->disconnect_id)
		return;

	device = btd_service_get_device(fastpair->service);
	fastpair->disconnect_id = device_add_disconnect_watch(device,
					fastpair_device_disconnected,
					fastpair, NULL);
}

static void fastpair_unwatch_disconnect(struct fastpair *fastpair)
{
	struct btd_device *device;

	if (!fastpair->disconnect_id)
		return;

	device = btd_service_get_device(fastpair->service);
	device_remove_disconnect_watch(device, fastpair->disconnect_id);
	fastpair->disconnect_id = 0;
}

static void fastpair_reset_connection(struct fastpair *fastpair)
{
	fastpair_cancel_reconnect(fastpair);

	if (fastpair->io_id) {
		g_source_remove(fastpair->io_id);
		fastpair->io_id = 0;
	}

	if (fastpair->io) {
		g_io_channel_shutdown(fastpair->io, TRUE, NULL);
		g_io_channel_unref(fastpair->io);
		fastpair->io = NULL;
	}

	fastpair_message_stream_free(fastpair->stream);
	fastpair->stream = NULL;
	fastpair->connected_since = 0;
	fastpair->battery_update_received = false;
}

static bool fastpair_stream_was_stable(struct fastpair *fastpair)
{
	gint64 duration;

	if (!fastpair->battery_update_received || !fastpair->connected_since)
		return false;

	duration = g_get_monotonic_time() - fastpair->connected_since;

	return duration >= (gint64) FASTPAIR_RECONNECT_MAX *
							G_USEC_PER_SEC;
}

static void fastpair_handle_bredr_disconnect(struct fastpair *fastpair)
{
	btd_service_state_t state;

	if (fastpair->handling_bredr_disconnect)
		return;

	fastpair->handling_bredr_disconnect = true;
	state = fastpair->service ? btd_service_get_state(fastpair->service) :
						BTD_SERVICE_STATE_UNAVAILABLE;

	fastpair_reset_connection(fastpair);

	if (state == BTD_SERVICE_STATE_CONNECTING)
		btd_service_connecting_complete(fastpair->service, -ENOTCONN);
	else if (state == BTD_SERVICE_STATE_CONNECTED ||
			state == BTD_SERVICE_STATE_DISCONNECTING)
		btd_service_disconnecting_complete(fastpair->service, 0);

	fastpair->reconnect_delay = FASTPAIR_RECONNECT_MIN;
	fastpair_unregister_batteries(fastpair);
	fastpair->handling_bredr_disconnect = false;
}

static void fastpair_schedule_reconnect(struct fastpair *fastpair);

static bool fastpair_connection_error_is_transient(int err)
{
	switch (err) {
	case -ECONNABORTED:
	case -ENOENT:
	case -ENOTSUP:
	case -EPROTO:
		return false;
	default:
		return true;
	}
}

static gboolean fastpair_auto_connect(gpointer user_data)
{
	struct fastpair *fastpair = user_data;
	struct btd_device *device;
	btd_service_state_t state;
	int err;

	fastpair->reconnect_id = 0;
	if (!fastpair->service)
		return FALSE;

	device = btd_service_get_device(fastpair->service);
	state = btd_service_get_state(fastpair->service);

	if (!btd_device_bdaddr_type_connected(device, BDADDR_BREDR)) {
		fastpair_handle_bredr_disconnect(fastpair);
		return FALSE;
	}

	if (state != BTD_SERVICE_STATE_DISCONNECTED)
		return FALSE;

	err = btd_service_connect(fastpair->service);
	if (err < 0 && err != -EALREADY) {
		DBG("unable to auto-connect Message Stream: %s",
		    strerror(-err));
		if (fastpair_connection_error_is_transient(err))
			fastpair_schedule_reconnect(fastpair);
	}

	return FALSE;
}

static void fastpair_schedule_connect(struct fastpair *fastpair,
						unsigned int delay)
{
	struct btd_device *device;
	btd_service_state_t state;

	if (!fastpair->service || fastpair->reconnect_id)
		return;

	device = btd_service_get_device(fastpair->service);
	state = btd_service_get_state(fastpair->service);

	if (!device_is_paired(device, BDADDR_BREDR) ||
			!btd_device_bdaddr_type_connected(device,
							BDADDR_BREDR) ||
			(state != BTD_SERVICE_STATE_UNAVAILABLE &&
			 state != BTD_SERVICE_STATE_DISCONNECTED))
		return;

	if (delay)
		fastpair->reconnect_id = g_timeout_add_seconds(
					delay, fastpair_auto_connect, fastpair);
	else
		fastpair->reconnect_id = g_idle_add(fastpair_auto_connect,
								fastpair);
}

static void fastpair_schedule_auto_connect(struct fastpair *fastpair)
{
	fastpair_schedule_connect(fastpair, 0);
}

static void fastpair_schedule_reconnect(struct fastpair *fastpair)
{
	unsigned int delay = fastpair->reconnect_delay;

	fastpair_schedule_connect(fastpair, delay);
	if (!fastpair->reconnect_id || delay >= FASTPAIR_RECONNECT_MAX)
		return;

	fastpair->reconnect_delay = MIN(delay * 2,
						FASTPAIR_RECONNECT_MAX);
}

static void fastpair_service_state_cb(struct btd_service *service,
				      btd_service_state_t old_state,
				      btd_service_state_t new_state,
				      void *user_data)
{
	struct btd_device *device;
	struct btd_service *fastpair_service;
	struct fastpair *fastpair;

	device = btd_service_get_device(service);
	fastpair_service = btd_device_get_service(device,
						FASTPAIR_MESSAGE_STREAM_UUID);
	if (!fastpair_service)
		return;

	fastpair = btd_service_get_user_data(fastpair_service);
	if (!fastpair)
		return;

	/*
	 * A disconnect watch can run before the connected services settle and
	 * is not invoked again. Use service transitions as a fallback once the
	 * BR/EDR bearer itself is gone.
	 */
	if (!btd_device_bdaddr_type_connected(device, BDADDR_BREDR)) {
		if (new_state == BTD_SERVICE_STATE_UNAVAILABLE ||
				new_state == BTD_SERVICE_STATE_DISCONNECTED)
			fastpair_handle_bredr_disconnect(fastpair);
		return;
	}

	if (new_state != BTD_SERVICE_STATE_CONNECTED)
		return;

	/*
	 * Disconnect watches are one-shot, so restore ours after reconnection.
	 */
	fastpair_watch_disconnect(fastpair);

	if (fastpair_service != service)
		fastpair_schedule_auto_connect(fastpair);
}

static void fastpair_update_batteries(struct fastpair *fastpair,
					      const uint8_t *payload,
					      uint16_t length)
{
	struct fastpair_battery values[FASTPAIR_BATTERY_COUNT];
	struct btd_device *device;
	const char *path;
	unsigned int i;

	if (!fastpair_message_get_batteries(
			FASTPAIR_DEVICE_INFORMATION_GROUP,
			FASTPAIR_BATTERY_UPDATE_CODE, payload, length, values))
		return;

	fastpair->battery_update_received = true;

	device = btd_service_get_device(fastpair->service);
	path = device_get_path(device);

	for (i = 0; i < FASTPAIR_BATTERY_COUNT; i++) {
		if (!fastpair->batteries[i] &&
					!fastpair->registration_failed[i]) {
			fastpair->batteries[i] = btd_battery_register_component(
						path, battery_identifiers[i],
						FASTPAIR_BATTERY_SOURCE);
			if (!fastpair->batteries[i])
				fastpair->registration_failed[i] = true;
		}

		if (!fastpair->batteries[i])
			continue;

		btd_battery_update(fastpair->batteries[i],
					values[i].percentage);
		btd_battery_update_charging(fastpair->batteries[i],
						values[i].charging);
	}
}

static void fastpair_message(uint8_t group, uint8_t code,
			     const uint8_t *payload, uint16_t length,
			     void *user_data)
{
	struct fastpair *fastpair = user_data;

	DBG("group 0x%02x code 0x%02x length %u", group, code, length);

	if (group != FASTPAIR_DEVICE_INFORMATION_GROUP ||
			code != FASTPAIR_BATTERY_UPDATE_CODE)
		return;

	fastpair_update_batteries(fastpair, payload, length);
}

static void fastpair_disconnected(struct fastpair *fastpair, int err,
						bool reconnect)
{
	struct btd_device *device;
	btd_service_state_t state;
	bool bredr_connected;
	bool stream_was_stable;

	if (!fastpair->service) {
		fastpair_reset_connection(fastpair);
		return;
	}

	device = btd_service_get_device(fastpair->service);
	state = btd_service_get_state(fastpair->service);
	bredr_connected = btd_device_bdaddr_type_connected(device,
							BDADDR_BREDR);
	if (!bredr_connected) {
		fastpair_handle_bredr_disconnect(fastpair);
		return;
	}

	stream_was_stable = fastpair_stream_was_stable(fastpair);
	fastpair_reset_connection(fastpair);

	if (state == BTD_SERVICE_STATE_CONNECTING)
		btd_service_connecting_complete(fastpair->service, err);
	else if (state == BTD_SERVICE_STATE_CONNECTED ||
			state == BTD_SERVICE_STATE_DISCONNECTING)
		btd_service_disconnecting_complete(fastpair->service, 0);

	/* Short battery-producing sessions must continue backing off. */
	if (stream_was_stable)
		fastpair->reconnect_delay = FASTPAIR_RECONNECT_MIN;

	fastpair_invalidate_batteries(fastpair);
	if (reconnect)
		fastpair_schedule_reconnect(fastpair);
}

static gboolean fastpair_io_cb(GIOChannel *io, GIOCondition condition,
				       gpointer user_data)
{
	struct fastpair *fastpair = user_data;
	uint8_t buffer[4096];
	ssize_t len;
	int fd;

	if (condition & G_IO_IN) {
		fd = g_io_channel_unix_get_fd(io);

		do {
			len = read(fd, buffer, sizeof(buffer));
		} while (len < 0 && errno == EINTR);

		if (len > 0) {
			if (!fastpair_message_stream_feed(fastpair->stream,
							buffer, len)) {
				error("Invalid Fast Pair Message Stream frame");
				goto failed;
			}
		} else if (!len) {
			goto failed;
		} else if (errno != EAGAIN && errno != EWOULDBLOCK) {
			error("Fast Pair Message Stream read failed: %s",
							strerror(errno));
			goto failed;
		}
	}

	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto failed;

	return TRUE;

failed:
	fastpair->io_id = 0;
	fastpair_disconnected(fastpair, -EIO, true);
	return FALSE;
}

static void fastpair_connect_cb(GIOChannel *io, GError *err,
				gpointer user_data)
{
	struct fastpair *fastpair = user_data;

	/* A closed pending channel can still dispatch its btio source. */
	if (!fastpair->service || fastpair->io != io)
		return;

	if (err) {
		error("Fast Pair Message Stream connection failed: %s",
							err->message);
		fastpair_disconnected(fastpair, -EIO, true);
		return;
	}

	fastpair->stream = fastpair_message_stream_new(fastpair_message,
							fastpair);
	if (!fastpair->stream) {
		fastpair_disconnected(fastpair, -ENOMEM, true);
		return;
	}
	fastpair->connected_since = g_get_monotonic_time();

	fastpair->io_id = g_io_add_watch(io,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			fastpair_io_cb, fastpair);
	memset(fastpair->registration_failed, 0,
					sizeof(fastpair->registration_failed));
	btd_service_connecting_complete(fastpair->service, 0);
}

static int fastpair_connect(struct btd_service *service)
{
	struct fastpair *fastpair = btd_service_get_user_data(service);
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	const sdp_record_t *record;
	sdp_list_t *protos;
	GError *err = NULL;
	GIOChannel *io;
	int channel;

	if (fastpair->io)
		return -EALREADY;

	record = btd_device_get_record(device, FASTPAIR_MESSAGE_STREAM_UUID);
	if (!record)
		return -ENOENT;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get Fast Pair access protocols");
		return -EPROTO;
	}

	channel = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (channel <= 0) {
		error("Unable to get Fast Pair RFCOMM channel");
		return -EPROTO;
	}

	/* Keep the callback context alive until btio destroys its source. */
	fastpair_ref(fastpair);
	io = bt_io_connect(fastpair_connect_cb, fastpair, fastpair_unref, &err,
			BT_IO_OPT_SOURCE_BDADDR,
			btd_adapter_get_address(adapter),
			BT_IO_OPT_DEST_BDADDR, device_get_address(device),
			BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
			BT_IO_OPT_CHANNEL, channel,
			BT_IO_OPT_INVALID);
	if (!io) {
		fastpair_unref(fastpair);
		error("Unable to start Fast Pair connection: %s",
				err ? err->message : strerror(EIO));
		g_clear_error(&err);
		return -EIO;
	}

	fastpair->io = io;

	return 0;
}

static int fastpair_disconnect(struct btd_service *service)
{
	struct fastpair *fastpair = btd_service_get_user_data(service);

	if (!fastpair->io)
		return -ENOTCONN;

	fastpair_disconnected(fastpair, 0, false);

	return 0;
}

static int fastpair_probe(struct btd_service *service)
{
	struct fastpair *fastpair;

	fastpair = g_new0(struct fastpair, 1);
	fastpair->ref_count = 1;
	fastpair->service = service;
	fastpair->reconnect_delay = FASTPAIR_RECONNECT_MIN;
	btd_service_set_user_data(service, fastpair);
	fastpair_watch_disconnect(fastpair);
	fastpair_schedule_auto_connect(fastpair);

	return 0;
}

static void fastpair_remove(struct btd_service *service)
{
	struct fastpair *fastpair = btd_service_get_user_data(service);

	btd_service_set_user_data(service, NULL);
	fastpair_unwatch_disconnect(fastpair);
	fastpair->service = NULL;
	fastpair_reset_connection(fastpair);
	fastpair_unregister_batteries(fastpair);
	fastpair_unref(fastpair);
}

static struct btd_profile fastpair_profile = {
	.name		= "fastpair",
	.priority	= BTD_PROFILE_PRIORITY_LOW,
	.bearer		= BTD_PROFILE_BEARER_BREDR,
	.remote_uuid	= FASTPAIR_MESSAGE_STREAM_UUID,
	.auto_connect	= true,
	.experimental	= true,
	.device_probe	= fastpair_probe,
	.device_remove	= fastpair_remove,
	.connect	= fastpair_connect,
	.disconnect	= fastpair_disconnect,
};

static int fastpair_init(void)
{
	int err;

	err = btd_profile_register(&fastpair_profile);
	if (err < 0)
		return err;

	service_state_id = btd_service_add_state_cb(fastpair_service_state_cb,
								NULL);

	return 0;
}

static void fastpair_exit(void)
{
	btd_service_remove_state_cb(service_state_id);
	btd_profile_unregister(&fastpair_profile);
}

BLUETOOTH_PLUGIN_DEFINE(fastpair, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			fastpair_init, fastpair_exit)
