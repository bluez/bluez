/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation.
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
#include <time.h>

#include <glib.h>

#include "lib/uuid.h"
#include "lib/mgmt.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/service.h"
#include "src/profile.h"
#include "src/hcid.h"

#define CONTROL_CONNECT_TIMEOUT 2
#define SOURCE_RETRY_TIMEOUT 2
#define SINK_RETRY_TIMEOUT SOURCE_RETRY_TIMEOUT
#define SOURCE_RETRIES 1
#define SINK_RETRIES SOURCE_RETRIES

/* Tracking of remote services to be auto-reconnected upon link loss */

#define RECONNECT_GIVE_UP (3 * 60)
#define RECONNECT_TIMEOUT 1

struct reconnect_data {
	struct btd_device *dev;
	bool reconnect;
	GSList *services;
	guint timer;
	bool active;
	time_t start;
	int timeout;
};

static const char *default_reconnect[] = {
			HSP_AG_UUID, HFP_AG_UUID, A2DP_SOURCE_UUID, NULL };
static char **reconnect_uuids = NULL;
static GSList *reconnects = NULL;

static unsigned int service_id = 0;
static GSList *devices = NULL;

struct policy_data {
	struct btd_device *dev;

	guint source_timer;
	uint8_t source_retries;
	guint sink_timer;
	uint8_t sink_retries;
	guint ct_timer;
	guint tg_timer;
};

static void policy_connect(struct policy_data *data,
						struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);

	DBG("%s profile %s", device_get_path(data->dev), profile->name);

	btd_service_connect(service);
}

static void policy_disconnect(struct policy_data *data,
						struct btd_service *service)
{
	struct btd_profile *profile = btd_service_get_profile(service);

	DBG("%s profile %s", device_get_path(data->dev), profile->name);

	btd_service_disconnect(service);
}

static gboolean policy_connect_ct(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->ct_timer = 0;

	service = btd_device_get_service(data->dev, AVRCP_REMOTE_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_ct_timer(struct policy_data *data)
{
	if (data->ct_timer > 0)
		g_source_remove(data->ct_timer);

	data->ct_timer = g_timeout_add_seconds(CONTROL_CONNECT_TIMEOUT,
						policy_connect_ct, data);
}

static struct policy_data *find_data(struct btd_device *dev)
{
	GSList *l;

	for (l = devices; l; l = l->next) {
		struct policy_data *data = l->data;

		if (data->dev == dev)
			return data;
	}

	return NULL;
}

static void policy_remove(void *user_data)
{
	struct policy_data *data = user_data;

	if (data->source_timer > 0)
		g_source_remove(data->source_timer);

	if (data->sink_timer > 0)
		g_source_remove(data->sink_timer);

	if (data->ct_timer > 0)
		g_source_remove(data->ct_timer);

	if (data->tg_timer > 0)
		g_source_remove(data->tg_timer);

	g_free(data);
}

static struct policy_data *policy_get_data(struct btd_device *dev)
{
	struct policy_data *data;

	data = find_data(dev);
	if (data != NULL)
		return data;

	data = g_new0(struct policy_data, 1);
	data->dev = dev;

	devices = g_slist_prepend(devices, data);

	return data;
}

static gboolean policy_connect_sink(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->source_timer = 0;
	data->sink_retries++;

	service = btd_device_get_service(data->dev, A2DP_SINK_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_sink_timer(struct policy_data *data)
{
	if (data->sink_timer > 0)
		g_source_remove(data->sink_timer);

	data->sink_timer = g_timeout_add_seconds(SINK_RETRY_TIMEOUT,
							policy_connect_sink,
							data);
}

static void sink_cb(struct btd_service *service, btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;
	struct btd_service *controller;

	controller = btd_device_get_service(dev, AVRCP_REMOTE_UUID);
	if (controller == NULL)
		return;

	data = policy_get_data(dev);

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->sink_timer > 0) {
			g_source_remove(data->sink_timer);
			data->sink_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->sink_retries < SINK_RETRIES)
					policy_set_sink_timer(data);
				else
					data->sink_retries = 0;
				break;
			} else if (data->sink_timer > 0) {
				g_source_remove(data->sink_timer);
				data->sink_timer = 0;
			}
		}

		if (data->ct_timer > 0) {
			g_source_remove(data->ct_timer);
			data->ct_timer = 0;
		} else if (btd_service_get_state(controller) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, controller);
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->sink_timer > 0) {
			g_source_remove(data->sink_timer);
			data->sink_timer = 0;
		}

		/* Check if service initiate the connection then proceed
		 * immediatelly otherwise set timer
		 */
		if (old_state == BTD_SERVICE_STATE_CONNECTING)
			policy_connect(data, controller);
		else if (btd_service_get_state(controller) !=
						BTD_SERVICE_STATE_CONNECTED)
			policy_set_ct_timer(data);
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static gboolean policy_connect_tg(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->tg_timer = 0;

	service = btd_device_get_service(data->dev, AVRCP_TARGET_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_tg_timer(struct policy_data *data)
{
	if (data->tg_timer > 0)
		g_source_remove(data->tg_timer);

	data->tg_timer = g_timeout_add_seconds(CONTROL_CONNECT_TIMEOUT,
							policy_connect_tg,
							data);
}

static gboolean policy_connect_source(gpointer user_data)
{
	struct policy_data *data = user_data;
	struct btd_service *service;

	data->source_timer = 0;
	data->source_retries++;

	service = btd_device_get_service(data->dev, A2DP_SOURCE_UUID);
	if (service != NULL)
		policy_connect(data, service);

	return FALSE;
}

static void policy_set_source_timer(struct policy_data *data)
{
	if (data->source_timer > 0)
		g_source_remove(data->source_timer);

	data->source_timer = g_timeout_add_seconds(SOURCE_RETRY_TIMEOUT,
							policy_connect_source,
							data);
}

static void source_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;
	struct btd_service *target;

	target = btd_device_get_service(dev, AVRCP_TARGET_UUID);
	if (target == NULL)
		return;

	data = policy_get_data(dev);

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->source_timer > 0) {
			g_source_remove(data->source_timer);
			data->source_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
		if (old_state == BTD_SERVICE_STATE_CONNECTING) {
			int err = btd_service_get_error(service);

			if (err == -EAGAIN) {
				if (data->source_retries < SOURCE_RETRIES)
					policy_set_source_timer(data);
				else
					data->source_retries = 0;
				break;
			} else if (data->source_timer > 0) {
				g_source_remove(data->source_timer);
				data->source_timer = 0;
			}
		}

		if (data->tg_timer > 0) {
			g_source_remove(data->tg_timer);
			data->tg_timer = 0;
		} else if (btd_service_get_state(target) !=
						BTD_SERVICE_STATE_DISCONNECTED)
			policy_disconnect(data, target);
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->source_timer > 0) {
			g_source_remove(data->source_timer);
			data->source_timer = 0;
		}

		/* Check if service initiate the connection then proceed
		 * immediatelly otherwise set timer
		 */
		if (old_state == BTD_SERVICE_STATE_CONNECTING)
			policy_connect(data, target);
		else if (btd_service_get_state(target) !=
						BTD_SERVICE_STATE_CONNECTED)
			policy_set_tg_timer(data);
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void controller_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;

	data = find_data(dev);
	if (data == NULL)
		return;

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->ct_timer > 0) {
			g_source_remove(data->ct_timer);
			data->ct_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->ct_timer > 0) {
			g_source_remove(data->ct_timer);
			data->ct_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void target_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct policy_data *data;

	data = find_data(dev);
	if (data == NULL)
		return;

	switch (new_state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		if (data->tg_timer > 0) {
			g_source_remove(data->tg_timer);
			data->tg_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		break;
	case BTD_SERVICE_STATE_CONNECTED:
		if (data->tg_timer > 0) {
			g_source_remove(data->tg_timer);
			data->tg_timer = 0;
		}
		break;
	case BTD_SERVICE_STATE_DISCONNECTING:
		break;
	}
}

static void reconnect_reset(struct reconnect_data *reconnect)
{
	reconnect->start = 0;
	reconnect->timeout = 1;

	if (reconnect->timer > 0) {
		g_source_remove(reconnect->timer);
		reconnect->timer = 0;
	}
}

static bool reconnect_match(const char *uuid)
{
	char **str;

	if (!reconnect_uuids)
		return false;

	for (str = reconnect_uuids; *str; str++) {
		if (!bt_uuid_strcmp(uuid, *str))
			return true;
	}

	return false;
}

static struct reconnect_data *reconnect_find(struct btd_device *dev)
{
	GSList *l;

	for (l = reconnects; l; l = g_slist_next(l)) {
		struct reconnect_data *reconnect = l->data;

		if (reconnect->dev == dev)
			return reconnect;
	}

	return NULL;
}

static struct reconnect_data *reconnect_add(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct reconnect_data *reconnect;

	reconnect = reconnect_find(dev);
	if (!reconnect) {
		reconnect = g_new0(struct reconnect_data, 1);
		reconnect->dev = dev;
		reconnects = g_slist_append(reconnects, reconnect);
	}

	if (g_slist_find(reconnect->services, service))
		return reconnect;

	reconnect->services = g_slist_append(reconnect->services,
						btd_service_ref(service));

	return reconnect;
}

static void reconnect_destroy(gpointer data)
{
	struct reconnect_data *reconnect = data;

	if (reconnect->timer > 0)
		g_source_remove(reconnect->timer);

	g_slist_free_full(reconnect->services,
					(GDestroyNotify) btd_service_unref);
	g_free(reconnect);
}

static void reconnect_remove(struct btd_service *service)
{
	struct btd_device *dev = btd_service_get_device(service);
	struct reconnect_data *reconnect;
	GSList *l;

	reconnect = reconnect_find(dev);
	if (!reconnect)
		return;

	l = g_slist_find(reconnect->services, service);
	if (!l)
		return;

	reconnect->services = g_slist_delete_link(reconnect->services, l);
	btd_service_unref(service);

	if (reconnect->services)
		return;

	reconnects = g_slist_remove(reconnects, reconnect);

	if (reconnect->timer > 0)
		g_source_remove(reconnect->timer);

	g_free(reconnect);
}

static void service_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_profile *profile = btd_service_get_profile(service);
	struct reconnect_data *reconnect;

	if (g_str_equal(profile->remote_uuid, A2DP_SINK_UUID))
		sink_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, A2DP_SOURCE_UUID))
		source_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_REMOTE_UUID))
		controller_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_TARGET_UUID))
		target_cb(service, old_state, new_state);

	/*
	 * Return if the reconnection feature is not enabled (all
	 * subsequent code in this function is about that).
	 */
	if (!reconnect_uuids || !reconnect_uuids[0])
		return;

	/*
	 * We're only interested in reconnecting profiles which have set
	 * auto_connect to true.
	 */
	if (!profile->auto_connect)
		return;

	/*
	 * If the service went away remove it from the reconnection
	 * tracking. The function will remove the entire tracking data
	 * if this was the last service for the device.
	 */
	if (new_state == BTD_SERVICE_STATE_UNAVAILABLE) {
		reconnect_remove(service);
		return;
	}

	if (new_state != BTD_SERVICE_STATE_CONNECTED)
		return;

	/*
	 * Add an entry to track reconnections. The function will return
	 * an existing entry if there is one.
	 */
	reconnect = reconnect_add(service);

	reconnect->active = false;
	reconnect_reset(reconnect);

	/*
	 * Should this device be reconnected? A matching UUID might not
	 * be the first profile that's connected so we might have an
	 * entry but with the reconnect flag set to false.
	 */
	if (!reconnect->reconnect)
		reconnect->reconnect = reconnect_match(profile->remote_uuid);

	DBG("Added %s reconnect %u", profile->name, reconnect->reconnect);
}

static gboolean reconnect_timeout(gpointer data)
{
	struct reconnect_data *reconnect = data;
	int err;

	DBG("Reconnecting profiles");

	/* Mark the GSource as invalid */
	reconnect->timer = 0;

	/* Increase timeout for the next attempt if this * one fails. */
	reconnect->timeout *= 2;

	err = btd_device_connect_services(reconnect->dev, reconnect->services);
	if (err < 0) {
		error("Reconnecting services failed: %s (%d)",
							strerror(-err), -err);
		reconnect_reset(reconnect);
		return FALSE;
	}

	reconnect->active = true;

	if (!reconnect->start)
		reconnect->start = time(NULL);

	return FALSE;
}

static void disconnect_cb(struct btd_device *dev, uint8_t reason)
{
	struct reconnect_data *reconnect;

	DBG("reason %u", reason);

	if (reason != MGMT_DEV_DISCONN_TIMEOUT)
		return;

	reconnect = reconnect_find(dev);
	if (!reconnect || !reconnect->reconnect)
		return;

	DBG("Device %s identified for auto-reconnection",
							device_get_path(dev));

	reconnect->timer = g_timeout_add_seconds(reconnect->timeout,
							reconnect_timeout,
							reconnect);
}

static void conn_fail_cb(struct btd_device *dev, uint8_t status)
{
	struct reconnect_data *reconnect;
	time_t duration;

	DBG("status %u", status);

	reconnect = reconnect_find(dev);
	if (!reconnect || !reconnect->reconnect)
		return;

	if (!reconnect->active)
		return;

	reconnect->active = false;

	/* Give up if we were powered off */
	if (status == MGMT_STATUS_NOT_POWERED) {
		reconnect_reset(reconnect);
		return;
	}

	/* Give up if we've tried for too long */
	duration = time(NULL) - reconnect->start;
	if (duration + reconnect->timeout >= RECONNECT_GIVE_UP) {
		reconnect_reset(reconnect);
		return;
	}

	reconnect->timer = g_timeout_add_seconds(reconnect->timeout,
							reconnect_timeout,
							reconnect);
}

static int policy_init(void)
{
	GError *gerr = NULL;
	GKeyFile *conf;

	service_id = btd_service_add_state_cb(service_cb, NULL);

	conf = btd_get_main_conf();
	if (!conf) {
		reconnect_uuids = g_strdupv((char **) default_reconnect);
		goto add_cb;
	}

	reconnect_uuids = g_key_file_get_string_list(conf, "Policy",
							"ReconnectUUIDs",
							NULL, &gerr);
	if (gerr) {
		g_error_free(gerr);
		reconnect_uuids = g_strdupv((char **) default_reconnect);
		goto add_cb;
	}
add_cb:
	if (reconnect_uuids && reconnect_uuids[0]) {
		btd_add_disconnect_cb(disconnect_cb);
		btd_add_conn_fail_cb(conn_fail_cb);
	}

	return 0;
}

static void policy_exit(void)
{
	btd_remove_disconnect_cb(disconnect_cb);
	btd_remove_conn_fail_cb(conn_fail_cb);

	if (reconnect_uuids)
		g_strfreev(reconnect_uuids);

	g_slist_free_full(reconnects, reconnect_destroy);

	g_slist_free_full(devices, policy_remove);

	btd_service_remove_state_cb(service_id);
}

BLUETOOTH_PLUGIN_DEFINE(policy, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						policy_init, policy_exit)
