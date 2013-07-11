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

#include <glib.h>

#include "lib/uuid.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/service.h"
#include "src/profile.h"

#define CONTROL_CONNECT_TIMEOUT 2
#define SOURCE_RETRY_TIMEOUT 2
#define SINK_RETRY_TIMEOUT SOURCE_RETRY_TIMEOUT
#define SOURCE_RETRIES 1
#define SINK_RETRIES SOURCE_RETRIES

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

static void service_cb(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_profile *profile = btd_service_get_profile(service);

	if (g_str_equal(profile->remote_uuid, A2DP_SINK_UUID))
		sink_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, A2DP_SOURCE_UUID))
		source_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_REMOTE_UUID))
		controller_cb(service, old_state, new_state);
	else if (g_str_equal(profile->remote_uuid, AVRCP_TARGET_UUID))
		target_cb(service, old_state, new_state);
}

static int policy_init(void)
{
	service_id = btd_service_add_state_cb(service_cb, NULL);

	return 0;
}

static void policy_exit(void)
{
	g_slist_free_full(devices, policy_remove);

	btd_service_remove_state_cb(service_id);
}

BLUETOOTH_PLUGIN_DEFINE(policy, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						policy_init, policy_exit)
