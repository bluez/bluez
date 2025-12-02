// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2013  BMW Car IT GmbH. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"

#include "src/shared/queue.h"

#include "log.h"
#include "backtrace.h"

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"

struct btd_service {
	int			ref;
	struct btd_device	*device;
	struct btd_profile	*profile;
	void			*user_data;
	btd_service_state_t	state;
	int			err;
	bool			is_allowed;
	bool			initiator;
	struct queue		*depends;
	struct queue		*dependents;
};

struct service_state_callback {
	btd_service_state_cb	cb;
	void			*user_data;
	unsigned int		id;
};

static GSList *state_callbacks = NULL;

static const char *state2str(btd_service_state_t state)
{
	switch (state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return "unavailable";
	case BTD_SERVICE_STATE_DISCONNECTED:
		return "disconnected";
	case BTD_SERVICE_STATE_CONNECTING:
		return "connecting";
	case BTD_SERVICE_STATE_CONNECTED:
		return "connected";
	case BTD_SERVICE_STATE_DISCONNECTING:
		return "disconnecting";
	}

	return NULL;
}

static void depends_ready(void *item, void *user_data)
{
	struct btd_service *service = item;
	struct btd_service *dep = user_data;
	struct btd_profile_uuid_cb *after = &service->profile->after_services;
	char addr[18];

	if (dep && !queue_remove(service->depends, dep))
		return;
	if (!service->depends || !queue_isempty(service->depends))
		return;

	queue_destroy(service->depends, NULL);
	service->depends = NULL;

	if (!after->count && !after->func)
		return;

	ba2str(device_get_address(service->device), addr);
	DBG("%p: device %s profile %s dependencies ready", service,
						addr, service->profile->name);

	switch (service->state) {
	case BTD_SERVICE_STATE_CONNECTING:
	case BTD_SERVICE_STATE_CONNECTED:
		if (after->func)
			after->func(service);
		break;
	case BTD_SERVICE_STATE_UNAVAILABLE:
	case BTD_SERVICE_STATE_DISCONNECTING:
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	}
}

static void service_ready(struct btd_service *service)
{
	queue_foreach(service->dependents, depends_ready, service);
	queue_destroy(service->dependents, NULL);
	service->dependents = NULL;

	depends_ready(service, NULL);
}

static void change_state(struct btd_service *service, btd_service_state_t state,
									int err)
{
	btd_service_state_t old = service->state;
	char addr[18];
	GSList *l;

	if (state == old)
		return;

	btd_assert(service->device != NULL);
	btd_assert(service->profile != NULL);

	service->state = state;
	service->err = err;

	ba2str(device_get_address(service->device), addr);
	DBG("%p: device %s profile %s state changed: %s -> %s (%d)", service,
					addr, service->profile->name,
					state2str(old), state2str(state), err);

	for (l = state_callbacks; l != NULL; l = g_slist_next(l)) {
		struct service_state_callback *cb = l->data;

		cb->cb(service, old, state, cb->user_data);
	}

	if (state != BTD_SERVICE_STATE_CONNECTING)
		service_ready(service);

	if (state == BTD_SERVICE_STATE_DISCONNECTED)
		service->initiator = false;
}

struct btd_service *btd_service_ref(struct btd_service *service)
{
	service->ref++;

	DBG("%p: ref=%d", service, service->ref);

	return service;
}

static void depends_remove(void *item, void *user_data)
{
	struct btd_service *service = item;

	queue_remove(service->dependents, user_data);
}

static void dependents_remove(void *item, void *user_data)
{
	struct btd_service *service = item;

	queue_remove(service->depends, user_data);
}

void btd_service_unref(struct btd_service *service)
{
	service->ref--;

	DBG("%p: ref=%d", service, service->ref);

	if (service->ref > 0)
		return;

	queue_foreach(service->depends, depends_remove, service);
	queue_foreach(service->dependents, dependents_remove, service);
	queue_destroy(service->depends, NULL);
	queue_destroy(service->dependents, NULL);

	g_free(service);
}

struct btd_service *service_create(struct btd_device *device,
						struct btd_profile *profile)
{
	struct btd_service *service;

	service = g_try_new0(struct btd_service, 1);
	if (!service) {
		error("service_create: failed to alloc memory");
		return NULL;
	}

	service->ref = 1;
	service->device = device; /* Weak ref */
	service->profile = profile;
	service->state = BTD_SERVICE_STATE_UNAVAILABLE;
	service->is_allowed = true;

	return service;
}

int service_probe(struct btd_service *service)
{
	char addr[18];
	int err;

	btd_assert(service->state == BTD_SERVICE_STATE_UNAVAILABLE);

	err = service->profile->device_probe(service);
	if (err == 0) {
		change_state(service, BTD_SERVICE_STATE_DISCONNECTED, 0);
		return 0;
	}

	ba2str(device_get_address(service->device), addr);
	error("%s profile probe failed for %s", service->profile->name, addr);

	return err;
}

void service_remove(struct btd_service *service)
{
	change_state(service, BTD_SERVICE_STATE_DISCONNECTED, -ECONNABORTED);
	change_state(service, BTD_SERVICE_STATE_UNAVAILABLE, 0);
	service->profile->device_remove(service);
	service->device = NULL;
	service->profile = NULL;
	btd_service_unref(service);
}

static void add_depends(struct btd_service *service)
{
	struct btd_profile_uuid_cb *after = &service->profile->after_services;
	unsigned int i;

	queue_foreach(service->depends, depends_remove, service);
	queue_destroy(service->depends, NULL);
	service->depends = queue_new();

	for (i = 0; i < after->count; ++i) {
		const char *uuid = after->uuids[i];
		struct btd_service *dep;

		dep = btd_device_get_service(service->device, uuid);
		if (!dep)
			continue;

		/* Profiles are sorted vs after_uuids, so the dependency will
		 * have started connecting before us if it is going to connect.
		 */
		if (dep->state != BTD_SERVICE_STATE_CONNECTING)
			continue;
		if (queue_find(service->depends, NULL, dep))
			continue;

		queue_push_tail(service->depends, dep);

		if (!dep->dependents)
			dep->dependents = queue_new();
		queue_push_tail(dep->dependents, service);
	}
}

int service_accept(struct btd_service *service, bool initiator)
{
	char addr[18];
	int err;

	switch (service->state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return -EINVAL;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
	case BTD_SERVICE_STATE_CONNECTED:
		return 0;
	case BTD_SERVICE_STATE_DISCONNECTING:
		return -EBUSY;
	}

	if (!service->profile->accept)
		return -ENOSYS;

	if (!service->is_allowed) {
		info("service %s is not allowed",
						service->profile->remote_uuid);
		return -ECONNABORTED;
	}

	service->initiator = initiator;
	add_depends(service);

	err = service->profile->accept(service);
	if (!err)
		goto done;

	ba2str(device_get_address(service->device), addr);
	error("%s profile accept failed for %s", service->profile->name, addr);

	return err;

done:
	if (service->state == BTD_SERVICE_STATE_DISCONNECTED)
		change_state(service, BTD_SERVICE_STATE_CONNECTING, 0);
	return 0;
}

int service_set_connecting(struct btd_service *service)
{
	switch (service->state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return -EINVAL;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
	case BTD_SERVICE_STATE_CONNECTED:
		return 0;
	case BTD_SERVICE_STATE_DISCONNECTING:
		return -EBUSY;
	}

	change_state(service, BTD_SERVICE_STATE_CONNECTING, 0);

	return 0;
}

int btd_service_connect(struct btd_service *service)
{
	struct btd_profile *profile = service->profile;
	char addr[18];
	int err;

	if (!profile->connect)
		return -ENOTSUP;

	if (!btd_adapter_get_powered(device_get_adapter(service->device)))
		return -ENETDOWN;

	switch (service->state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return -EINVAL;
	case BTD_SERVICE_STATE_DISCONNECTED:
		break;
	case BTD_SERVICE_STATE_CONNECTING:
		return 0;
	case BTD_SERVICE_STATE_CONNECTED:
		return -EALREADY;
	case BTD_SERVICE_STATE_DISCONNECTING:
		return -EBUSY;
	}

	if (!service->is_allowed) {
		info("service %s is not allowed",
						service->profile->remote_uuid);
		return -ECONNABORTED;
	}

	add_depends(service);

	err = profile->connect(service);
	if (err == 0) {
		service->initiator = true;
		change_state(service, BTD_SERVICE_STATE_CONNECTING, 0);
		return 0;
	}

	ba2str(device_get_address(service->device), addr);
	error("%s profile connect failed for %s: %s", profile->name, addr,
								strerror(-err));

	return err;
}

int btd_service_disconnect(struct btd_service *service)
{
	struct btd_profile *profile = service->profile;
	char addr[18];
	int err;

	if (!profile->disconnect)
		return -ENOTSUP;

	switch (service->state) {
	case BTD_SERVICE_STATE_UNAVAILABLE:
		return -EINVAL;
	case BTD_SERVICE_STATE_DISCONNECTED:
		return -EALREADY;
	case BTD_SERVICE_STATE_DISCONNECTING:
		return 0;
	case BTD_SERVICE_STATE_CONNECTING:
	case BTD_SERVICE_STATE_CONNECTED:
		break;
	}

	change_state(service, BTD_SERVICE_STATE_DISCONNECTING, 0);

	err = profile->disconnect(service);
	if (err == 0)
		return 0;

	if (err == -ENOTCONN) {
		btd_service_disconnecting_complete(service, 0);
		return 0;
	}

	ba2str(device_get_address(service->device), addr);
	error("%s profile disconnect failed for %s: %s", profile->name, addr,
								strerror(-err));

	btd_service_disconnecting_complete(service, err);

	return err;
}

struct btd_device *btd_service_get_device(const struct btd_service *service)
{
	return service->device;
}

struct btd_profile *btd_service_get_profile(const struct btd_service *service)
{
	return service->profile;
}

void btd_service_set_user_data(struct btd_service *service, void *user_data)
{
	service->user_data = user_data;
}

void *btd_service_get_user_data(const struct btd_service *service)
{
	return service->user_data;
}

btd_service_state_t btd_service_get_state(const struct btd_service *service)
{
	return service->state;
}

int btd_service_get_error(const struct btd_service *service)
{
	return service->err;
}

bool btd_service_is_initiator(const struct btd_service *service)
{
	return service->initiator;
}

unsigned int btd_service_add_state_cb(btd_service_state_cb cb, void *user_data)
{
	struct service_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new0(struct service_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	state_callbacks = g_slist_append(state_callbacks, state_cb);

	return state_cb->id;
}

bool btd_service_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = state_callbacks; l != NULL; l = g_slist_next(l)) {
		struct service_state_callback *cb = l->data;

		if (cb && cb->id == id) {
			state_callbacks = g_slist_remove(state_callbacks, cb);
			g_free(cb);
			return true;
		}
	}

	return false;
}

void btd_service_set_allowed(struct btd_service *service, bool allowed)
{
	if (allowed == service->is_allowed)
		return;

	service->is_allowed = allowed;

	if (!allowed && (service->state == BTD_SERVICE_STATE_CONNECTING ||
			service->state == BTD_SERVICE_STATE_CONNECTED)) {
		btd_service_disconnect(service);
		return;
	}
}

bool btd_service_is_allowed(struct btd_service *service)
{
	return service->is_allowed;
}

void btd_service_connecting_complete(struct btd_service *service, int err)
{
	if (service->state != BTD_SERVICE_STATE_DISCONNECTED &&
			service->state != BTD_SERVICE_STATE_CONNECTING)
		return;

	if (err == 0)
		change_state(service, BTD_SERVICE_STATE_CONNECTED, 0);
	else
		change_state(service, BTD_SERVICE_STATE_DISCONNECTED, err);
}

void btd_service_disconnecting_complete(struct btd_service *service, int err)
{
	if (service->state != BTD_SERVICE_STATE_CONNECTED &&
			service->state != BTD_SERVICE_STATE_DISCONNECTING)
		return;

	if (err == 0)
		change_state(service, BTD_SERVICE_STATE_DISCONNECTED, 0);
	else /* If disconnect fails, we assume it remains connected */
		change_state(service, BTD_SERVICE_STATE_CONNECTED, err);
}
