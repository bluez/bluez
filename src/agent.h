/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include "shared/mgmt.h"

struct agent;

typedef void (*agent_cb) (struct agent *agent, DBusError *err,
				void *user_data);

typedef void (*agent_pincode_cb) (struct agent *agent, DBusError *err,
					const char *pincode, void *user_data);

typedef void (*agent_passkey_cb) (struct agent *agent, DBusError *err,
					uint32_t passkey, void *user_data);

struct agent *agent_ref(struct agent *agent);
void agent_unref(struct agent *agent);

struct agent *agent_get(const char *owner);

int agent_authorize_service(struct agent *agent, struct btd_device *device,
				const char *uuid, agent_cb cb,
				void *user_data, GDestroyNotify destroy);

int agent_request_pincode(struct agent *agent, struct btd_device *device,
				agent_pincode_cb cb, gboolean secure,
				void *user_data, GDestroyNotify destroy);

int agent_request_passkey(struct agent *agent, struct btd_device *device,
				agent_passkey_cb cb, void *user_data,
				GDestroyNotify destroy);

int agent_request_confirmation(struct agent *agent, struct btd_device *device,
				uint32_t passkey, agent_cb cb,
				void *user_data, GDestroyNotify destroy);

int agent_request_authorization(struct agent *agent, struct btd_device *device,
						agent_cb cb, void *user_data,
						GDestroyNotify destroy);

int agent_display_passkey(struct agent *agent, struct btd_device *device,
				uint32_t passkey, uint16_t entered);

int agent_display_pincode(struct agent *agent, struct btd_device *device,
				const char *pincode, agent_cb cb,
				void *user_data, GDestroyNotify destroy);

int agent_cancel(struct agent *agent);

enum mgmt_io_capability agent_get_io_capability(struct agent *agent);

void btd_agent_init(void);
void btd_agent_cleanup(void);
