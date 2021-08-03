// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "lib/bluetooth.h"

#include "src/adapter.h"
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"

#include "src/shared/queue.h"

/* |policy_data| has the same life cycle as btd_adapter */
static struct btd_admin_policy {
	struct btd_adapter *adapter;
	uint16_t adapter_id;
} *policy_data = NULL;

static struct btd_admin_policy *admin_policy_new(struct btd_adapter *adapter)
{
	struct btd_admin_policy *admin_policy = NULL;

	admin_policy = g_try_malloc(sizeof(*admin_policy));
	if (!admin_policy) {
		btd_error(btd_adapter_get_index(adapter),
				"Failed to allocate memory for admin_policy");
		return NULL;
	}

	admin_policy->adapter = adapter;
	admin_policy->adapter_id = btd_adapter_get_index(adapter);

	return admin_policy;
}

static void admin_policy_free(void *data)
{
	struct btd_admin_policy *admin_policy = data;

	g_free(admin_policy);
}

static int admin_policy_adapter_probe(struct btd_adapter *adapter)
{
	if (policy_data) {
		btd_warn(policy_data->adapter_id,
						"Policy data already exists");
		admin_policy_free(policy_data);
		policy_data = NULL;
	}

	policy_data = admin_policy_new(adapter);
	if (!policy_data)
		return -ENOMEM;

	btd_info(policy_data->adapter_id, "Admin Policy has been enabled");

	return 0;
}

static struct btd_adapter_driver admin_policy_driver = {
	.name	= "admin_policy",
	.probe	= admin_policy_adapter_probe,
	.resume = NULL,
};

static int admin_init(void)
{
	DBG("");

	return btd_register_adapter_driver(&admin_policy_driver);
}

static void admin_exit(void)
{
	DBG("");

	btd_unregister_adapter_driver(&admin_policy_driver);

	if (policy_data)
		admin_policy_free(policy_data);
}

BLUETOOTH_PLUGIN_DEFINE(admin, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_init, admin_exit)
