// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdbool.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "lib/uuid.h"

#include "src/log.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"

#include "device.h"
#include "server.h"

static int hid_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
    const bdaddr_t* address;
    char addr[18];
    char** exclude_adapters;
    gsize num_exclude_adapters;

    address = btd_adapter_get_address(adapter);
    ba2str(address, addr);
    exclude_adapters = input_get_exclude_adapters();
    num_exclude_adapters = input_get_num_exclude_adapters();

    for(int i = 0; i < num_exclude_adapters; i++)
    {
        if(strcmp(addr, exclude_adapters[i]))
        {
            return 0;
        }
    }

	return server_start(address);
}

static void hid_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	server_stop(btd_adapter_get_address(adapter));
}

static struct btd_profile input_profile = {
	.name		= "input-hid",
	.local_uuid	= HID_UUID,
	.remote_uuid	= HID_UUID,

	.auto_connect	= true,
	.connect	= input_device_connect,
	.disconnect	= input_device_disconnect,

	.device_probe	= input_device_register,
	.device_remove	= input_device_unregister,

	.adapter_probe	= hid_server_probe,
	.adapter_remove = hid_server_remove,
};

static GKeyFile *load_config_file(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (!g_error_matches(err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static int input_init(void)
{
	GKeyFile *config;
	GError *err = NULL;

    DBG("CONFIGDIR: %s", CONFIGDIR);
	config = load_config_file(CONFIGDIR "/input.conf");
	if (config) {
		int idle_timeout;
        char* exclude_adapters_str;
        char** exclude_adapters;
        gsize num_exclude_adapters;
		gboolean uhid_enabled, classic_bonded_only, auto_sec;

		idle_timeout = g_key_file_get_integer(config, "General",
							"IdleTimeout", &err);
		if (!err) {
			DBG("input.conf: IdleTimeout=%d", idle_timeout);
			input_set_idle_timeout(idle_timeout * 60);
		} else
			g_clear_error(&err);

		uhid_enabled = g_key_file_get_boolean(config, "General",
							"UserspaceHID", &err);
		if (!err) {
			DBG("input.conf: UserspaceHID=%s", uhid_enabled ?
							"true" : "false");
			input_enable_userspace_hid(uhid_enabled);
		} else
			g_clear_error(&err);

		classic_bonded_only = g_key_file_get_boolean(config, "General",
						"ClassicBondedOnly", &err);

		if (!err) {
			DBG("input.conf: ClassicBondedOnly=%s",
					classic_bonded_only ? "true" : "false");
			input_set_classic_bonded_only(classic_bonded_only);
		} else
			g_clear_error(&err);

		auto_sec = g_key_file_get_boolean(config, "General",
						"LEAutoSecurity", &err);
		if (!err) {
			DBG("input.conf: LEAutoSecurity=%s",
					auto_sec ? "true" : "false");
			input_set_auto_sec(auto_sec);
		} else
			g_clear_error(&err);

        g_key_file_set_list_separator(config, ',');

        exclude_adapters_str = g_key_file_get_string(config, "General",
                "ExcludeAdapters", &err);
        exclude_adapters = g_key_file_get_string_list(config, "General",
                "ExcludeAdapters", &num_exclude_adapters, &err);
		if (!err) {
			DBG("input.conf: ExcludeAdapters=%s", exclude_adapters_str);
			input_set_exclude_adapters(exclude_adapters);
			input_set_num_exclude_adapters(num_exclude_adapters);
		} else
			g_clear_error(&err);
	}

	btd_profile_register(&input_profile);

	if (config)
		g_key_file_free(config);

	return 0;
}

static void input_exit(void)
{
	btd_profile_unregister(&input_profile);
}

BLUETOOTH_PLUGIN_DEFINE(input, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							input_init, input_exit)
