/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2017  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "src/shared/btp.h"

#define AD_PATH "/org/bluez/advertising"
#define AD_IFACE "org.bluez.LEAdvertisement1"

/* List of assigned numbers for advetising data and scan response */
#define AD_TYPE_FLAGS				0x01
#define AD_TYPE_INCOMPLETE_UUID16_SERVICE_LIST	0x02
#define AD_TYPE_SHORT_NAME			0x08
#define AD_TYPE_SERVICE_DATA_UUID16		0x16
#define AD_TYPE_APPEARANCE			0x19
#define AD_TYPE_MANUFACTURER_DATA		0xff

static struct l_dbus *dbus;

struct btp_adapter {
	struct l_dbus_proxy *proxy;
	struct l_dbus_proxy *ad_proxy;
	uint8_t index;
	uint32_t supported_settings;
	uint32_t current_settings;
	uint32_t default_settings;
	struct l_queue *devices;
};

struct btp_device {
	struct l_dbus_proxy *proxy;
};

static struct l_queue *adapters;
static char *socket_path;
static struct btp *btp;

static bool gap_service_registered;

struct ad_data {
	uint8_t data[25];
	uint8_t len;
};

struct service_data {
	char *uuid;
	struct ad_data data;
};

struct manufacturer_data {
	uint16_t id;
	struct ad_data data;
};

static struct ad {
	bool registered;
	char *type;
	char *local_name;
	uint16_t local_appearance;
	uint16_t duration;
	uint16_t timeout;
	struct l_queue *uuids;
	struct l_queue *services;
	struct l_queue *manufacturers;
	bool tx_power;
	bool name;
	bool appearance;
} ad;

static char *dupuuid2str(const uint8_t *uuid, uint8_t len)
{
	switch (len) {
	case 16:
		return l_strdup_printf("%hhx%hhx", uuid[0], uuid[1]);
	case 128:
		return l_strdup_printf("%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx"
					"%hhx%hhx%hhx%hhx%hhx%hhx%hhx", uuid[0],
					uuid[1], uuid[2], uuid[3], uuid[4],
					uuid[5], uuid[6], uuid[6], uuid[8],
					uuid[7], uuid[10], uuid[11], uuid[12],
					uuid[13], uuid[14], uuid[15]);
	default:
		return NULL;
	}
}

static bool match_dev_addr_type(const char *addr_type_str, uint8_t addr_type)
{
	if (addr_type == BTP_GAP_ADDR_PUBLIC && strcmp(addr_type_str, "public"))
		return false;

	if (addr_type == BTP_GAP_ADDR_RANDOM && strcmp(addr_type_str, "random"))
		return false;

	return true;
}

static struct btp_adapter *find_adapter_by_proxy(struct l_dbus_proxy *proxy)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (adapter->proxy == proxy)
			return adapter;
	}

	return NULL;
}

static struct btp_adapter *find_adapter_by_index(uint8_t index)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (adapter->index == index)
			return adapter;
	}

	return NULL;
}

static struct btp_adapter *find_adapter_by_path(const char *path)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (!strcmp(l_dbus_proxy_get_path(adapter->proxy), path))
			return adapter;
	}

	return NULL;
}

static struct btp_device *find_device_by_address(struct btp_adapter *adapter,
							const bdaddr_t *addr,
							uint8_t addr_type)
{
	const struct l_queue_entry *entry;
	const char *str;
	char addr_str[18];

	if (!ba2str(addr, addr_str))
		return NULL;

	for (entry = l_queue_get_entries(adapter->devices); entry;
							entry = entry->next) {
		struct btp_device *device = entry->data;

		l_dbus_proxy_get_property(device->proxy, "Address", "s", &str);
		if (strcmp(str, addr_str))
			continue;

		l_dbus_proxy_get_property(device->proxy, "AddressType", "s",
									&str);
		if (match_dev_addr_type(str, addr_type))
			return device;
	}

	return NULL;
}

static bool match_adapter_dev_proxy(const void *device, const void *proxy)
{
	const struct btp_device *d = device;

	return d->proxy == proxy;
}

static bool match_adapter_dev(const void *device_a, const void *device_b)
{
	return device_a == device_b;
}

static struct btp_adapter *find_adapter_by_device(struct btp_device *device)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		if (l_queue_find(adapter->devices, match_adapter_dev, device))
			return adapter;
	}

	return NULL;
}

static struct btp_device *find_device_by_proxy(struct l_dbus_proxy *proxy)
{
	const struct l_queue_entry *entry;
	struct btp_device *device;

	for (entry = l_queue_get_entries(adapters); entry;
							entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		device = l_queue_find(adapter->devices, match_adapter_dev_proxy,
									proxy);

		if (device)
			return device;
	}

	return NULL;
}

static void btp_gap_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint16_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_GAP_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST);
	commands |= (1 << BTP_OP_GAP_READ_COTROLLER_INFO);
	commands |= (1 << BTP_OP_GAP_RESET);
	commands |= (1 << BTP_OP_GAP_SET_POWERED);
	commands |= (1 << BTP_OP_GAP_SET_CONNECTABLE);
	commands |= (1 << BTP_OP_GAP_SET_DISCOVERABLE);
	commands |= (1 << BTP_OP_GAP_SET_BONDABLE);
	commands |= (1 << BTP_OP_GAP_START_ADVERTISING);
	commands |= (1 << BTP_OP_GAP_STOP_ADVERTISING);
	commands |= (1 << BTP_OP_GAP_START_DISCOVERY);
	commands |= (1 << BTP_OP_GAP_STOP_DISCOVERY);
	commands |= (1 << BTP_OP_GAP_CONNECT);
	commands |= (1 << BTP_OP_GAP_DISCONNECT);

	commands = L_CPU_TO_LE16(commands);

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
}

static void btp_gap_read_controller_index(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct l_queue_entry *entry;
	struct btp_gap_read_index_rp *rp;
	uint8_t cnt;
	int i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	cnt = l_queue_length(adapters);

	rp = l_malloc(sizeof(*rp) + cnt);

	rp->num = cnt;

	for (i = 0, entry = l_queue_get_entries(adapters); entry;
						i++, entry = entry->next) {
		struct btp_adapter *adapter = entry->data;

		rp->indexes[i] = adapter->index;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST,
			BTP_INDEX_NON_CONTROLLER, sizeof(*rp) + cnt, rp);
}

static void btp_gap_read_info(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_gap_read_info_rp rp;
	const char *str;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	memset(&rp, 0, sizeof(rp));

	if (!l_dbus_proxy_get_property(adapter->proxy, "Address", "s", &str))
		goto failed;

	if (str2ba(str, &rp.address) < 0)
		goto failed;

	if (!l_dbus_proxy_get_property(adapter->proxy, "Name", "s", &str)) {
		goto failed;
	}

	strncpy((char *) rp.name, str, sizeof(rp.name));
	strncpy((char *) rp.short_name, str, sizeof(rp.short_name));
	rp.supported_settings = L_CPU_TO_LE32(adapter->supported_settings);
	rp.current_settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_COTROLLER_INFO, index,
							sizeof(rp), &rp);

	return;
failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void remove_device_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct btp_device *device = user_data;

	l_dbus_message_set_arguments(message, "o",
					l_dbus_proxy_get_path(device->proxy));
}

static void remove_device_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_device *device = user_data;
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter)
		return;

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);

		l_error("Failed to remove device %s (%s)",
					l_dbus_proxy_get_path(device->proxy),
					name);
		return;
	}

	l_queue_remove(adapter->devices, device);
}

static void unreg_advertising_setup(struct l_dbus_message *message,
								void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(message);
	l_dbus_message_builder_append_basic(builder, 'o', AD_PATH);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void unreg_advertising_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	const char *path = l_dbus_proxy_get_path(proxy);
	struct btp_adapter *adapter = find_adapter_by_path(path);

	if (!adapter)
		return;

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);

		l_error("Failed to stop advertising %s (%s)",
					l_dbus_proxy_get_path(proxy), name);
		return;
	}

	if (!l_dbus_object_remove_interface(dbus, AD_PATH, AD_IFACE))
		l_info("Unable to remove ad instance");
	if (!l_dbus_object_remove_interface(dbus, AD_PATH,
						L_DBUS_INTERFACE_PROPERTIES))
		l_info("Unable to remove propety instance");
	if (!l_dbus_unregister_interface(dbus, AD_IFACE))
		l_info("Unable to unregister ad interface");
}

static void btp_gap_reset(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct l_queue_entry *entry;
	uint8_t status;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to remove devices */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop) {
		status = BTP_ERROR_FAIL;
		goto failed;
	}

	for (entry = l_queue_get_entries(adapter->devices); entry;
							entry = entry->next) {
		struct btp_device *device = entry->data;

		l_dbus_proxy_method_call(adapter->proxy, "RemoveDevice",
						remove_device_setup,
						remove_device_reply, device,
						NULL);
	}

	if (adapter->ad_proxy)
		if (!l_dbus_proxy_method_call(adapter->ad_proxy,
						"UnregisterAdvertisement",
						unreg_advertising_setup,
						unreg_advertising_reply,
						NULL, NULL)) {
			status = BTP_ERROR_FAIL;
			goto failed;
		}

	adapter->current_settings = adapter->default_settings;

	/* TODO for we assume all went well */
	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_RESET, index, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

struct set_setting_data {
	struct btp_adapter *adapter;
	uint8_t opcode;
	uint32_t setting;
	bool value;
};

static void set_setting_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *result, void *user_data)
{
	struct set_setting_data *data = user_data;
	struct btp_adapter *adapter = data->adapter;
	uint32_t settings;

	if (l_dbus_message_is_error(result)) {
		btp_send_error(btp, BTP_GAP_SERVICE, data->adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	if (data->value)
		adapter->current_settings |= data->setting;
	else
		adapter->current_settings &= ~data->setting;

	settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, data->opcode, adapter->index,
						sizeof(settings), &settings);
}

static void btp_gap_set_powered(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_powered_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_POWERED;
	data->setting = BTP_GAP_SETTING_POWERED;
	data->value = cp->powered;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Powered", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void update_current_settings(struct btp_adapter *adapter,
							uint32_t new_settings)
{
	struct btp_new_settings_ev ev;

	adapter->current_settings = new_settings;

	ev.current_settings = L_CPU_TO_LE32(adapter->current_settings);

	btp_send(btp, BTP_GAP_SERVICE, BTP_EV_GAP_NEW_SETTINGS, adapter->index,
							sizeof(ev), &ev);
}

static void btp_gap_set_connectable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_connectable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	uint32_t new_settings;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	new_settings = adapter->current_settings;

	if (cp->connectable)
		new_settings |= BTP_GAP_SETTING_CONNECTABLE;
	else
		new_settings &= ~BTP_GAP_SETTING_CONNECTABLE;

	update_current_settings(adapter, new_settings);

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_CONNECTABLE, index,
					sizeof(new_settings), &new_settings);

	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void btp_gap_set_discoverable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_discoverable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_DISCOVERABLE;
	data->setting = BTP_GAP_SETTING_DISCOVERABLE;
	data->value = cp->discoverable;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Discoverable", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void btp_gap_set_bondable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_set_bondable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct set_setting_data *data;

	if (length < sizeof(*cp))
		goto failed;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	data = l_new(struct set_setting_data, 1);
	data->adapter = adapter;
	data->opcode = BTP_OP_GAP_SET_BONDABLE;
	data->setting = BTP_GAP_SETTING_BONDABLE;
	data->value = cp->bondable;

	if (l_dbus_proxy_set_property(adapter->proxy, set_setting_reply,
					data, l_free, "Pairable", "b",
					data->value))
		return;

	l_free(data);

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void ad_cleanup_service(void *service)
{
	struct service_data *s = service;

	l_free(s->uuid);
	l_free(s);
}

static void ad_cleanup(void)
{
	l_free(ad.local_name);
	l_queue_destroy(ad.uuids, l_free);
	l_queue_destroy(ad.services, ad_cleanup_service);
	l_queue_destroy(ad.manufacturers, l_free);

	memset(&ad, 0, sizeof(ad));
}

static void ad_init(void)
{
	ad.uuids = l_queue_new();
	ad.services = l_queue_new();
	ad.manufacturers = l_queue_new();

	ad.local_appearance = UINT16_MAX;
}

static struct l_dbus_message *ad_release_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;

	l_dbus_unregister_object(dbus, AD_PATH);
	l_dbus_unregister_interface(dbus, AD_IFACE);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	ad_cleanup();

	return reply;
}

static bool ad_type_getter(struct l_dbus *dbus, struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 's', ad.type);

	return true;
}

static bool ad_serviceuuids_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct l_queue_entry *entry;

	if (l_queue_isempty(ad.uuids))
		return false;

	l_dbus_message_builder_enter_array(builder, "s");

	for (entry = l_queue_get_entries(ad.uuids); entry; entry = entry->next)
		l_dbus_message_builder_append_basic(builder, 's', entry->data);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ad_servicedata_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct l_queue_entry *entry;
	size_t i;

	if (l_queue_isempty(ad.services))
		return false;

	l_dbus_message_builder_enter_array(builder, "{sv}");

	for (entry = l_queue_get_entries(ad.services); entry;
							entry = entry->next) {
		struct service_data *sd = entry->data;

		l_dbus_message_builder_enter_dict(builder, "sv");
		l_dbus_message_builder_append_basic(builder, 's', sd->uuid);
		l_dbus_message_builder_enter_variant(builder, "ay");
		l_dbus_message_builder_enter_array(builder, "y");

		for (i = 0; i < sd->data.len; i++)
			l_dbus_message_builder_append_basic(builder, 'y',
							&(sd->data.data[i]));

		l_dbus_message_builder_leave_array(builder);
		l_dbus_message_builder_leave_variant(builder);
		l_dbus_message_builder_leave_dict(builder);
	}
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ad_manufacturerdata_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct l_queue_entry *entry;
	size_t i;

	if (l_queue_isempty(ad.manufacturers))
		return false;

	l_dbus_message_builder_enter_array(builder, "{qv}");

	for (entry = l_queue_get_entries(ad.manufacturers); entry;
							entry = entry->next) {
		struct manufacturer_data *md = entry->data;

		l_dbus_message_builder_enter_dict(builder, "qv");
		l_dbus_message_builder_append_basic(builder, 'q', &md->id);
		l_dbus_message_builder_enter_variant(builder, "ay");
		l_dbus_message_builder_enter_array(builder, "y");

		for (i = 0; i < md->data.len; i++)
			l_dbus_message_builder_append_basic(builder, 'y',
							&(md->data.data[i]));

		l_dbus_message_builder_leave_array(builder);
		l_dbus_message_builder_leave_variant(builder);
		l_dbus_message_builder_leave_dict(builder);
	}
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ad_includes_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	l_dbus_message_builder_enter_array(builder, "s");

	if (!(ad.tx_power || ad.name || ad.appearance))
		return false;

	if (ad.tx_power) {
		const char *str = "tx-power";

		l_dbus_message_builder_append_basic(builder, 's', &str);
	}

	if (ad.name) {
		const char *str = "local-name";

		l_dbus_message_builder_append_basic(builder, 's', &str);
	}

	if (ad.appearance) {
		const char *str = "appearance";

		l_dbus_message_builder_append_basic(builder, 's', &str);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ad_localname_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	if (!ad.local_name)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', ad.local_name);

	return true;
}

static bool ad_appearance_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	if (!ad.local_appearance)
		return false;

	l_dbus_message_builder_append_basic(builder, 'q', &ad.local_appearance);

	return true;
}

static bool ad_duration_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	if (!ad.duration)
		return false;

	l_dbus_message_builder_append_basic(builder, 'q', &ad.duration);

	return true;
}

static bool ad_timeout_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	if (!ad.timeout)
		return false;

	l_dbus_message_builder_append_basic(builder, 'q', &ad.timeout);

	return true;
}

static void setup_ad_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Release",
						L_DBUS_METHOD_FLAG_NOREPLY,
						ad_release_call, "", "");
	l_dbus_interface_property(interface, "Type", 0, "s", ad_type_getter,
									NULL);
	l_dbus_interface_property(interface, "ServiceUUIDs", 0, "as",
						ad_serviceuuids_getter, NULL);
	l_dbus_interface_property(interface, "ServiceData", 0, "a{sv}",
						ad_servicedata_getter, NULL);
	l_dbus_interface_property(interface, "ManufacturerServiceData", 0,
					"a{qv}", ad_manufacturerdata_getter,
					NULL);
	l_dbus_interface_property(interface, "Includes", 0, "as",
						ad_includes_getter, NULL);
	l_dbus_interface_property(interface, "LocalName", 0, "s",
						ad_localname_getter, NULL);
	l_dbus_interface_property(interface, "Appearance", 0, "q",
						ad_appearance_getter, NULL);
	l_dbus_interface_property(interface, "Duration", 0, "q",
						ad_duration_getter, NULL);
	l_dbus_interface_property(interface, "Timeout", 0, "q",
						ad_timeout_getter, NULL);
}

static void start_advertising_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	const char *path = l_dbus_proxy_get_path(proxy);
	struct btp_adapter *adapter = find_adapter_by_path(path);
	uint32_t new_settings;

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to start advertising (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	new_settings = adapter->current_settings;
	new_settings |= BTP_GAP_SETTING_ADVERTISING;
	update_current_settings(adapter, new_settings);

	ad.registered = true;

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_START_ADVERTISING,
					adapter->index, sizeof(new_settings),
					&new_settings);
}

static void create_advertising_data(uint8_t adv_data_len, const uint8_t *data)
{
	const uint8_t *ad_data;
	uint8_t ad_type, ad_len;
	uint8_t remaining_data_len = adv_data_len;

	while (remaining_data_len) {
		ad_type = data[adv_data_len - remaining_data_len];
		ad_len = data[adv_data_len - remaining_data_len + 1];
		ad_data = &data[adv_data_len - remaining_data_len + 2];

		switch (ad_type) {
		case AD_TYPE_INCOMPLETE_UUID16_SERVICE_LIST:
		{
			char *uuid = dupuuid2str(ad_data, 16);

			l_queue_push_tail(ad.uuids, uuid);

			break;
		}
		case AD_TYPE_SHORT_NAME:
			ad.local_name = malloc(ad_len + 1);
			memcpy(ad.local_name, ad_data, ad_len);
			ad.local_name[ad_len] = '\0';

			break;
		case AD_TYPE_SERVICE_DATA_UUID16:
		{
			struct service_data *sd;

			sd = l_new(struct service_data, 1);
			sd->uuid = dupuuid2str(ad_data, 16);
			sd->data.len = ad_len - 2;
			memcpy(sd->data.data, ad_data + 2, sd->data.len);

			l_queue_push_tail(ad.services, sd);

			break;
		}
		case AD_TYPE_APPEARANCE:
			memcpy(&ad.local_appearance, ad_data, ad_len);

			break;
		case AD_TYPE_MANUFACTURER_DATA:
		{
			struct manufacturer_data *md;

			md = l_new(struct manufacturer_data, 1);
			/* The first 2 octets contain the Company Identifier
			 * Code followed by additional manufacturer specific
			 * data.
			 */
			memcpy(&md->id, ad_data, 2);
			md->data.len = ad_len - 2;
			memcpy(md->data.data, ad_data + 2, md->data.len);

			l_queue_push_tail(ad.manufacturers, md);

			break;
		}
		default:
			l_info("Unsupported advertising data type");

			break;
		}
		/* Advertising entity data len + advertising entity header
		 * (type, len)
		 */
		remaining_data_len -= ad_len + 2;
	}
}

static void create_scan_response(uint8_t scan_rsp_len, const uint8_t *data)
{
	/* TODO */
}

static void start_advertising_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(message);
	l_dbus_message_builder_append_basic(builder, 'o', AD_PATH);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void btp_gap_start_advertising(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_start_adv_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to advertise */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
							!prop || ad.registered)
		goto failed;

	if (!l_dbus_register_interface(dbus, AD_IFACE, setup_ad_interface, NULL,
								false)) {
		l_info("Unable to register ad interface");
		goto failed;
	}

	if (!l_dbus_object_add_interface(dbus, AD_PATH, AD_IFACE, NULL)) {
		l_info("Unable to instantiate ad interface");

		if (!l_dbus_unregister_interface(dbus, AD_IFACE))
			l_info("Unable to unregister ad interface");

		goto failed;
	}

	if (!l_dbus_object_add_interface(dbus, AD_PATH,
						L_DBUS_INTERFACE_PROPERTIES,
						NULL)) {
		l_info("Unable to instantiate the properties interface");

		if (!l_dbus_object_remove_interface(dbus, AD_PATH, AD_IFACE))
			l_info("Unable to remove ad instance");
		if (!l_dbus_unregister_interface(dbus, AD_IFACE))
			l_info("Unable to unregister ad interface");

		goto failed;
	}

	ad_init();

	if (adapter->current_settings & BTP_GAP_SETTING_CONNECTABLE)
		ad.type = "peripheral";
	else
		ad.type = "broadcast";

	if (cp->adv_data_len > 0)
		create_advertising_data(cp->adv_data_len, cp->data);
	if (cp->scan_rsp_len > 0)
		create_scan_response(cp->scan_rsp_len,
						cp->data + cp->scan_rsp_len);

	if (!l_dbus_proxy_method_call(adapter->ad_proxy,
							"RegisterAdvertisement",
							start_advertising_setup,
							start_advertising_reply,
							NULL, NULL)) {
		if (!l_dbus_object_remove_interface(dbus, AD_PATH, AD_IFACE))
			l_info("Unable to remove ad instance");
		if (!l_dbus_unregister_interface(dbus, AD_IFACE))
			l_info("Unable to unregister ad interface");

		goto failed;
	}

	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void stop_advertising_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	const char *path = l_dbus_proxy_get_path(proxy);
	struct btp_adapter *adapter = find_adapter_by_path(path);
	uint32_t new_settings;

	if (!adapter)
		return;

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);

		l_error("Failed to stop advertising %s (%s)",
					l_dbus_proxy_get_path(proxy), name);
		return;
	}

	if (!l_dbus_object_remove_interface(dbus, AD_PATH, AD_IFACE))
		l_info("Unable to remove ad instance");
	if (!l_dbus_object_remove_interface(dbus, AD_PATH,
						L_DBUS_INTERFACE_PROPERTIES))
		l_info("Unable to remove propety instance");
	if (!l_dbus_unregister_interface(dbus, AD_IFACE))
		l_info("Unable to unregister ad interface");

	new_settings = adapter->current_settings;
	new_settings &= ~BTP_GAP_SETTING_ADVERTISING;
	update_current_settings(adapter, new_settings);

	ad_cleanup();

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_STOP_ADVERTISING,
					adapter->index, sizeof(new_settings),
					&new_settings);
}

static void btp_gap_stop_advertising(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	uint8_t status = BTP_ERROR_FAIL;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
				!prop || !adapter->ad_proxy || !ad.registered)
		goto failed;

	if (!l_dbus_proxy_method_call(adapter->ad_proxy,
						"UnregisterAdvertisement",
						unreg_advertising_setup,
						stop_advertising_reply,
						NULL, NULL))
		goto failed;

	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void start_discovery_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to start discovery (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_START_DISCOVERY,
						adapter->index, 0, NULL);
}

static void set_discovery_filter_setup(struct l_dbus_message *message,
							void *user_data)
{
	uint8_t flags = L_PTR_TO_UINT(user_data);
	struct l_dbus_message_builder *builder;

	if (!(flags & (BTP_GAP_DISCOVERY_FLAG_LE |
					BTP_GAP_DISCOVERY_FLAG_BREDR))) {
		l_info("Failed to start discovery - no transport set");
		return;
	}

	builder = l_dbus_message_builder_new(message);

	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");

	/* Be in observer mode or in general mode (default in Bluez) */
	if (flags & BTP_GAP_DISCOVERY_FLAG_OBSERVATION) {
		l_dbus_message_builder_append_basic(builder, 's', "Transport");
		l_dbus_message_builder_enter_variant(builder, "s");

		if (flags & (BTP_GAP_DISCOVERY_FLAG_LE |
						BTP_GAP_DISCOVERY_FLAG_BREDR))
			l_dbus_message_builder_append_basic(builder, 's',
									"auto");
		else if (flags & BTP_GAP_DISCOVERY_FLAG_LE)
			l_dbus_message_builder_append_basic(builder, 's', "le");
		else if (flags & BTP_GAP_DISCOVERY_FLAG_BREDR)
			l_dbus_message_builder_append_basic(builder, 's',
								"bredr");

		l_dbus_message_builder_leave_variant(builder);
	}

	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);

	/* TODO add passive, limited discovery */
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void set_discovery_filter_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to set discovery filter (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	l_dbus_proxy_method_call(adapter->proxy, "StartDiscovery", NULL,
					start_discovery_reply, NULL, NULL);
}

static void btp_gap_start_discovery(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_start_discovery_cp *cp = param;
	bool prop;

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	/* Adapter needs to be powered to start discovery */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop) {
		btp_send_error(btp, BTP_GAP_SERVICE, index, BTP_ERROR_FAIL);
		return;
	}

	l_dbus_proxy_method_call(adapter->proxy, "SetDiscoveryFilter",
						set_discovery_filter_setup,
						set_discovery_filter_reply,
						L_UINT_TO_PTR(cp->flags), NULL);
}

static void clear_discovery_filter_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(message);

	/* Clear discovery filter setup */
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void clear_discovery_filter_reaply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to set discovery filter (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_STOP_DISCOVERY,
						adapter->index, 0, NULL);
}

static void stop_discovery_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_proxy(proxy);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);
		l_error("Failed to stop discovery (%s)", name);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter->index,
								BTP_ERROR_FAIL);
		return;
	}

	l_dbus_proxy_method_call(adapter->proxy, "SetDiscoveryFilter",
						clear_discovery_filter_setup,
						clear_discovery_filter_reaply,
						NULL, NULL);
}

static void btp_gap_stop_discovery(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	bool prop;

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	/* Adapter needs to be powered to be able to remove devices */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop) {
		btp_send_error(btp, BTP_GAP_SERVICE, index, BTP_ERROR_FAIL);
		return;
	}

	l_dbus_proxy_method_call(adapter->proxy, "StopDiscovery", NULL,
					stop_discovery_reply, NULL, NULL);
}

static void connect_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *result, void *user_data)
{
	uint8_t adapter_index = L_PTR_TO_UINT(user_data);
	struct btp_adapter *adapter = find_adapter_by_index(adapter_index);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to connect (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter_index,
								BTP_ERROR_FAIL);
		return;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_CONNECT, adapter_index, 0,
									NULL);
}

static void btp_gap_connect(uint8_t index, const void *param, uint16_t length,
								void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_connect_cp *cp = param;
	struct btp_device *device;
	bool prop;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to connect */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop)
		goto failed;

	device = find_device_by_address(adapter, &cp->address,
							cp->address_type);

	if (!device)
		goto failed;

	l_dbus_proxy_method_call(device->proxy, "Connect", NULL, connect_reply,
					L_UINT_TO_PTR(adapter->index), NULL);

	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void disconnect_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *result, void *user_data)
{
	uint8_t adapter_index = L_PTR_TO_UINT(user_data);
	struct btp_adapter *adapter = find_adapter_by_index(adapter_index);

	if (!adapter) {
		btp_send_error(btp, BTP_GAP_SERVICE, BTP_INDEX_NON_CONTROLLER,
								BTP_ERROR_FAIL);
		return;
	}

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to disconnect (%s), %s", name, desc);

		btp_send_error(btp, BTP_GAP_SERVICE, adapter_index,
								BTP_ERROR_FAIL);
		return;
	}

	btp_send(btp, BTP_GAP_SERVICE, BTP_OP_GAP_DISCONNECT, adapter_index, 0,
									NULL);
}

static void btp_gap_disconnect(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_gap_disconnect_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;
	struct btp_device *device;
	bool prop;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Adapter needs to be powered to be able to connect */
	if (!l_dbus_proxy_get_property(adapter->proxy, "Powered", "b", &prop) ||
									!prop)
		goto failed;

	device = find_device_by_address(adapter, &cp->address,
							cp->address_type);

	if (!device)
		goto failed;

	l_dbus_proxy_method_call(device->proxy, "Disconnect", NULL,
					disconnect_reply,
					L_UINT_TO_PTR(adapter->index), NULL);

	return;

failed:
	btp_send_error(btp, BTP_GAP_SERVICE, index, status);
}

static void btp_gap_device_found_ev(struct l_dbus_proxy *proxy)
{
	struct btp_device_found_ev ev;
	const char *str;
	int16_t rssi;

	if (!l_dbus_proxy_get_property(proxy, "Address", "s", &str) ||
						str2ba(str, &ev.address) < 0)
		return;

	if (!l_dbus_proxy_get_property(proxy, "AddressType", "s", &str))
		return;

	ev.address_type = strcmp(str, "public") ? BTP_GAP_ADDR_RANDOM :
							BTP_GAP_ADDR_PUBLIC;

	if (!l_dbus_proxy_get_property(proxy, "RSSI", "n", &rssi))
		return;

	ev.rssi = rssi;

	/* TODO Temporary set all flags */
	ev.flags = (BTP_EV_GAP_DEVICE_FOUND_FLAG_RSSI |
					BTP_EV_GAP_DEVICE_FOUND_FLAG_AD |
					BTP_EV_GAP_DEVICE_FOUND_FLAG_SR);

	/* TODO Add eir to device found event */
	ev.eir_len = 0;

	btp_send(btp, BTP_GAP_SERVICE, BTP_EV_GAP_DEVICE_FOUND,
						BTP_INDEX_NON_CONTROLLER,
						sizeof(ev) + ev.eir_len, &ev);
}

static void btp_gap_device_connection_ev(struct l_dbus_proxy *proxy,
								bool connected)
{
	struct btp_adapter *adapter;
	struct btp_device *device;
	const char *str_addr, *str_addr_type;
	uint8_t address_type;

	device = find_device_by_proxy(proxy);
	adapter = find_adapter_by_device(device);

	if (!device || !adapter)
		return;

	if (!l_dbus_proxy_get_property(proxy, "Address", "s", &str_addr))
		return;

	if (!l_dbus_proxy_get_property(proxy, "AddressType", "s",
								&str_addr_type))
		return;

	address_type = strcmp(str_addr_type, "public") ? BTP_GAP_ADDR_RANDOM :
							BTP_GAP_ADDR_PUBLIC;

	if (connected) {
		struct btp_gap_device_connected_ev ev;

		str2ba(str_addr, &ev.address);
		ev.address_type = address_type;

		btp_send(btp, BTP_GAP_SERVICE, BTP_EV_GAP_DEVICE_CONNECTED,
					adapter->index, sizeof(ev), &ev);
	} else {
		struct btp_gap_device_disconnected_ev ev;

		str2ba(str_addr, &ev.address);
		ev.address_type = address_type;

		btp_send(btp, BTP_GAP_SERVICE, BTP_EV_GAP_DEVICE_DISCONNECTED,
					adapter->index, sizeof(ev), &ev);
	}
}

static void register_gap_service(void)
{
	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_SUPPORTED_COMMANDS,
					btp_gap_read_commands, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE,
				BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST,
				btp_gap_read_controller_index, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_READ_COTROLLER_INFO,
						btp_gap_read_info, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_RESET,
						btp_gap_reset, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_POWERED,
					btp_gap_set_powered, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_CONNECTABLE,
					btp_gap_set_connectable, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_DISCOVERABLE,
					btp_gap_set_discoverable, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_SET_BONDABLE,
					btp_gap_set_bondable, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_START_ADVERTISING,
					btp_gap_start_advertising, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_STOP_ADVERTISING,
					btp_gap_stop_advertising, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_START_DISCOVERY,
					btp_gap_start_discovery, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_STOP_DISCOVERY,
					btp_gap_stop_discovery, NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_CONNECT, btp_gap_connect,
								NULL, NULL);

	btp_register(btp, BTP_GAP_SERVICE, BTP_OP_GAP_DISCONNECT,
						btp_gap_disconnect, NULL, NULL);
}

static void btp_core_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint8_t commands = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	commands |= (1 << BTP_OP_CORE_READ_SUPPORTED_COMMANDS);
	commands |= (1 << BTP_OP_CORE_READ_SUPPORTED_SERVICES);
	commands |= (1 << BTP_OP_CORE_REGISTER);
	commands |= (1 << BTP_OP_CORE_UNREGISTER);

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, sizeof(commands), &commands);
}

static void btp_core_read_services(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	uint8_t services = 0;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	services |= (1 << BTP_CORE_SERVICE);
	services |= (1 << BTP_GAP_SERVICE);

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_SERVICES,
			BTP_INDEX_NON_CONTROLLER, sizeof(services), &services);
}

static void btp_core_register(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct btp_core_register_cp  *cp = param;

	if (length < sizeof(*cp))
		goto failed;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	switch (cp->service_id) {
	case BTP_GAP_SERVICE:
		if (gap_service_registered)
			goto failed;

		register_gap_service();
		gap_service_registered = true;
		break;
	case BTP_GATT_SERVICE:
	case BTP_L2CAP_SERVICE:
	case BTP_MESH_NODE_SERVICE:
	case BTP_CORE_SERVICE:
	default:
		goto failed;
	}

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_REGISTER,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_CORE_SERVICE, index, BTP_ERROR_FAIL);
}

static void btp_core_unregister(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const struct btp_core_unregister_cp  *cp = param;

	if (length < sizeof(*cp))
		goto failed;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_CORE_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	switch (cp->service_id) {
	case BTP_GAP_SERVICE:
		if (!gap_service_registered)
			goto failed;

		btp_unregister_service(btp, BTP_GAP_SERVICE);
		gap_service_registered = false;
		break;
	case BTP_GATT_SERVICE:
	case BTP_L2CAP_SERVICE:
	case BTP_MESH_NODE_SERVICE:
	case BTP_CORE_SERVICE:
	default:
		goto failed;
	}

	btp_send(btp, BTP_CORE_SERVICE, BTP_OP_CORE_UNREGISTER,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
	return;

failed:
	btp_send_error(btp, BTP_CORE_SERVICE, index, BTP_ERROR_FAIL);
}

static void register_core_service(void)
{
	btp_register(btp, BTP_CORE_SERVICE,
					BTP_OP_CORE_READ_SUPPORTED_COMMANDS,
					btp_core_read_commands, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE,
					BTP_OP_CORE_READ_SUPPORTED_SERVICES,
					btp_core_read_services, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE, BTP_OP_CORE_REGISTER,
						btp_core_register, NULL, NULL);

	btp_register(btp, BTP_CORE_SERVICE, BTP_OP_CORE_UNREGISTER,
					btp_core_unregister, NULL, NULL);
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminating");
		l_main_quit();
		break;
	}
}

static void btp_device_free(struct btp_device *device)
{
	l_free(device);
}

static void btp_adapter_free(struct btp_adapter *adapter)
{
	l_queue_destroy(adapter->devices,
				(l_queue_destroy_func_t)btp_device_free);
	l_free(adapter);
}

static void extract_settings(struct l_dbus_proxy *proxy, uint32_t *current,
						uint32_t *supported)
{
	bool prop;

	*supported = 0;
	*current = 0;

	/* TODO not all info is available via D-Bus API */
	*supported |=  BTP_GAP_SETTING_POWERED;
	*supported |=  BTP_GAP_SETTING_CONNECTABLE;
	*supported |=  BTP_GAP_SETTING_DISCOVERABLE;
	*supported |=  BTP_GAP_SETTING_BONDABLE;
	*supported |=  BTP_GAP_SETTING_SSP;
	*supported |=  BTP_GAP_SETTING_BREDR;
	*supported |=  BTP_GAP_SETTING_LE;
	*supported |=  BTP_GAP_SETTING_ADVERTISING;
	*supported |=  BTP_GAP_SETTING_SC;
	*supported |=  BTP_GAP_SETTING_PRIVACY;
	/* *supported |=  BTP_GAP_SETTING_STATIC_ADDRESS; */

	/* TODO not all info is availbe via D-Bus API so some are assumed to be
	 * enabled by bluetoothd or simply hardcoded until API is extended
	 */
	*current |=  BTP_GAP_SETTING_CONNECTABLE;
	*current |=  BTP_GAP_SETTING_SSP;
	*current |=  BTP_GAP_SETTING_BREDR;
	*current |=  BTP_GAP_SETTING_LE;
	*current |=  BTP_GAP_SETTING_PRIVACY;
	*current |=  BTP_GAP_SETTING_SC;
	/* *supported |=  BTP_GAP_SETTING_STATIC_ADDRESS; */

	if (l_dbus_proxy_get_property(proxy, "Powered", "b", &prop) && prop)
		*current |=  BTP_GAP_SETTING_POWERED;

	if (l_dbus_proxy_get_property(proxy, "Discoverable", "b", &prop) &&
									prop)
		*current |=  BTP_GAP_SETTING_DISCOVERABLE;

	if (l_dbus_proxy_get_property(proxy, "Pairable", "b", &prop) && prop)
		*current |=  BTP_GAP_SETTING_BONDABLE;
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy added: %s (%s)", interface, path);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		struct btp_adapter *adapter;

		adapter = l_new(struct btp_adapter, 1);
		adapter->proxy = proxy;
		adapter->index = l_queue_length(adapters);
		adapter->devices = l_queue_new();

		extract_settings(proxy, &adapter->current_settings,
						&adapter->supported_settings);

		adapter->default_settings = adapter->current_settings;

		l_queue_push_tail(adapters, adapter);
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_adapter *adapter;
		struct btp_device *device;
		char *str;

		if (!l_dbus_proxy_get_property(proxy, "Adapter", "o", &str))
			return;

		adapter = find_adapter_by_path(str);
		if (!adapter)
			return;

		device = l_new(struct btp_device, 1);
		device->proxy = proxy;

		l_queue_push_tail(adapter->devices, device);

		btp_gap_device_found_ev(proxy);

		return;
	}

	if (!strcmp(interface, "org.bluez.LEAdvertisingManager1")) {
		struct btp_adapter *adapter;

		adapter = find_adapter_by_path(path);
		if (!adapter)
			return;

		adapter->ad_proxy = proxy;

		return;
	}
}

static bool device_match_by_proxy(const void *a, const void *b)
{
	const struct btp_device *device = a;
	const struct l_dbus_proxy *proxy = b;

	return device->proxy == proxy;
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy removed: %s (%s)", interface, path);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		l_info("Adapter removed, terminating.");
		l_main_quit();
		return;
	}

	if (!strcmp(interface, "org.bluez.Device1")) {
		struct btp_adapter *adapter;
		char *str;

		if (!l_dbus_proxy_get_property(proxy, "Adapter", "o", &str))
			return;

		adapter = find_adapter_by_path(str);
		if (!adapter)
			return;

		l_queue_remove_if(adapter->devices, device_match_by_proxy,
									proxy);

		return;
	}
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("property_changed %s %s %s", name, path, interface);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		struct btp_adapter *adapter = find_adapter_by_proxy(proxy);
		uint32_t new_settings;

		if (!adapter)
			return;

		new_settings = adapter->current_settings;

		if (!strcmp(name, "Powered")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_POWERED;
			else
				new_settings &= ~BTP_GAP_SETTING_POWERED;
		} else if (!strcmp(name, "Discoverable")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_DISCOVERABLE;
			else
				new_settings &= ~BTP_GAP_SETTING_DISCOVERABLE;
		}

		if (!strcmp(name, "Pairable")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			if (prop)
				new_settings |= BTP_GAP_SETTING_BONDABLE;
			else
				new_settings &= ~BTP_GAP_SETTING_BONDABLE;
		}

		if (new_settings != adapter->current_settings)
			update_current_settings(adapter, new_settings);

		return;
	} else if (!strcmp(interface, "org.bluez.Device1")) {
		if (!strcmp(name, "RSSI")) {
			int16_t rssi;

			if (!l_dbus_message_get_arguments(msg, "n", &rssi))
				return;

			btp_gap_device_found_ev(proxy);
		} else if (!strcmp(name, "Connected")) {
			bool prop;

			if (!l_dbus_message_get_arguments(msg, "b", &prop))
				return;

			btp_gap_device_connection_ev(proxy, prop);
		}
	}
}

static void client_connected(struct l_dbus *dbus, void *user_data)
{
	l_info("D-Bus client connected");
}

static void client_disconnected(struct l_dbus *dbus, void *user_data)
{
	l_info("D-Bus client disconnected, terminated");
	l_main_quit();
}

static void client_ready(struct l_dbus_client *client, void *user_data)
{
	l_info("D-Bus client ready, connecting BTP");

	btp = btp_new(socket_path);
	if (!btp) {
		l_error("Failed to connect BTP, terminating");
		l_main_quit();
		return;
	}

	register_core_service();

	btp_send(btp, BTP_CORE_SERVICE, BTP_EV_CORE_READY,
					BTP_INDEX_NON_CONTROLLER, 0, NULL);
}

static void ready_callback(void *user_data)
{
	if (!l_dbus_object_manager_enable(dbus))
		l_info("Unable to register the ObjectManager");
}

static void usage(void)
{
	l_info("btpclient - Bluetooth tester");
	l_info("Usage:");
	l_info("\tbtpclient [options]");
	l_info("options:\n"
	"\t-s, --socket <socket>  Socket to use for BTP\n"
	"\t-q, --quiet            Don't emit any logs\n"
	"\t-v, --version          Show version\n"
	"\t-h, --help             Show help options");
}

static const struct option options[] = {
	{ "socket",	1, 0, 's' },
	{ "quiet",	0, 0, 'q' },
	{ "version",	0, 0, 'v' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct l_dbus_client *client;
	struct l_signal *signal;
	sigset_t mask;
	int opt;

	l_log_set_stderr();

	while ((opt = getopt_long(argc, argv, "+hs:vq", options, NULL)) != -1) {
		switch (opt) {
		case 's':
			socket_path = l_strdup(optarg);
			break;
		case 'q':
			l_log_set_null();
			break;
		case 'd':
			break;
		case 'v':
			l_info("%s", VERSION);
			return EXIT_SUCCESS;
		case 'h':
		default:
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (!socket_path) {
		l_info("Socket option is required");
		l_info("Type --help for usage");
		return EXIT_FAILURE;
	}

	if (!l_main_init())
		return EXIT_FAILURE;


	adapters = l_queue_new();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, "org.bluez", "/org/bluez");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);

	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);

	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

	l_main_run();

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);
	l_signal_remove(signal);
	btp_cleanup(btp);

	l_queue_destroy(adapters, (l_queue_destroy_func_t)btp_adapter_free);

	l_free(socket_path);

	l_main_exit();

	return EXIT_SUCCESS;
}
