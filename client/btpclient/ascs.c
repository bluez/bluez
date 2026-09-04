// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Collabora Ltd.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <ell/ell.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "src/shared/btp.h"
#include "src/shared/util.h"
#include "src/shared/lc3.h"
#include "btpclient.h"
#include "ascs.h"

#define SINK_PATH "/org/bluez/btpclient/sink"
#define SOURCE_PATH "/org/bluez/btpclient/source"
#define ENDPOINT_IFACE "org.bluez.MediaEndpoint1"

#define EP_SUPPORTED_CTXT 0x0fff

/* PAC LC3 Source:
 *
 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
 * Duration: 7.5 ms 10 ms
 * Channel count: 3
 * Frame length: 26-240
 */
uint8_t source_capa[] = {
	0x03, LC3_FREQ, LC3_FREQ_ANY & 0xFF, LC3_FREQ_ANY >> 8,
	0x02, LC3_DURATION, LC3_DURATION_ANY,
	0x05, LC3_FRAME_LEN, 26, 0, 240, 0,
	0x02, LC3_CHAN_COUNT, 3
};

/* PAC LC3 Sink:
 *
 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
 * Duration: 7.5 ms 10 ms
 * Frame length: 26-240
 */
uint8_t sink_capa[] = {
	0x03, LC3_FREQ, LC3_FREQ_ANY & 0xFF, LC3_FREQ_ANY >> 8,
	0x02, LC3_DURATION, LC3_DURATION_ANY,
	0x05, LC3_FRAME_LEN, 26, 0, 240, 0
};

struct codec_preset {
	char *name;
	const struct iovec data;
	const struct iovec meta;
	struct bt_bap_qos qos;
	uint8_t target_latency;
	uint32_t chan_alloc;
	bool custom;
	bool alt;
	struct codec_preset *alt_preset;
};

#define LC3_PRESET_LL(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x01, \
	}

#define LC3_PRESET_HR(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x03, \
	}

static struct codec_preset lc3_ucast_presets[] = {
	/* QoS Configuration settings for low latency audio data */
	LC3_PRESET_LL("8_1_1", LC3_CONFIG_8_1, LC3_QOS_8_1_1),
	LC3_PRESET_LL("8_2_1", LC3_CONFIG_8_2, LC3_QOS_8_2_1),
	LC3_PRESET_LL("16_1_1", LC3_CONFIG_16_1, LC3_QOS_16_1_1),
	LC3_PRESET_LL("16_2_1", LC3_CONFIG_16_2, LC3_QOS_16_2_1),
	LC3_PRESET_LL("24_1_1", LC3_CONFIG_24_1, LC3_QOS_24_1_1),
	LC3_PRESET_LL("24_2_1", LC3_CONFIG_24_2, LC3_QOS_24_2_1),
	LC3_PRESET_LL("32_1_1", LC3_CONFIG_32_1, LC3_QOS_32_1_1),
	LC3_PRESET_LL("32_2_1", LC3_CONFIG_32_2, LC3_QOS_32_2_1),
	LC3_PRESET_LL("44_1_1", LC3_CONFIG_44_1, LC3_QOS_44_1_1),
	LC3_PRESET_LL("44_2_1", LC3_CONFIG_44_2, LC3_QOS_44_2_1),
	LC3_PRESET_LL("48_1_1", LC3_CONFIG_48_1, LC3_QOS_48_1_1),
	LC3_PRESET_LL("48_2_1", LC3_CONFIG_48_2, LC3_QOS_48_2_1),
	LC3_PRESET_LL("48_3_1", LC3_CONFIG_48_3, LC3_QOS_48_3_1),
	LC3_PRESET_LL("48_4_1", LC3_CONFIG_48_4, LC3_QOS_48_4_1),
	LC3_PRESET_LL("48_5_1", LC3_CONFIG_48_5, LC3_QOS_48_5_1),
	LC3_PRESET_LL("48_6_1", LC3_CONFIG_48_6, LC3_QOS_48_6_1),
	/* QoS Configuration settings for high reliability audio data */
	LC3_PRESET_HR("8_1_2", LC3_CONFIG_8_1, LC3_QOS_8_1_2),
	LC3_PRESET_HR("8_2_2", LC3_CONFIG_8_2, LC3_QOS_8_2_2),
	LC3_PRESET_HR("16_1_2", LC3_CONFIG_16_1, LC3_QOS_16_1_2),
	LC3_PRESET_HR("16_2_2", LC3_CONFIG_16_2, LC3_QOS_16_2_2),
	LC3_PRESET_HR("24_1_2", LC3_CONFIG_24_1, LC3_QOS_24_1_2),
	LC3_PRESET_HR("24_2_2", LC3_CONFIG_24_2, LC3_QOS_24_2_2),
	LC3_PRESET_HR("32_1_2", LC3_CONFIG_32_1, LC3_QOS_32_1_2),
	LC3_PRESET_HR("32_2_2", LC3_CONFIG_32_2, LC3_QOS_32_2_2),
	LC3_PRESET_HR("44_1_2", LC3_CONFIG_44_1, LC3_QOS_44_1_2),
	LC3_PRESET_HR("44_2_2", LC3_CONFIG_44_2, LC3_QOS_44_2_2),
	LC3_PRESET_HR("48_1_2", LC3_CONFIG_48_1, LC3_QOS_48_1_2),
	LC3_PRESET_HR("48_2_2", LC3_CONFIG_48_2, LC3_QOS_48_2_2),
	LC3_PRESET_HR("48_3_2", LC3_CONFIG_48_3, LC3_QOS_48_3_2),
	LC3_PRESET_HR("48_4_2", LC3_CONFIG_48_4, LC3_QOS_48_4_2),
	LC3_PRESET_HR("48_5_2", LC3_CONFIG_48_5, LC3_QOS_48_5_2),
	LC3_PRESET_HR("48_6_2", LC3_CONFIG_48_6, LC3_QOS_48_6_2)
};

static struct btp *btp;
static struct l_dbus *dbus;
static bool ascs_service_registered;
struct l_queue *pending_select_properties;

static void btp_ascs_read_commands(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	const uint8_t supported_commands[] = {
		BTP_OP_ASCS_READ_SUPPORTED_COMMANDS,
		BTP_OP_ASCS_CONFIGURE_CODEC,
		BTP_OP_ASCS_CONFIGURE_QOS,
		BTP_OP_ASCS_ENABLE,
		BTP_OP_ASCS_RECEIVER_START_READY,
		BTP_OP_ASCS_ADD_ASE_TO_CIS,
		BTP_OP_ASCS_PRECONFIGURE_QOS,
	};
	uint8_t *commands = NULL;
	size_t commands_len = 0;
	size_t i;

	if (index != BTP_INDEX_NON_CONTROLLER) {
		btp_send_error(btp, BTP_ASCS_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	for (i = 0; i < L_ARRAY_SIZE(supported_commands); i++) {
		if (!add_supported_command(&commands, &commands_len,
						supported_commands[i]))
			goto failed;
	}

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_READ_SUPPORTED_COMMANDS,
			BTP_INDEX_NON_CONTROLLER, commands_len, commands);

	l_free(commands);

	return;

failed:
	l_free(commands);
	btp_send_error(btp, BTP_ASCS_SERVICE, index, BTP_ERROR_FAIL);
}

static void ascs_register_endpoint_setup(struct l_dbus_message *message,
							void *user_data)
{
	uint uuid = L_PTR_TO_UINT(user_data);
	struct l_dbus_message_builder *builder;
	const char *path, *uuid_str;
	uint8_t *capa;
	unsigned int capa_size, val, i;

	if (uuid == PAC_SOURCE_CHRC_UUID) {
		path = SOURCE_PATH;
		uuid_str = PAC_SOURCE_UUID;
		capa = source_capa;
		capa_size = sizeof(source_capa);
	} else {
		path = SINK_PATH;
		uuid_str = PAC_SINK_UUID;
		capa = sink_capa;
		capa_size = sizeof(sink_capa);
	}

	builder = l_dbus_message_builder_new(message);

	l_dbus_message_builder_append_basic(builder, 'o', path);

	l_dbus_message_builder_enter_array(builder, "{sv}");

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "UUID");
	l_dbus_message_builder_enter_variant(builder, "s");
	l_dbus_message_builder_append_basic(builder, 's', uuid_str);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Codec");
	l_dbus_message_builder_enter_variant(builder, "y");
	val = 0x06;
	l_dbus_message_builder_append_basic(builder, 'y', &val);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Capabilities");
	l_dbus_message_builder_enter_variant(builder, "ay");
	l_dbus_message_builder_enter_array(builder, "y");
	for (i = 0; i < capa_size; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &(capa[i]));
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Locations");
	l_dbus_message_builder_enter_variant(builder, "u");
	val = 1;
	l_dbus_message_builder_append_basic(builder, 'u', &val);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "SupportedContext");
	l_dbus_message_builder_enter_variant(builder, "q");
	val = EP_SUPPORTED_CTXT;
	l_dbus_message_builder_append_basic(builder, 'q', &val);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Context");
	l_dbus_message_builder_enter_variant(builder, "q");
	val = EP_SUPPORTED_CTXT;
	l_dbus_message_builder_append_basic(builder, 'q', &val);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void ascs_register_endpoint_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	uint uuid = L_PTR_TO_UINT(user_data);
	const char *path;

	if (uuid == PAC_SOURCE_CHRC_UUID)
		path = SOURCE_PATH;
	else
		path = SINK_PATH;

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to set register endpoint (%s), %s", name, desc);

		goto failed;
	}

	l_info("Media endpoint %s registered", path);

	return;

failed:
	if (!l_dbus_object_remove_interface(dbus, path, ENDPOINT_IFACE))
		l_info("Unable to remove endpoint instance");
}

static bool register_endpoint(struct btp_adapter *adapter, bt_uuid_t *uuid)
{
	uint16_t pac_uuid;
	const char *path;

	if (bt_uuid16_cmp(uuid, ASE_SINK_UUID)) {
		pac_uuid = PAC_SOURCE_CHRC_UUID;
		path = SOURCE_PATH;
	} else {
		pac_uuid = PAC_SINK_CHRC_UUID;
		path = SINK_PATH;
	}

	if (!l_dbus_object_add_interface(dbus, path,
						ENDPOINT_IFACE, adapter)) {
		l_info("Unable to instantiate endpoint interface");
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, path,
						L_DBUS_INTERFACE_PROPERTIES,
						adapter)) {
		l_info("Unable to instantiate endpoint properties interface");
		return false;
	}

	l_dbus_proxy_method_call(adapter->media_proxy,
			"RegisterEndpoint",
			ascs_register_endpoint_setup,
			ascs_register_endpoint_reply,
			L_UINT_TO_PTR(pac_uuid), NULL);

	return true;
}

static void send_state_changed(uint8_t index, const bdaddr_t *address,
					uint8_t address_type, uint8_t id,
					uint8_t state)
{
	struct btp_ascs_ase_state_changed_ev ev;

	memcpy(&ev.address, address, sizeof(ev.address));
	ev.address_type = address_type;
	ev.ase_id = id;
	ev.state = state;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_ASE_STATE_CHANGED,
						index, sizeof(ev), &ev);
}

static void btp_ascs_configure_codec(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_device *dev;
	const struct btp_ascs_configure_codec_cp *cp = param;
	struct btp_ascs_operation_completed_ev ev;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	dev = find_device_by_address(adapter, &cp->address, cp->address_type);
	if (!dev)
		goto failed;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_CONFIGURE_CODEC, index, 0,
									NULL);

	memcpy(&ev.address, &cp->address, sizeof(ev.address));
	ev.address_type = cp->address_type;
	ev.ase_id = cp->ase_id;
	ev.opcode = BTP_OP_ASCS_CONFIGURE_CODEC;
	ev.status = 0;
	ev.flags = 0;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_OPERATION_COMPLETED,
				adapter->index, sizeof(ev), &ev);

	send_state_changed(adapter->index, &cp->address, cp->address_type,
				cp->ase_id, BT_BAP_STREAM_STATE_CONFIG);

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, index, status);
}

static bool match_ase(const void *entry, const void *data)
{
	const struct btp_ase *ase = entry;
	uint8_t id = L_PTR_TO_UINT(data);

	return ase->ase_id == id;
}

struct configure_qos_complete_data {
	struct btp_adapter *adapter;
	const struct btp_ascs_configure_qos_cp *cp;
};

static void configure_qos_complete_cb(void *data, void *user_data)
{
	struct btp_ase *ase = data;
	struct configure_qos_complete_data *param = user_data;
	const struct btp_ascs_configure_qos_cp *cp = param->cp;
	struct btp_ascs_operation_completed_ev ev;

	if ((cp->ase_id && cp->ase_id != ase->ase_id) ||
					(cp->cig_id != ase->cig_id))
		return;

	memcpy(&ev.address, &cp->address, sizeof(ev.address));
	ev.address_type = cp->address_type;
	ev.ase_id = ase->ase_id;
	ev.opcode = BTP_OP_ASCS_CONFIGURE_QOS;
	ev.status = 0;
	ev.flags = 0;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_OPERATION_COMPLETED,
			param->adapter->index, sizeof(ev), &ev);

	send_state_changed(param->adapter->index,  &cp->address,
					cp->address_type, ase->ase_id,
					BT_BAP_STREAM_STATE_QOS);
}

static void btp_ascs_configure_qos(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_device *dev;
	const struct btp_ascs_configure_qos_cp *cp = param;
	struct configure_qos_complete_data data;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	dev = find_device_by_address(adapter, &cp->address, cp->address_type);
	if (!dev)
		goto failed;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_CONFIGURE_QOS, index, 0,
									NULL);

	/* Send BTP_EV_ASCS_OPERATION_COMPLETED for each of the ASEs */
	data.adapter = adapter;
	data.cp = cp;
	l_queue_foreach(dev->ases, configure_qos_complete_cb, &data);

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, index, status);
}

static bool read_cb(struct l_io *io, void *user_data)
{
	struct btp_ase *ase = user_data;
	struct btp_device *device = ase->device;
	struct btp_adapter *adapter = find_adapter_by_device(device);
	struct btp_bap_stream_received_ev *ev;
	ssize_t bytes_read;

	ev = l_malloc(sizeof(struct btp_bap_stream_received_ev) + ase->rx_mtu);
	memcpy(&ev->address, &device->address, sizeof(ev->address));
	ev->address_type = device->address_type;
	ev->ase_id = ase->ase_id;

	bytes_read = read(l_io_get_fd(io), ev->data, ase->rx_mtu);
	if (bytes_read < 0) {
		l_info("Invalid read length: %ld", bytes_read);
		l_free(ev);
		return false;
	}
	ev->data_len = bytes_read;

	btp_send(btp, BTP_BAP_SERVICE, BTP_EV_BAP_STREAM_RECEIVED,
				adapter->index, sizeof(*ev) + bytes_read, ev);

	l_free(ev);

	return false;
}

static bool match_ase_path(const void *entry, const void *data)
{
	const struct btp_ase *ase = entry;
	const char *path = data;
	const char *ase_path = l_dbus_proxy_get_path(ase->transport_proxy);

	if (!path || !ase_path)
		return false;

	return !strcmp(path, ase_path);
}

static void ase_change_state(struct btp_ase *ase,
					enum ase_transport_state state)
{
	struct btp_device *device = ase->device;
	struct btp_adapter *adapter = find_adapter_by_device(device);
	struct l_dbus_message_iter iter;
	const char *path;

	ase->transport_state = state;
	if (state == ASE_TRANSPORT_ACQUIRED)
		send_state_changed(adapter->index, &device->address,
						device->address_type,
						ase->ase_id,
						BT_BAP_STREAM_STATE_ENABLING);

	if (adapter->desync)
		return;

	/* Update linked endpoints */
	if (!l_dbus_proxy_get_property(ase->transport_proxy, "Links", "ao",
						&iter))
		return;

	while (l_dbus_message_iter_next_entry(&iter, &path)) {
		struct btp_ase *l;

		l = l_queue_find(device->ases, match_ase_path, path);
		if (!l)
			continue;

		l->transport_state = state;
		if (state != ASE_TRANSPORT_ACQUIRED)
			continue;

		send_state_changed(adapter->index, &l->device->address,
						l->device->address_type,
						l->ase_id,
						BT_BAP_STREAM_STATE_ENABLING);
	}
}

static void ascs_acquire_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct btp_ase *ase = user_data;
	struct btp_device *device = ase->device;
	struct btp_adapter *adapter = find_adapter_by_device(device);
	uint8_t status = BTP_ERROR_FAIL;
	int sk;
	uint16_t rx, tx;
	struct l_dbus_message_iter iter;

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to acquire endpoint (%s), %s", name, desc);

		goto failed;
	}

	if (!l_dbus_message_get_arguments(result, "hqq", &sk, &rx, &tx))
		goto failed;

	ase_change_state(ase, ASE_TRANSPORT_ACQUIRED);
	ase->rx_mtu = rx;
	ase->tx_mtu = tx;
	ase->io = l_io_new(sk);
	if (!ase->io) {
		close(sk);
		goto failed;
	}

	if (ase->dir == BTP_BAP_DIR_SOURCE)
		l_io_set_read_handler(ase->io, read_cb, ase, NULL);

	/* Update linked endpoints */
	if (l_dbus_proxy_get_property(ase->transport_proxy, "Links", "ao",
						&iter)) {
		const char *path;

		while (l_dbus_message_iter_next_entry(&iter, &path)) {
			struct btp_ase *l;

			l = l_queue_find(device->ases, match_ase_path, path);
			if (l) {
				l->rx_mtu = rx;
				l->tx_mtu = tx;
				if (l->dir == BTP_BAP_DIR_SOURCE)
					l_io_set_read_handler(ase->io,
							read_cb, l, NULL);
				break;
			}
		}
	}

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, adapter->index, status);
}

static void btp_ascs_enable(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_ascs_enable_cp *cp = param;
	struct btp_ascs_operation_completed_ev ev;
	struct btp_device *dev;
	struct btp_ase *ase;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_ENABLE, index, 0, NULL);

	memcpy(&ev.address, &cp->address, sizeof(ev.address));
	ev.address_type = cp->address_type;
	ev.ase_id = cp->ase_id;
	ev.opcode = BTP_OP_ASCS_ENABLE;
	ev.status = 0;
	ev.flags = 0;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_OPERATION_COMPLETED,
			adapter->index, sizeof(ev), &ev);

	dev = find_device_by_address(adapter, &cp->address, cp->address_type);
	if (!dev)
		goto failed;

	ase = l_queue_find(dev->ases, match_ase, L_UINT_TO_PTR(cp->ase_id));
	if (!ase)
		goto failed;

	/* In desync mode, Acquire the transport straight away and defer
	 * sending the ENABLING state notification until Acquire completes;
	 * otherwise notify ENABLING immediately.
	 */
	if (adapter->desync) {
		l_dbus_proxy_method_call(ase->transport_proxy, "Acquire",
					NULL, ascs_acquire_reply, ase, NULL);
		ase_change_state(ase, ASE_TRANSPORT_ACQUIRING);
	} else {
		send_state_changed(adapter->index, &cp->address,
						cp->address_type,
						ase->ase_id,
						BT_BAP_STREAM_STATE_ENABLING);
	}

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, index, status);
}

static void btp_ascs_receiver_start_ready(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	const struct btp_ascs_enable_cp *cp = param;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	/* Outside desync mode, Acquire the transport on Receiver Start
	 * Ready; in desync mode it was already Acquired when Enable was
	 * received.
	 */
	if (!adapter->desync) {
		struct btp_device *dev;
		struct btp_ase *ase;

		dev = find_device_by_address(adapter, &cp->address,
							cp->address_type);
		if (!dev)
			goto failed;

		ase = l_queue_find(dev->ases, match_ase,
						L_UINT_TO_PTR(cp->ase_id));
		if (!ase)
			goto failed;

		l_dbus_proxy_method_call(ase->transport_proxy, "Acquire",
					NULL, ascs_acquire_reply, ase, NULL);
		ase_change_state(ase, ASE_TRANSPORT_ACQUIRING);

		if (adapter->desync)
			return;

		send_state_changed(adapter->index, &cp->address,
						cp->address_type,
						ase->ase_id,
						BT_BAP_STREAM_STATE_ENABLING);
	}

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_RECEIVER_START_READY,
							index, 0, NULL);

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, index, status);
}

static void btp_ascs_add_ase_to_cis(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);
	struct btp_device *dev;
	const struct btp_ascs_add_ase_to_cis_cp *cp = param;
	struct btp_ase *ase;
	uint8_t status = BTP_ERROR_FAIL;

	if (!adapter) {
		status = BTP_ERROR_INVALID_INDEX;
		goto failed;
	}

	dev = find_device_by_address(adapter, &cp->address, cp->address_type);
	if (!dev)
		goto failed;

	ase = l_queue_find(dev->ases, match_ase, L_UINT_TO_PTR(cp->ase_id));
	if (!ase)
		goto failed;

	if (ase->cig_id != cp->cig_id || ase->cis_id != cp->cis_id) {
		l_error("Invalid CIG/CIS ID, expecting %u/%u, got %u/%u",
						ase->cig_id, ase->cis_id,
						cp->cig_id, cp->cis_id);
		goto failed;
	}

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_ADD_ASE_TO_CIS, index, 0,
									NULL);

	if (ase->transport_proxy) {
		struct btp_ascs_cis_connected_ev ev;

		memcpy(&ev.address, &dev->address, sizeof(ev.address));
		ev.address_type = dev->address_type;
		ev.ase_id = ase->ase_id;
		ev.cis_id = ase->cis_id;

		btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_CIS_CONNECTED,
				adapter->index, sizeof(ev), &ev);
	}

	return;

failed:
	btp_send_error(btp, BTP_ASCS_SERVICE, index, status);
}

static void btp_ascs_preconfigure_qos(uint8_t index, const void *param,
					uint16_t length, void *user_data)
{
	struct btp_adapter *adapter = find_adapter_by_index(index);

	if (!adapter) {
		btp_send_error(btp, BTP_ASCS_SERVICE, index,
						BTP_ERROR_INVALID_INDEX);
		return;
	}

	btp_send(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_PRECONFIGURE_QOS, index, 0,
									NULL);
}

bool ascs_setup(struct btp_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, ASE_SINK_UUID);
	register_endpoint(adapter, &uuid);
	bt_uuid16_create(&uuid, ASE_SOURCE_UUID);
	register_endpoint(adapter, &uuid);

	return true;
}

static struct l_dbus_message *ep_set_conf(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	l_info("Set configuration (%s)", l_dbus_message_get_path(message));

	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *ep_select_conf(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	l_info("Select configuration (%s)", l_dbus_message_get_path(message));

	return l_dbus_message_new_error(message,
					"org.bluez.Error.NotSupported",
					"NotSupported");
}

static void parse_capabilities(uint8_t *data, uint32_t len, uint16_t *rates,
				uint8_t *durations, uint8_t *channel_counts,
				uint16_t *frame_min, uint16_t *frame_max,
				uint8_t *blks)
{
	uint32_t i = 0;

	while (i < len) {
		struct bt_ltv *ltv = (struct bt_ltv *)(data + i);

		if ((i + ltv->len >= len) || (!ltv->len)) {
			l_warn("Invalid LTV in capabilities");
			return;
		}

		switch (ltv->type) {
		case LC3_FREQ:
			if (rates)
				*rates = bt_get_le16(ltv->value);
			break;
		case LC3_DURATION:
			if (durations)
				*durations = ltv->value[0];
			break;
		case LC3_CHAN_COUNT:
			if (channel_counts)
				*channel_counts = ltv->value[0];
			break;
		case LC3_FRAME_LEN:
			if (frame_min)
				*frame_min = bt_get_le16(&ltv->value[0]);
			if (frame_max)
				*frame_max = bt_get_le16(&ltv->value[2]);
			break;
		case LC3_FRAME_COUNT:
			if (blks)
				*blks = ltv->value[0];
			break;
		default:
			l_debug("Unknown capability type: 0x%02X", ltv->type);
		}

		i += ltv->len + 1;
	}
}

static void parse_config(struct codec_preset *preset, uint8_t *freq,
				uint8_t *duration, uint16_t *frame_len)
{
	uint8_t *cfg = preset->data.iov_base;
	size_t len = preset->data.iov_len;
	uint8_t *ptr = cfg;

	while ((size_t)(ptr - cfg) < len) {
		uint8_t length = ptr[0];
		uint8_t type;

		if (length < 1) {
			l_warn("Invalid LTV in capabilities");
			return;
		}

		ptr++;
		type = ptr[0];

		switch (type) {
		case LC3_CONFIG_FREQ:
			if (freq)
				*freq = ptr[1];
			break;
		case LC3_CONFIG_DURATION:
			if (duration)
				*duration = ptr[1];
			break;
		case LC3_CONFIG_FRAME_LEN:
			if (frame_len)
				*frame_len = bt_get_le16(&ptr[1]);
			break;
		default:
			l_debug("Unknown config type: 0x%02X", type);
		}

		ptr += length;
	}
}

static struct codec_preset *select_properties(uint16_t rates, uint8_t durations,
				uint8_t channel_counts, uint16_t frame_min,
				uint16_t frame_max, uint32_t locations,
				uint32_t channel, uint8_t target_latency)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lc3_ucast_presets); i++) {
		struct codec_preset *preset = &lc3_ucast_presets[i];
		uint8_t c_freq = 0;
		uint8_t c_duration = UINT8_MAX;
		uint16_t c_frame_len = UINT16_MAX;

		parse_config(preset, &c_freq, &c_duration, &c_frame_len);
		if ((c_freq == 0) || (c_duration == UINT8_MAX) ||
						(c_frame_len == UINT16_MAX))
			continue;

		if (!((1 << (c_freq - 1)) & rates))
			continue;

		if (!((1 << c_duration) & durations))
			continue;

		if ((c_frame_len < frame_min) || (c_frame_len > frame_max))
			continue;

		if (target_latency &&
				(preset->target_latency != target_latency))
			continue;

		return preset;
	}

	return NULL;
}

static void ltv_find(size_t i, uint8_t l, uint8_t t, uint8_t *v,
					void *user_data)
{
	bool *found = user_data;

	*found = true;
}

static uint8_t get_next_cis(struct btp_device *device, uint8_t dir,
							uint8_t base)
{
	const struct l_queue_entry *adapter_entry;
	const struct l_queue_entry *ase_entry;
	uint8_t cis = base;
	bool found = false;

	/* For the same device, reuse the opposite cis_id if there is no ASE
	 * in the requested direction already using that same cis_id
	 */
	for (ase_entry = l_queue_get_entries(device->ases); ase_entry;
					ase_entry = ase_entry->next) {
		struct btp_ase *ase = ase_entry->data;
		const struct l_queue_entry *entry;
		bool has_same_dir = false;

		if (ase->dir == dir)
			continue;

		for (entry = l_queue_get_entries(device->ases); entry;
					entry = entry->next) {
			struct btp_ase *peer = entry->data;

			if (peer->dir == dir && peer->cis_id == ase->cis_id) {
				has_same_dir = true;
				break;
			}
		}

		if (!has_same_dir)
			return ase->cis_id;
	}

	/* Else returns the global highest cis_id + 1 across all ASEs of all
	 * devices, or 'base' if none has already been assigned
	 */
	for (adapter_entry = l_queue_get_entries(get_adapters_list());
					adapter_entry;
					adapter_entry = adapter_entry->next) {
		struct btp_adapter *adapter = adapter_entry->data;
		const struct l_queue_entry *device_entry;

		for (device_entry = l_queue_get_entries(adapter->devices);
					device_entry;
					device_entry = device_entry->next) {
			struct btp_device *dev = device_entry->data;

			for (ase_entry = l_queue_get_entries(dev->ases);
						ase_entry;
						ase_entry = ase_entry->next) {
				struct btp_ase *ase = ase_entry->data;

				if (ase->cis_id == BT_ISO_QOS_CIS_UNSET)
					continue;

				if (!found || ase->cis_id > cis)
					cis = ase->cis_id;

				found = true;
			}
		}
	}

	if (!found)
		return cis;

	return cis + 1;
}

static struct l_dbus_message *get_properties_reply(
						struct l_dbus_message *message,
						struct btp_adapter *adapter,
						struct btp_ase *ase)
{
	struct l_dbus_message_iter props, var, var_2;
	const char *key;
	uint8_t *data;
	uint32_t n = UINT8_MAX;
	uint8_t durations = 0, channel_counts = 0;
	uint16_t rates = 0, frame_min = 0, frame_max = 0;
	uint32_t locations = 0, channel = 1;
	struct l_dbus_message *reply;
	struct l_dbus_message_builder *builder;
	uint8_t i;
	struct codec_preset *preset;
	struct iovec *caps;
	uint8_t type = LC3_CONFIG_CHAN_ALLOC;
	bool found = false;
	uint8_t *ptr;
	uint16_t sdu;

	l_info("Select properties (%s)", l_dbus_message_get_path(message));

	if (!l_dbus_message_get_arguments(message, "a{sv}", &props))
		goto failed;

	while (l_dbus_message_iter_next_entry(&props, &key, &var)) {
		if (!strcmp(key, "Capabilities")) {
			if (!l_dbus_message_iter_get_variant(&var, "ay",
								&var_2)) {
				l_debug("Failed to get data variant");
				goto failed;
			}

			if (!l_dbus_message_iter_get_fixed_array(&var_2,
								&data, &n)) {
				l_debug("Cannot get Capabilities");
				goto failed;
			}

			parse_capabilities(data, n, &rates, &durations,
						&channel_counts, &frame_min,
						&frame_max, NULL);
		} else if (!strcmp(key, "ChannelAllocation")) {
			if (!l_dbus_message_iter_get_variant(&var, "u",
								&channel))
				goto failed;
		} else if (!strcmp(key, "Locations")) {
			if (!l_dbus_message_iter_get_variant(&var, "u",
								&locations))
				goto failed;
		}
	}

	preset = select_properties(rates, durations, channel_counts,
					frame_min, frame_max, locations,
					channel, adapter->target_latency);
	if (!preset)
		goto failed;

	caps = util_iov_dup(&preset->data, 1);
	/* Check if Channel Allocation is present in caps */
	util_ltv_foreach(caps->iov_base, caps->iov_len,
				&type, ltv_find, &found);

	/* If Channel Allocation has not been set directly via
	 * preset->data then attempt to set it if chan_alloc has been
	 * set.
	 */
	if (!found && locations) {
		uint8_t chan_alloc_ltv[] = {
			0x05, LC3_CONFIG_CHAN_ALLOC, 0, 0, 0, 0
		};

		put_le32(channel, &chan_alloc_ltv[2]);
		util_iov_append(caps, &chan_alloc_ltv,
					sizeof(chan_alloc_ltv));
	}

	reply = l_dbus_message_new_method_return(message);

	builder = l_dbus_message_builder_new(reply);
	l_dbus_message_builder_enter_array(builder, "{sv}");

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Capabilities");
	l_dbus_message_builder_enter_variant(builder, "ay");
	l_dbus_message_builder_enter_array(builder, "y");
	ptr = caps->iov_base;
	for (i = 0; i < caps->iov_len; i++)
		l_dbus_message_builder_append_basic(builder, 'y', ptr++);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "QoS");
	l_dbus_message_builder_enter_variant(builder, "a{sv}");
	l_dbus_message_builder_enter_array(builder, "{sv}");

	/* SelectProperties() is only invoked when acting as the Unicast Client,
	 * so assign CIG 0 here and pick the next available CIS for this ASE.
	 */
	if (ase->cig_id == BT_ISO_QOS_CIG_UNSET)
		ase->cig_id = 0;
	if (ase->cis_id == BT_ISO_QOS_CIS_UNSET)
		ase->cis_id = get_next_cis(ase->device, ase->dir, 0);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's',
					"CIG");
	l_dbus_message_builder_enter_variant(builder, "y");
	l_dbus_message_builder_append_basic(builder, 'y',
					&ase->cig_id);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's',
					"CIS");
	l_dbus_message_builder_enter_variant(builder, "y");
	l_dbus_message_builder_append_basic(builder, 'y',
					&ase->cis_id);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's',
					"PresentationDelay");
	l_dbus_message_builder_enter_variant(builder, "u");
	l_dbus_message_builder_append_basic(builder, 'u',
					&preset->qos.ucast.delay);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's',
					"TargetLatency");
	l_dbus_message_builder_enter_variant(builder, "y");
	l_dbus_message_builder_append_basic(builder, 'y',
					&preset->qos.ucast.target_latency);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Interval");
	l_dbus_message_builder_enter_variant(builder, "u");
	l_dbus_message_builder_append_basic(builder, 'u',
					&preset->qos.ucast.io_qos.interval);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "PHY");
	l_dbus_message_builder_enter_variant(builder, "y");
	l_dbus_message_builder_append_basic(builder, 'y',
					&preset->qos.ucast.io_qos.phys);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "SDU");
	l_dbus_message_builder_enter_variant(builder, "q");
	sdu = preset->qos.ucast.io_qos.sdu * channel;
	l_dbus_message_builder_append_basic(builder, 'q', &sdu);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's',
					"Retransmissions");
	l_dbus_message_builder_enter_variant(builder, "y");
	l_dbus_message_builder_append_basic(builder, 'y',
					&preset->qos.ucast.io_qos.rtn);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "Latency");
	l_dbus_message_builder_enter_variant(builder, "q");
	l_dbus_message_builder_append_basic(builder, 'q',
				&preset->qos.ucast.io_qos.latency);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	return reply;

failed:
	return l_dbus_message_new_error(message, "org.bluez.Error.Invalid",
						"Invalid arguments");
}

static struct l_dbus_message *ep_select_properties(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct btp_adapter *adapter = user_data;
	struct l_dbus_message_iter props, var;
	const struct l_queue_entry *e1, *e2;
	const char *key, *ep_path = NULL;
	struct btp_ase *ase = NULL;

	if (!l_dbus_message_get_arguments(message, "a{sv}", &props))
		goto failed;

	while (l_dbus_message_iter_next_entry(&props, &key, &var)) {
		if (!strcmp(key, "Endpoint")) {
			if (!l_dbus_message_iter_get_variant(&var, "o",
								&ep_path))
				goto failed;
		}
	}

	if (!ep_path)
		goto failed;

	for (e1 = l_queue_get_entries(adapter->devices); e1; e1 = e1->next) {
		struct btp_device *device = e1->data;

		for (e2 = l_queue_get_entries(device->ases); e2;
							e2 = e2->next) {
			struct btp_ase *a = e2->data;

			if (a->ep_proxy == NULL)
				continue;

			if (!strcmp(l_dbus_proxy_get_path(a->ep_proxy),
								ep_path)) {
				ase = a;
				break;
			}
		}
	}

	if (!ase) {
		l_info("Select properties (%s) postponed",
					l_dbus_message_get_path(message));
		l_queue_push_tail(pending_select_properties,
					l_dbus_message_ref(message));
		return NULL;
	}

	return get_properties_reply(message, adapter, ase);

failed:
	return l_dbus_message_new_error(message, "org.bluez.Error.Invalid",
						"Invalid arguments");
}

static struct l_dbus_message *ep_clear_conf(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	l_info("Clear configuration (%s)", l_dbus_message_get_path(message));

	return l_dbus_message_new_error(message,
					"org.bluez.Error.NotSupported",
					"NotSupported");
}

static void setup_endpoint_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "SetConfiguration", 0,
					ep_set_conf, "", "oa{sv}",
					"transport", "properties");
	l_dbus_interface_method(iface, "SelectConfiguration", 0,
					ep_select_conf, "ay", "ay",
					"capabilities");
	l_dbus_interface_method(iface, "SelectProperties", 0,
					ep_select_properties, "a{sv}",
					"a{sv}", "capabilities");
	l_dbus_interface_method(iface, "ClearConfiguration", 0,
					ep_clear_conf, "", "o", "transport");
}

static struct l_dbus_message *find_pending_msg(struct l_queue *l,
							struct btp_ase *ase)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(l); entry; entry = entry->next) {
		struct l_dbus_message *msg = entry->data;
		struct l_dbus_message_iter props, var;
		const char *key, *ep_path = NULL;

		if (!l_dbus_message_get_arguments(msg, "a{sv}", &props))
			continue;

		while (l_dbus_message_iter_next_entry(&props, &key, &var)) {
			if (!strcmp(key, "Endpoint")) {
				if (l_dbus_message_iter_get_variant(&var, "o",
								&ep_path))
					break;
			}
		}

		if (!l_dbus_proxy_get_path(ase->ep_proxy))
			continue;

		if (ep_path && !strcmp(l_dbus_proxy_get_path(ase->ep_proxy),
								ep_path))
			return msg;
	}

	return NULL;
}

static void set_desync_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *result, void *user_data)
{
	struct btp_ase *ase = user_data;
	struct btp_adapter *adapter;
	struct btp_ascs_cis_connected_ev ev;

	if (l_dbus_message_is_error(result)) {
		const char *name, *desc;

		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to desync Links (%s), %s", name, desc);
		return;
	}

	adapter = find_adapter_by_device(ase->device);
	if (!adapter)
		return;

	memcpy(&ev.address, &ase->device->address, sizeof(ev.address));
	ev.address_type = ase->device->address_type;
	ev.ase_id = ase->ase_id;
	ev.cis_id = ase->cis_id;

	btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_CIS_CONNECTED,
			adapter->index, sizeof(ev), &ev);
}

void ascs_ase_replied(struct btp_adapter *adapter, struct btp_ase *ase)
{
	struct l_dbus_message *msg, *reply;

	msg = find_pending_msg(pending_select_properties, ase);
	if (msg) {
		l_queue_remove(pending_select_properties, msg);
		reply = get_properties_reply(msg, adapter, ase);
		l_dbus_send(dbus, reply);

		l_dbus_message_unref(msg);
	}
}

static bool transport_get_cig_cis(struct l_dbus_proxy *proxy, uint8_t *cig,
								uint8_t *cis)
{
	struct l_dbus_message_iter iter, var;
	const char *key;

	*cig = BT_ISO_QOS_CIG_UNSET;
	*cis = BT_ISO_QOS_CIS_UNSET;

	if (!l_dbus_proxy_get_property(proxy, "QoS", "a{sv}", &iter))
		return false;

	while (l_dbus_message_iter_next_entry(&iter, &key, &var)) {
		if (!strcmp(key, "CIG")) {
			if (!l_dbus_message_iter_get_variant(&var, "y", cig))
				return false;
		}

		if (!strcmp(key, "CIS")) {
			if (!l_dbus_message_iter_get_variant(&var, "y", cis))
				return false;
		}
	}

	return true;
}

struct set_cig_cis_data {
	struct btp_device *device;
	uint8_t cig;
};

static void set_cig_cis(void *data, void *user_data)
{
	struct btp_ase *ase = data;
	struct set_cig_cis_data *param = user_data;
	uint8_t cis = get_next_cis(param->device, ase->dir, 1);

	if (ase->cig_id != BT_ISO_QOS_CIG_UNSET)
		return;

	ase->cig_id = param->cig;
	ase->cis_id = cis;
}

void ascs_proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	char *str, *state;
	struct btp_device *device = user_data;
	struct btp_adapter *adapter;
	uint8_t dir;
	uint8_t cig = BT_ISO_QOS_CIG_UNSET, cis = BT_ISO_QOS_CIS_UNSET;
	struct btp_ase *ase;

	adapter = find_adapter_by_device(device);
	if (!adapter)
		return;

	if (!l_dbus_proxy_get_property(proxy, "UUID", "s", &str))
		return;

	if (!l_dbus_proxy_get_property(proxy, "State", "s", &state))
		return;

	if (!bt_uuid_strcmp(str, PAC_SINK_UUID))
		dir = BTP_BAP_DIR_SOURCE;
	else
		dir = BTP_BAP_DIR_SINK;

	if (!transport_get_cig_cis(proxy, &cig, &cis)) {
		struct set_cig_cis_data data;

		/* No CIG/CIS reported on the transport yet, meaning this ASE
		 * is acting as the Unicast Server: assign CIG 1 to all of the
		 * device's ASEs and let set_cig_cis() derive their CIS ids.
		 */
		data.device = device;
		data.cig = 1;
		l_queue_foreach(device->ases, set_cig_cis, &data);
		return;
	}

	ase = find_ase(device, cig, cis, dir);
	if (!ase)
		return;

	ase->transport_proxy = proxy;

	/* In desync mode, the CIS_CONNECTED event is sent later, once the
	 * "Desynchronized" property has been set (see set_desync_reply());
	 * otherwise send it now.
	 */
	if (!adapter->desync) {
		struct btp_ascs_cis_connected_ev ev;

		memcpy(&ev.address, &device->address, sizeof(ev.address));
		ev.address_type = device->address_type;
		ev.ase_id = ase->ase_id;
		ev.cis_id = ase->cis_id;

		btp_send(btp, BTP_ASCS_SERVICE, BTP_EV_ASCS_CIS_CONNECTED,
				adapter->index, sizeof(ev), &ev);
	}

	if (ase->transport_state == ASE_TRANSPORT_ACQUIRING &&
			!strcmp(state, "idle")) {
		l_dbus_proxy_method_call(proxy, "Acquire",
					NULL,
					ascs_acquire_reply,
					ase, NULL);
	}
}

void ascs_property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.MediaTransport1")) {
		if (!strcmp(name, "State")) {
			const char *state, *path, *uuid;
			struct btp_device *dev;
			struct btp_adapter *adapter;
			uint8_t dir, cig, cis;
			struct btp_ase *ase;
			uint8_t ase_state;

			if (!l_dbus_message_get_arguments(msg, "s", &state))
				return;

			if (!l_dbus_proxy_get_property(proxy, "Device", "o",
								&path))
				return;

			dev = find_device_by_path(path);
			if (!dev)
				return;

			adapter = find_adapter_by_device(dev);
			if (!adapter)
				return;

			if (!l_dbus_proxy_get_property(proxy, "UUID", "s",
								&uuid))
				return;

			if (!bt_uuid_strcmp(uuid, PAC_SINK_UUID))
				dir = BTP_BAP_DIR_SOURCE;
			else
				dir = BTP_BAP_DIR_SINK;

			if (!transport_get_cig_cis(proxy, &cig, &cis))
				return;

			ase = find_ase(dev, cig, cis, dir);
			if (!ase)
				return;

			if (!strcmp(state, "active"))
				ase_state = BT_BAP_STREAM_STATE_STREAMING;
			else if (!strcmp(state, "pending") &&
				ase->transport_state == ASE_TRANSPORT_READY) {
				l_dbus_proxy_method_call(proxy, "Acquire",
							NULL,
							ascs_acquire_reply,
							ase, NULL);
				ase_change_state(ase, ASE_TRANSPORT_ACQUIRING);
				ase_state = BT_BAP_STREAM_STATE_ENABLING;
			} else {
				if (ase->io) {
					l_io_destroy(ase->io);
					ase->io = NULL;
				}

				ase_state = BT_BAP_STREAM_STATE_IDLE;
			}

			send_state_changed(adapter->index,  &dev->address,
							dev->address_type,
							ase->ase_id,
							ase_state);
		}

		if (!strcmp(name, "Desynchronized")) {
			struct btp_device *dev;
			struct btp_adapter *adapter;
			const bool desynchronized;
			const char *path, *uuid;
			uint8_t dir, cig, cis;
			struct btp_ase *ase;

			if (!l_dbus_message_get_arguments(msg, "b",
							&desynchronized))
				return;

			if (!l_dbus_proxy_get_property(proxy, "Device", "o",
								&path))
				return;

			dev = find_device_by_path(path);
			if (!dev)
				return;

			adapter = find_adapter_by_device(dev);
			if (!adapter || !adapter->desync)
				return;

			if (!l_dbus_proxy_get_property(proxy, "UUID", "s",
								&uuid))
				return;

			if (!bt_uuid_strcmp(uuid, PAC_SINK_UUID))
				dir = BTP_BAP_DIR_SOURCE;
			else
				dir = BTP_BAP_DIR_SINK;

			if (!transport_get_cig_cis(proxy, &cig, &cis))
				return;

			ase = find_ase(dev, cig, cis, dir);
			if (!ase)
				return;

			if (!desynchronized) {
				l_dbus_proxy_set_property(proxy,
							set_desync_reply,
							ase, NULL,
							"Desynchronized", "b",
							true);
			}
		}
	}
}

bool ascs_register_service(struct btp *btp_, struct l_dbus *dbus_,
					struct l_dbus_client *client)
{
	btp = btp_;
	dbus = dbus_;

	btp_register(btp, BTP_ASCS_SERVICE,
					BTP_OP_ASCS_READ_SUPPORTED_COMMANDS,
					btp_ascs_read_commands, NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_CONFIGURE_CODEC,
					btp_ascs_configure_codec, NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_CONFIGURE_QOS,
					btp_ascs_configure_qos, NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_ENABLE,
					btp_ascs_enable, NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_RECEIVER_START_READY,
					btp_ascs_receiver_start_ready,
					NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_ADD_ASE_TO_CIS,
					btp_ascs_add_ase_to_cis, NULL, NULL);

	btp_register(btp, BTP_ASCS_SERVICE, BTP_OP_ASCS_PRECONFIGURE_QOS,
					btp_ascs_preconfigure_qos, NULL, NULL);

	if (!l_dbus_register_interface(dbus, ENDPOINT_IFACE,
						setup_endpoint_interface,
						NULL, false)) {
		l_info("Unable to register endpoint interface");
		return false;
	}

	pending_select_properties = l_queue_new();

	ascs_service_registered = true;

	return true;
}

void ascs_unregister_service(struct btp *btp)
{
	l_queue_destroy(pending_select_properties,
				(l_queue_destroy_func_t)l_dbus_message_unref);

	if (!l_dbus_unregister_interface(dbus, ENDPOINT_IFACE))
		l_info("Unable to unregister endpoint interface");

	btp_unregister_service(btp, BTP_ASCS_SERVICE);
	ascs_service_registered = false;
}

bool ascs_is_service_registered(void)
{
	return ascs_service_registered;
}
