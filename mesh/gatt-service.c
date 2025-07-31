// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>			// memcpy(), strerror()
#include <sys/socket.h>			// SOCK_SEQPACKET, SOCK_NONBLOCK,
					// AF_UNIX, SOCK_CLOEXEC, MSG_NOSIGNAL,
					// struct msghdr,
					// socketpair(), sendmsg()
#include <sys/types.h>			// struct iovec
#include <unistd.h>			// close()

#include <ell/dbus.h>
#include <ell/dbus-client.h>
#include <ell/dbus-service.h>
#include <ell/idle.h>
#include <ell/io.h>
#include <ell/log.h>
#include <ell/util.h>			// L_ARRAY_SIZE(),
					// l_new(), l_free()

#include "mesh/dbus.h"			// dbus_get_bus(),
					// dbus_append_byte_array(),
					// dbus_error()
#include "mesh/error.h"			// MESH_ERROR_INVALID_ARGS
#include "mesh/util.h"			// print_packet()
#include "mesh/gatt-service.h"

#define GATT_SERVICE_IFACE "org.bluez.GattService1"
#define BLUEZ_MESH_GATT_PATH BLUEZ_MESH_PATH "/gatt"
#define BLUEZ_MESH_SERVICE_PATH BLUEZ_MESH_GATT_PATH "/service"
#define BLUEZ_MESH_CHRC_DATA_IN_PATH BLUEZ_MESH_SERVICE_PATH "/data_in"
#define BLUEZ_MESH_CHRC_DATA_OUT_PATH BLUEZ_MESH_SERVICE_PATH "/data_out"
/*
 * Advertising should NOT be handled by provisioning's object manager, so
 * we cannot use a child element of BLUEZ_MESH_GATT_PATH.
 */
#define BLUEZ_MESH_GATT_ADV_PATH BLUEZ_MESH_PATH "/gatt_adv"

#define GATT_MGR_IFACE "org.bluez.GattManager1"
#define GATT_SERVICE_IFACE "org.bluez.GattService1"
#define GATT_CHRC_IFACE "org.bluez.GattCharacteristic1"

#define LE_ADVERTISING_MGR_IFACE "org.bluez.LEAdvertisingManager1"
#define LE_ADVERTISEMENT_IFACE "org.bluez.LEAdvertisement1"

#define GATT_MTU 23

struct gatt_service;
struct characterstic
{
	const char *uuid;
	const char * const *flags;
	struct gatt_service *service;
};

enum write_value_type {
	WRITE_VALUE_TYPE_COMMAND,
	WRITE_VALUE_TYPE_REQUEST,
	WRITE_VALUE_TYPE_RELIABLE
};

enum link_type {
	LINK_TYPE_BR_EDR,
	LINK_TYPE_LE
};

struct write_value_options {
	const char *device;
	enum link_type link;
	enum write_value_type type;
	uint16_t offset;
	uint16_t mtu;
	bool prepare_authorize;
};

struct acquire_notify_options {
	const char *device;
	enum link_type link;
	uint16_t mtu;
};

/* MshPRT_v1.1, section 6.3.1, SAR field */
#define PROXY_PDA_SAR_SHIFT	6
#define PROXY_PDA_SAR_MASK	0x3
enum proxy_pdu_sar {
	PROXY_PDU_SAR_CMPLT_MSG = 0x00,
	PROXY_PDU_SAR_1ST_SEG   = 0x01,
	PROXY_PDU_SAR_CONT_SEG  = 0x02,
	PROXY_PDU_SAR_LAST_SEG  = 0x03,
};

struct gatt_service {
	const char *svc_uuid;
	uint8_t max_pdu_len;

	gatt_service_notify_acquired_cb notify_acquired_cb;
	gatt_service_notify_stopped_cb notify_stopped_cb;
	gatt_service_rx_cb rx_cb;
	gatt_service_tx_cmplt_cb tx_cmplt_cb;
	gatt_service_fill_adv_service_data_cb fill_adv_service_data_cb;
	struct characterstic chrc_data_in;
	struct characterstic chrc_data_out;

	struct l_dbus_client *dbus_client;
	struct l_dbus_proxy *dbus_proxy_gatt_mgr;
	struct l_dbus_proxy *dbus_proxy_le_adv_mgr;

	/*
	 * ToDo: Check whether acceptors timeout complies with MshPRT_v1.1,
	 * section 5.2.2
	 */
	struct l_io *notify_io;
	uint16_t mtu;
	uint8_t *sar;
	uint8_t *sar_out;
	uint8_t msg_type;
	uint8_t sar_len;
	void *user_data;

	gatt_destroy_cb svc_deinit_cb;
	gatt_destroy_cb adv_deinit_cb;

	gatt_destroy_cb destroy_cb;
	void *destroy_data;
};

static struct gatt_service *gatt_service = NULL;

static bool notify_write(struct l_io *io, void *user_data)
{
	struct gatt_service *service = user_data;
	unsigned int remaining = (service->sar + service->sar_len)
						- service->sar_out;
	unsigned max_size = service->mtu - 5;
	struct iovec iov[2];
	struct msghdr msg;
	bool more = false;
	uint8_t sar_type;
	int i, count;

	/* Note: One extra byte is required for sar_type */
	if (service->sar_len < max_size) {
		sar_type = PROXY_PDU_SAR_CMPLT_MSG;
		count = service->sar_len;
	}
	else if (service->sar_out == service->sar) {
		sar_type = PROXY_PDU_SAR_1ST_SEG;
		count = max_size - 1;
		more = true;
	}
	else if (remaining < max_size) {
		sar_type = PROXY_PDU_SAR_LAST_SEG;
		count = remaining;
	}
	else {
		sar_type = PROXY_PDU_SAR_CONT_SEG;
		count = max_size - 1;
		more = true;
	}

	sar_type <<= PROXY_PDA_SAR_SHIFT;
	sar_type |= service->msg_type;

//	l_info("remaining=%u, count=%u, sar_type=0x%02x", remaining, count, sar_type);
//	print_packet("notify_write", service->sar_out, count);

	iov[0].iov_base = &sar_type;
	iov[0].iov_len = sizeof(sar_type);
	iov[1].iov_base = service->sar_out;
	iov[1].iov_len = count;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = L_ARRAY_SIZE(iov);

	if (sendmsg(l_io_get_fd(service->notify_io), &msg, MSG_NOSIGNAL) < 0)
		l_error("Cannot write notification data: %s", strerror(errno));

	service->sar_out += count;

	if (!more)
		more = service->tx_cmplt_cb(service->user_data);

	return more;
}

void gatt_service_tx(struct gatt_service *service, uint8_t msg_type,
						const void *data, uint16_t len)
{
	if (!service || gatt_service != service)
		return;

	if (len > service->max_pdu_len) {
		l_error("Frame too long");
		return;
	}

	if (!service->notify_io) {
		l_warn("Not connected, dropping TX message...");
		return;
	}

	memcpy(service->sar, data, len);
	service->sar_len = len;
	service->sar_out = service->sar;
	service->msg_type = msg_type;
	print_packet("TX-GATT", service->sar, service->sar_len);
	l_io_set_write_handler(service->notify_io, notify_write, service, NULL);
}

static bool svc_uuid_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct gatt_service *service = user_data;

//	l_info("svc_uuid_getter");
	return l_dbus_message_builder_append_basic(builder, 's',
							service->svc_uuid);
}

static bool svc_primary_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	bool primary = true;

//	l_info("svc_primary_getter");
	return l_dbus_message_builder_append_basic(builder, 'b', &primary);
}

static void setup_gatt_svc_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_property(iface, "UUID", 0, "s", svc_uuid_getter, NULL);
	l_dbus_interface_property(iface, "Primary", 0, "b", svc_primary_getter,
									NULL);
}

static bool parse_write_value_options(struct l_dbus_message_iter *itr,
					struct write_value_options *opts)
{
	const char *key;
	struct l_dbus_message_iter var;

	opts->device = NULL;
	opts->link = LINK_TYPE_BR_EDR;
	opts->type = WRITE_VALUE_TYPE_COMMAND;
	opts->offset = 0;
	opts->mtu = 0;
	opts->prepare_authorize = false;

	while (l_dbus_message_iter_next_entry(itr, &key, &var)) {
		if (!strcmp(key, "device")) {
			if (!l_dbus_message_iter_get_variant(&var, "o",
								&opts->device))
				return false;
		} else if (!strcmp(key, "link")) {
			const char *link;

			if (!l_dbus_message_iter_get_variant(&var, "s", &link))
				return false;

			if (!strcmp(link, "BR/EDR"))
				opts->link = LINK_TYPE_BR_EDR;
			else if (!strcmp(link, "LE"))
				opts->link = LINK_TYPE_LE;
			else
				return false;
		} else if (!strcmp(key, "type")) {
			const char *type;

			if (!l_dbus_message_iter_get_variant(&var, "s", &type))
				return false;

			if (!strcmp(type, "command"))
				opts->type = WRITE_VALUE_TYPE_COMMAND;
			else if (!strcmp(type, "request"))
				opts->type = WRITE_VALUE_TYPE_REQUEST;
			else if (!strcmp(type, "reliable"))
				opts->type = WRITE_VALUE_TYPE_RELIABLE;
			else
				return false;
		} else if (!strcmp(key, "offset")) {
			if (!l_dbus_message_iter_get_variant(&var, "q",
								&opts->offset))
				return false;
		} else if (!strcmp(key, "mtu")) {
			if (!l_dbus_message_iter_get_variant(&var, "q",
								&opts->mtu))
				return false;
		} else if (!strcmp(key, "prepare-authorize")) {
			if (!l_dbus_message_iter_get_variant(&var, "b",
						&opts->prepare_authorize))
				return false;
		}
	}

	return true;
}

static struct l_dbus_message *chrc_write_value_call(struct l_dbus *,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct characterstic *chr = user_data;
	struct gatt_service *service = chr->service;
	struct l_dbus_message_iter iter_data, dict;
	struct write_value_options opts;
	enum proxy_pdu_sar sar;
	uint8_t msg_type;
	uint8_t *data;
	uint32_t len;
	int i;

	if (!l_dbus_message_get_arguments(msg, "aya{sv}", &iter_data, &dict))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!parse_write_value_options(&dict, &opts))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > service->max_pdu_len)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

//	l_info("chrc_write_value_call(type=%u, offset=%u, mtu=%u)", opts.type, opts.offset, opts.mtu);
//	print_packet("WriteValue", data, len);

	if (len < 1)
		return l_dbus_message_new_method_return(msg);

	sar = (data[0] >> PROXY_PDA_SAR_SHIFT) & PROXY_PDA_SAR_MASK;
	msg_type = data[0] & PROXY_MSG_TYPE_MASK;

	switch (sar)  {
		case PROXY_PDU_SAR_CMPLT_MSG:
			print_packet("RX-GATT", data, len);
			service->rx_cb(service->user_data, msg_type, data, len);
			break;

		case PROXY_PDU_SAR_1ST_SEG:
			if (len > service->max_pdu_len) {
				l_debug("Length exceeded: %d", len);
				break;
			}

			memcpy(service->sar, data, len);
			service->sar_len = len;
			break;

		case PROXY_PDU_SAR_CONT_SEG:
		case PROXY_PDU_SAR_LAST_SEG: {
			if (len - 1 > service->max_pdu_len - service->sar_len) {
				l_debug("Length exceeded: %d", len);
				break;
			}

			memcpy(service->sar + service->sar_len,
							data + 1, len - 1);
			service->sar_len += len - 1;

			if (sar == PROXY_PDU_SAR_LAST_SEG) {
				uint8_t sar_len = service->sar_len;

				/* reused by gatt_service_tx */
				service->sar_len = 0;
				print_packet("RX-GATT", service->sar, sar_len);
				service->rx_cb(service->user_data, msg_type,
							service->sar, sar_len);
			}

			break;
		}
	}

	return l_dbus_message_new_method_return(msg);
}

static bool parse_acquire_notify_options(struct l_dbus_message_iter *itr,
					struct acquire_notify_options *opts)
{
	const char *key;
	struct l_dbus_message_iter var;

	opts->device = NULL;
	opts->link = LINK_TYPE_BR_EDR;
	opts->mtu = 0;

	while (l_dbus_message_iter_next_entry(itr, &key, &var)) {
		if (!strcmp(key, "device")) {
			if (!l_dbus_message_iter_get_variant(&var, "o",
								&opts->device))
				return false;
		} else if (!strcmp(key, "link")) {
			const char *link;

			if (!l_dbus_message_iter_get_variant(&var, "s", &link))
				return false;

			if (!strcmp(link, "BR/EDR"))
				opts->link = LINK_TYPE_BR_EDR;
			else if (!strcmp(link, "LE"))
				opts->link = LINK_TYPE_LE;
			else
				return false;
		} else if (!strcmp(key, "mtu")) {
			if (!l_dbus_message_iter_get_variant(&var, "q",
								&opts->mtu))
				return false;
		}
	}

	return true;
}

static void notify_disconnected(struct l_io *io, void *user_data)
{
	struct gatt_service *service = user_data;

	if (service != gatt_service)
		return;

	l_debug("notify_disconnected");

	if (!service->notify_io)
		return;

	/* avoid recursion */
	l_io_set_disconnect_handler(service->notify_io, NULL, NULL, NULL);

	l_io_destroy(service->notify_io);
	service->notify_io = NULL;

	if (service->notify_stopped_cb)
		service->notify_stopped_cb(service->user_data);
}

static struct l_dbus_message *chrc_acquire_notify_call(struct l_dbus *,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct characterstic *chr = user_data;
	struct gatt_service *service = chr->service;
	struct l_dbus_message_iter dict;
	struct acquire_notify_options opts;
	struct l_dbus_message *reply;
	int fds[2];

	l_debug("AcquireNotify");

	if (!l_dbus_message_get_arguments(msg, "a{sv}", &dict))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!parse_acquire_notify_options(&dict, &opts))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (socketpair(AF_UNIX,
			SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
							0, fds) == -1)
		return dbus_error(msg, MESH_ERROR_FAILED,
						"Cannot create socket");

	service->notify_io = l_io_new(fds[0]);
	l_io_set_close_on_destroy(service->notify_io, true);
	l_io_set_disconnect_handler(service->notify_io, notify_disconnected,
								service, NULL);
	service->mtu = opts.mtu;
	l_debug("AcquireNotify: mtu=%u", opts.mtu);

	if (service->notify_acquired_cb)
		service->notify_acquired_cb(service->user_data);

	reply = l_dbus_message_new_method_return(msg);

	/* l_dbus_message_builder_append_basic() cannot append UNIX FDs */
	l_dbus_message_set_arguments(reply, "hq", fds[1], service->mtu);
	/*
	 * file descriptor for bluetoothd has just been dup'ed and must be
	 * closed here in order to get disconnect event after GATT notifications
	 * notifications have been disabled.
	 */
	close(fds[1]);

	return reply;
}

static bool chrc_uuid_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct characterstic *chr = user_data;

	const char *path = l_dbus_message_get_path(msg);
	const char *interface = l_dbus_message_get_interface(msg);
	const char *member = l_dbus_message_get_member(msg);

//	l_info("chrc_uuid_getter(path=%s, interface=%s, member=%s)", path, interface, member);
	return l_dbus_message_builder_append_basic(builder, 's', chr->uuid);
}

static bool chrc_service_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
//	l_info("chrc_service_getter");
	return l_dbus_message_builder_append_basic(builder, 'o',
						BLUEZ_MESH_SERVICE_PATH);
}

static bool chrc_notify_acquired_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct characterstic *chr = user_data;
	const struct gatt_service *service = chr->service;
	bool notifying = !!service->notify_io;

//	l_info("chrc_notify_acquired_getter");

	return l_dbus_message_builder_append_basic(builder, 'b', &notifying);
}

static bool chrc_flags_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct characterstic *chr = user_data;
	const char * const *flag = chr->flags;

//	l_info("chrc_flags_getter");

	l_dbus_message_builder_enter_array(builder, "s");

	while (*flag)
		l_dbus_message_builder_append_basic(builder, 's', *flag++);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void setup_gatt_chrc_interface(struct l_dbus_interface *iface)
{
	/* Note: "ReadValue" method is not supported. */
	l_dbus_interface_method(iface, "WriteValue" , 0, chrc_write_value_call,
							"", "aya{sv}",
							"value", "options");
	l_dbus_interface_method(iface, "AcquireNotify", 0,
							chrc_acquire_notify_call,
							"hq", "a{sv}",
							"fd", "mtu",
							"options");
	l_dbus_interface_property(iface, "UUID"   , 0, "s", chrc_uuid_getter,
									NULL);
	l_dbus_interface_property(iface, "Service", 0, "o", chrc_service_getter,
									NULL);
	l_dbus_interface_property(iface, "NotifyAcquired", 0, "b",
					chrc_notify_acquired_getter, NULL);
	l_dbus_interface_property(iface, "Flags"  , 0, "as", chrc_flags_getter,
									NULL);
}

static void register_app_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

//	l_info("register_app_setup");

	builder = l_dbus_message_builder_new(msg);

	/* Object path */
	l_dbus_message_builder_append_basic(builder, 'o', BLUEZ_MESH_GATT_PATH);

	/* Options (empty) */
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void register_app_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
//	l_info("register_app_reply");

	if (l_dbus_message_is_error(result)) {
		const char *error;

		l_dbus_message_get_error(result, &error, NULL);

		l_error("Registration of GATT application failed: %s", error);
	}
}

static bool gatt_svc_init(struct l_dbus *dbus, struct l_dbus_proxy *dbus_proxy,
					struct gatt_service *service)
{
	if (!l_dbus_register_interface(dbus, GATT_SERVICE_IFACE,
						setup_gatt_svc_interface,
						NULL, false)) {
		l_error("Cannot register " GATT_SERVICE_IFACE " interface");
		goto error_return;
	}

	if (!l_dbus_register_interface(dbus, GATT_CHRC_IFACE,
						setup_gatt_chrc_interface,
						NULL, false)) {
		l_error("Cannot register " GATT_CHRC_IFACE " interface");
		goto error_unregister_svc_iface;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_SERVICE_PATH,
						GATT_SERVICE_IFACE, service)) {
		l_error("Cannot add GATT service");
		goto error_unregister_chrc_iface;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_CHRC_DATA_IN_PATH,
						GATT_CHRC_IFACE,
						&service->chrc_data_in)) {
		l_error("Cannot add GATT Data In characteristic");
		goto error_remove_svc;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_CHRC_DATA_OUT_PATH,
						GATT_CHRC_IFACE,
						&service->chrc_data_out)) {
		l_error("Cannot add GATT Data Out characteristic");
		goto error_remove_data_in_chrc;
	}

	if (!l_dbus_object_manager_enable(dbus, BLUEZ_MESH_GATT_PATH)) {
		l_error("Cannot enable object manager");
		goto error_remove_data_out_chrc;
	}

	if (!l_dbus_proxy_method_call(dbus_proxy, "RegisterApplication",
						register_app_setup,
						register_app_reply,
						NULL, NULL)) {
		l_error("Cannot register GATT application");
		goto error_disable_object_manager;
	}

	return true;

error_disable_object_manager:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER);

error_remove_data_out_chrc:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_CHRC_DATA_OUT_PATH,
							GATT_CHRC_IFACE);

error_remove_data_in_chrc:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_CHRC_DATA_IN_PATH,
							GATT_CHRC_IFACE);

error_remove_svc:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_SERVICE_PATH,
							GATT_SERVICE_IFACE);

error_unregister_chrc_iface:
	l_dbus_unregister_interface(dbus, GATT_CHRC_IFACE);

error_unregister_svc_iface:
	l_dbus_unregister_interface(dbus, GATT_SERVICE_IFACE);

error_return:
	return false;
}

static void unregister_app_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

//	l_info("unregister_app_setup");

	builder = l_dbus_message_builder_new(msg);

	/* Object path */
	l_dbus_message_builder_append_basic(builder, 'o', BLUEZ_MESH_GATT_PATH);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void unregister_app_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct gatt_service *service = user_data;
	struct l_dbus *dbus = dbus_get_bus();
//	l_info("unregister_app_reply");

	if (l_dbus_message_is_error(result)) {
		const char *error;

		l_dbus_message_get_error(result, &error, NULL);

		l_error("Unregistration of GATT application failed: %s", error);
	}

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER);

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_CHRC_DATA_OUT_PATH,
							GATT_CHRC_IFACE);

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_CHRC_DATA_IN_PATH,
							GATT_CHRC_IFACE);

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_SERVICE_PATH,
							GATT_SERVICE_IFACE);

	l_dbus_unregister_interface(dbus, GATT_CHRC_IFACE);
	l_dbus_unregister_interface(dbus, GATT_SERVICE_IFACE);

	if (service->svc_deinit_cb)
		service->svc_deinit_cb(service);
}

static void gatt_svc_deinit(struct gatt_service *service, gatt_destroy_cb cb)
{
	service->svc_deinit_cb = cb;

	if (!l_dbus_proxy_method_call(service->dbus_proxy_gatt_mgr,
							"UnregisterApplication",
							unregister_app_setup,
							unregister_app_reply,
							service, NULL)) {
		l_error("Cannot unregister GATT application");
	}
}

static struct l_dbus_message *adv_release_call(struct l_dbus *,
						struct l_dbus_message *msg,
						void *user_data)
{
	l_debug("ADV Release");

	return NULL;
}

static bool adv_type_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
//	l_info("adv_type_getter");

	return l_dbus_message_builder_append_basic(builder, 's', "peripheral");
}

static bool adv_svc_uuids_getter(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct gatt_service *service = user_data;

//	l_info("adv_svc_uuids_getter");
	l_dbus_message_builder_enter_array(builder, "s");
	l_dbus_message_builder_append_basic(builder, 's', service->svc_uuid);
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool adv_svc_data_getter(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	const struct gatt_service *service = user_data;

//	l_info("adv_svc_data_getter");
	l_dbus_message_builder_enter_array(builder, "{sv}");

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', service->svc_uuid);
	l_dbus_message_builder_enter_variant(builder, "ay");

	if (!service->fill_adv_service_data_cb(service->user_data, builder))
		return false;

	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool adv_local_name_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	uint16_t max_interval_ms = 1000;
	uint16_t duration = 1 * max_interval_ms;

//	l_info("adv_local_name_getter");

	return l_dbus_message_builder_append_basic(builder, 's', "Test");
}

static bool adv_duration_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	uint16_t max_interval_ms = 1000;
	uint16_t duration = 1 * max_interval_ms;

//	l_info("adv_duration_getter");

	return l_dbus_message_builder_append_basic(builder, 'q', &duration);
}

static bool adv_timeout_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	uint16_t timeout = 1000;

//	l_info("adv_timeout_getter");

	return l_dbus_message_builder_append_basic(builder, 'q', &timeout);
}

static bool adv_min_interval_getter(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	uint32_t min_interval_ms = 1000;

//	l_info("adv_min_interval_getter");

	return l_dbus_message_builder_append_basic(builder, 'u',
							&min_interval_ms);
}

static bool adv_max_interval_getter(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	uint32_t max_interval_ms = 1000;

//	l_info("adv_max_interval_getter");

	return l_dbus_message_builder_append_basic(builder, 'u',
							&max_interval_ms);
}

static void setup_le_adv_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Release", 0, adv_release_call,
						"", "");
	l_dbus_interface_property(iface, "Type", 0, "s",
						adv_type_getter, NULL);
	l_dbus_interface_property(iface, "ServiceUUIDs", 0, "as",
						adv_svc_uuids_getter, NULL);
	l_dbus_interface_property(iface, "ServiceData", 0, "a{sv}",
						adv_svc_data_getter, NULL);
	l_dbus_interface_property(iface, "LocalName", 0, "s",
						adv_local_name_getter, NULL);
	l_dbus_interface_property(iface, "Duration", 0, "q",
						adv_duration_getter, NULL);
	l_dbus_interface_property(iface, "Timeout", 0, "q",
						adv_timeout_getter, NULL);
	l_dbus_interface_property(iface, "MinInterval", 0, "u",
						adv_min_interval_getter, NULL);
	l_dbus_interface_property(iface, "MaxInterval", 0, "u",
						adv_max_interval_getter, NULL);
}

static void register_adv_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

//	l_info("register_adv_setup");
	builder = l_dbus_message_builder_new(msg);

	/* Object path */
	l_dbus_message_builder_append_basic(builder, 'o',
						BLUEZ_MESH_GATT_ADV_PATH);

	/* Options (empty) */
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void register_adv_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
//	l_info("register_adv_reply");
	if (l_dbus_message_is_error(result)) {
		const char *error;

		l_dbus_message_get_error(result, &error, NULL);

		l_error("Registration of LE advertising failed: %s", error);
	}
}

static bool gatt_adv_init(struct l_dbus *dbus, struct l_dbus_proxy *dbus_proxy,
					struct gatt_service *service)
{
	if (!l_dbus_register_interface(dbus, LE_ADVERTISEMENT_IFACE,
							setup_le_adv_interface,
							NULL, false)) {
		l_error("Cannot register " LE_ADVERTISEMENT_IFACE " interface");
		goto error_return;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
						LE_ADVERTISEMENT_IFACE,
						service)) {
		l_error("Cannot add provisioner LE advertising service");
		goto error_unregister_le_adv_iface;
	}

	if (!l_dbus_object_manager_enable(dbus, BLUEZ_MESH_GATT_ADV_PATH)) {
		l_error("Cannot enable object manager");
		goto error_remove_le_adv;
	}

	/*
	 * org.freedesktop.DBus.Properties is required for building
	 * propertiesChanged signals
	 */
	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
					L_DBUS_INTERFACE_PROPERTIES, NULL)) {
		l_error("Cannot add LE advertising properties");
		goto error_disable_object_manager;
	}

	if (!l_dbus_proxy_method_call(dbus_proxy, "RegisterAdvertisement",
						register_adv_setup,
						register_adv_reply,
						NULL, NULL)) {
		l_error("Cannot register LE advertisement");
		goto error_remove_properties_iface;
	}

	return true;

error_remove_properties_iface:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
						L_DBUS_INTERFACE_PROPERTIES);

error_disable_object_manager:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER);

error_remove_le_adv:
	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
					LE_ADVERTISEMENT_IFACE);

error_unregister_le_adv_iface:
	l_dbus_unregister_interface(dbus, LE_ADVERTISEMENT_IFACE);

error_return:
	return false;
}

static void unregister_adv_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

//	l_info("unregister_adv_setup");

	builder = l_dbus_message_builder_new(msg);

	/* Object path */
	l_dbus_message_builder_append_basic(builder, 'o', BLUEZ_MESH_GATT_ADV_PATH);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void unregister_adv_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	struct gatt_service *service = user_data;
	struct l_dbus *dbus = dbus_get_bus();
//	l_info("unregister_adv_reply");

	if (l_dbus_message_is_error(result)) {
		const char *error;

		l_dbus_message_get_error(result, &error, NULL);

		l_error("Unregistration of LE advertisement failed: %s", error);
	}

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
						L_DBUS_INTERFACE_PROPERTIES);

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
					L_DBUS_INTERFACE_OBJECT_MANAGER);

	l_dbus_object_remove_interface(dbus, BLUEZ_MESH_GATT_ADV_PATH,
					LE_ADVERTISEMENT_IFACE);

	l_dbus_unregister_interface(dbus, LE_ADVERTISEMENT_IFACE);

	if (service->adv_deinit_cb)
		service->adv_deinit_cb(service);
}

static void gatt_adv_deinit(struct gatt_service *service, gatt_destroy_cb cb)
{
	service->adv_deinit_cb = cb;

	if (!l_dbus_proxy_method_call(service->dbus_proxy_le_adv_mgr,
							"UnregisterAdvertisement",
							unregister_adv_setup,
							unregister_adv_reply,
							service, NULL)) {
		l_error("Cannot unregister LE advertisement");
	}
}

static void dbus_proxy_added(struct l_dbus_proxy *dbus_proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(dbus_proxy);
	const char *path = l_dbus_proxy_get_path(dbus_proxy);
	struct gatt_service *service = user_data;

	l_debug("Proxy added: %s (%s)", interface, path);

	if (!strcmp(interface, GATT_MGR_IFACE)) {
		service->dbus_proxy_gatt_mgr = dbus_proxy;
		gatt_svc_init(dbus_get_bus(), dbus_proxy, service);
	} else if (!strcmp(interface, LE_ADVERTISING_MGR_IFACE)) {
		service->dbus_proxy_le_adv_mgr = dbus_proxy;
		gatt_adv_init(dbus_get_bus(), dbus_proxy, service);
	}
}

static void dbus_proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);
	struct gatt_service *service = user_data;

	l_debug("Proxy removed: %s (%s)", interface, path);

	if (!strcmp(interface, GATT_MGR_IFACE))
		service->dbus_proxy_gatt_mgr = NULL;
	else if (!strcmp(interface, LE_ADVERTISING_MGR_IFACE))
		service->dbus_proxy_le_adv_mgr = NULL;
}

struct gatt_service *
gatt_service_create(
		const char *svc_uuid,
		const char *chrc_data_in_uuid,
		const char *chrc_data_out_uuid,
		uint8_t max_pdu_len,
		gatt_service_notify_acquired_cb notify_acquired_cb,
		gatt_service_notify_stopped_cb notify_stopped_cb,
		gatt_service_rx_cb rx_cb,
		gatt_service_tx_cmplt_cb tx_cmplt_cb,
		gatt_service_fill_adv_service_data_cb fill_adv_service_data_cb,
		void *user_data)
{
	static const char *flags_data_in[] = {"write-without-response", NULL};
	static const char *flags_data_out[] = {"notify", NULL};

	/* Only one GATT service may exist at a time (MshPRT_v1.1, chapter 7) */
	if (gatt_service)
		return NULL;

	gatt_service = l_new(struct gatt_service, 1);
	gatt_service->svc_uuid = svc_uuid;
	gatt_service->max_pdu_len = max_pdu_len;
	gatt_service->sar = l_malloc(max_pdu_len);

	gatt_service->notify_acquired_cb = notify_acquired_cb;
	gatt_service->notify_stopped_cb = notify_stopped_cb;
	gatt_service->rx_cb = rx_cb;
	gatt_service->tx_cmplt_cb = tx_cmplt_cb;
	gatt_service->fill_adv_service_data_cb = fill_adv_service_data_cb;
	gatt_service->user_data = user_data;
	gatt_service->mtu = GATT_MTU;

	gatt_service->chrc_data_in.uuid = chrc_data_in_uuid;
	gatt_service->chrc_data_in.flags = flags_data_in;
	gatt_service->chrc_data_in.service = gatt_service;

	gatt_service->chrc_data_out.uuid = chrc_data_out_uuid;
	gatt_service->chrc_data_out.flags = flags_data_out;
	gatt_service->chrc_data_out.service = gatt_service;

	gatt_service->dbus_client = l_dbus_client_new(dbus_get_bus(),
						"org.bluez", "/org/bluez");

	l_dbus_client_set_proxy_handlers(gatt_service->dbus_client,
						dbus_proxy_added,
						dbus_proxy_removed,
						NULL,
						gatt_service, NULL);

	return gatt_service;
}

static void gatt_svc_destroy(void *user_data)
{
	struct gatt_service *service = user_data;
	gatt_destroy_cb destroy_cb;
	void *destroy_data;

	if (!gatt_service || gatt_service != service)
		return;

	destroy_cb = service->destroy_cb;
	destroy_data = service->destroy_data;

	l_dbus_client_destroy(service->dbus_client);
	l_io_destroy(service->notify_io);
	l_free(service->sar);
	l_free(service);
	gatt_service = NULL;

	if (destroy_cb)
		destroy_cb(destroy_data);
}

static void gatt_svc_deinit_finished(void *user_data)
{
	struct gatt_service *service = user_data;

	if (!gatt_service || gatt_service != service)
		return;

	/* l_dbus_client_destroy() must not be called from dbus context */
	l_idle_oneshot(gatt_svc_destroy, service, NULL);
}

static void gatt_adv_deinit_finished(void *user_data)
{
	struct gatt_service *service = user_data;

	if (!gatt_service || gatt_service != service)
		return;

	gatt_svc_deinit(service, gatt_svc_deinit_finished);
}

void gatt_service_destroy(struct gatt_service *service,
				gatt_destroy_cb destroy_cb, void *user_data)
{
	if (!gatt_service || gatt_service != service)
		return;

	/* avoid recursion */
	l_io_set_disconnect_handler(service->notify_io, NULL, NULL, NULL);

	service->destroy_cb = destroy_cb;
	service->destroy_data = user_data;
	gatt_adv_deinit(service, gatt_adv_deinit_finished);
}

void gatt_service_adv_updated(struct gatt_service *service)
{
	if (!gatt_service || gatt_service != service)
		return;

	l_dbus_property_changed(dbus_get_bus(), BLUEZ_MESH_GATT_ADV_PATH,
					LE_ADVERTISEMENT_IFACE, "ServiceData");
}
