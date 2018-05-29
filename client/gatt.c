/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>

#include <glib.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/io.h"
#include "src/shared/shell.h"
#include "gdbus/gdbus.h"
#include "gatt.h"

#define APP_PATH "/org/bluez/app"
#define PROFILE_INTERFACE "org.bluez.GattProfile1"
#define SERVICE_INTERFACE "org.bluez.GattService1"
#define CHRC_INTERFACE "org.bluez.GattCharacteristic1"
#define DESC_INTERFACE "org.bluez.GattDescriptor1"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define MAX_ATTR_VAL_LEN	512

struct desc {
	struct chrc *chrc;
	char *path;
	char *uuid;
	char **flags;
	int value_len;
	unsigned int max_val_len;
	uint8_t *value;
};

struct chrc {
	struct service *service;
	char *path;
	char *uuid;
	char **flags;
	bool notifying;
	GList *descs;
	int value_len;
	unsigned int max_val_len;
	uint8_t *value;
	uint16_t mtu;
	struct io *write_io;
	struct io *notify_io;
	bool authorization_req;
};

struct service {
	DBusConnection *conn;
	char *path;
	char *uuid;
	bool primary;
	GList *chrcs;
	GList *inc;
};

static GList *local_services;
static GList *services;
static GList *characteristics;
static GList *descriptors;
static GList *managers;
static GList *uuids;
static DBusMessage *pending_message = NULL;

struct pipe_io {
	GDBusProxy *proxy;
	struct io *io;
	uint16_t mtu;
};

static struct pipe_io write_io;
static struct pipe_io notify_io;

static void print_service(struct service *service, const char *description)
{
	const char *text;

	text = bt_uuidstr_to_str(service->uuid);
	if (!text)
		bt_shell_printf("%s%s%s%s Service\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					service->primary ? "Primary" :
					"Secondary",
					service->path, service->uuid);
	else
		bt_shell_printf("%s%s%s%s Service\n\t%s\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					service->primary ? "Primary" :
					"Secondary",
					service->path, service->uuid, text);
}

static void print_inc_service(struct service *service, const char *description)
{
	const char *text;

	text = bt_uuidstr_to_str(service->uuid);
	if (!text)
		bt_shell_printf("%s%s%s%s Included Service\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					service->primary ? "Primary" :
					"Secondary",
					service->path, service->uuid);
	else
		bt_shell_printf("%s%s%s%s Included Service\n\t%s\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					service->primary ? "Primary" :
					"Secondary",
					service->path, service->uuid, text);
}

static void print_service_proxy(GDBusProxy *proxy, const char *description)
{
	struct service service;
	DBusMessageIter iter;
	const char *uuid;
	dbus_bool_t primary;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (g_dbus_proxy_get_property(proxy, "Primary", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &primary);

	service.path = (char *) g_dbus_proxy_get_path(proxy);
	service.uuid = (char *) uuid;
	service.primary = primary;

	print_service(&service, description);
}

void gatt_add_service(GDBusProxy *proxy)
{
	services = g_list_append(services, proxy);

	print_service_proxy(proxy, COLORED_NEW);
}

void gatt_remove_service(GDBusProxy *proxy)
{
	GList *l;

	l = g_list_find(services, proxy);
	if (!l)
		return;

	services = g_list_delete_link(services, l);

	print_service_proxy(proxy, COLORED_DEL);
}

static void print_chrc(struct chrc *chrc, const char *description)
{
	const char *text;

	text = bt_uuidstr_to_str(chrc->uuid);
	if (!text)
		bt_shell_printf("%s%s%sCharacteristic\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					chrc->path, chrc->uuid);
	else
		bt_shell_printf("%s%s%sCharacteristic\n\t%s\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					chrc->path, chrc->uuid, text);
}

static void print_characteristic(GDBusProxy *proxy, const char *description)
{
	struct chrc chrc;
	DBusMessageIter iter;
	const char *uuid;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	chrc.path = (char *) g_dbus_proxy_get_path(proxy);
	chrc.uuid = (char *) uuid;

	print_chrc(&chrc, description);
}

static gboolean chrc_is_child(GDBusProxy *characteristic)
{
	DBusMessageIter iter;
	const char *service;

	if (!g_dbus_proxy_get_property(characteristic, "Service", &iter))
		return FALSE;

	dbus_message_iter_get_basic(&iter, &service);

	return g_dbus_proxy_lookup(services, NULL, service,
					"org.bluez.GattService1") != NULL;
}

void gatt_add_characteristic(GDBusProxy *proxy)
{
	if (!chrc_is_child(proxy))
		return;

	characteristics = g_list_append(characteristics, proxy);

	print_characteristic(proxy, COLORED_NEW);
}

static void notify_io_destroy(void)
{
	io_destroy(notify_io.io);
	memset(&notify_io, 0, sizeof(notify_io));
}

static void write_io_destroy(void)
{
	io_destroy(write_io.io);
	memset(&write_io, 0, sizeof(write_io));
}

void gatt_remove_characteristic(GDBusProxy *proxy)
{
	GList *l;

	l = g_list_find(characteristics, proxy);
	if (!l)
		return;

	characteristics = g_list_delete_link(characteristics, l);

	print_characteristic(proxy, COLORED_DEL);

	if (write_io.proxy == proxy)
		write_io_destroy();
	else if (notify_io.proxy == proxy)
		notify_io_destroy();
}

static void print_desc(struct desc *desc, const char *description)
{
	const char *text;

	text = bt_uuidstr_to_str(desc->uuid);
	if (!text)
		bt_shell_printf("%s%s%sDescriptor\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					desc->path, desc->uuid);
	else
		bt_shell_printf("%s%s%sDescriptor\n\t%s\n\t%s\n\t%s\n",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					desc->path, desc->uuid, text);
}

static void print_descriptor(GDBusProxy *proxy, const char *description)
{
	struct desc desc;
	DBusMessageIter iter;
	const char *uuid;

	if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	desc.path = (char *) g_dbus_proxy_get_path(proxy);
	desc.uuid = (char *) uuid;

	print_desc(&desc, description);
}

static gboolean descriptor_is_child(GDBusProxy *characteristic)
{
	GList *l;
	DBusMessageIter iter;
	const char *service, *path;

	if (!g_dbus_proxy_get_property(characteristic, "Characteristic", &iter))
		return FALSE;

	dbus_message_iter_get_basic(&iter, &service);

	for (l = characteristics; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;

		path = g_dbus_proxy_get_path(proxy);

		if (!strcmp(path, service))
			return TRUE;
	}

	return FALSE;
}

void gatt_add_descriptor(GDBusProxy *proxy)
{
	if (!descriptor_is_child(proxy))
		return;

	descriptors = g_list_append(descriptors, proxy);

	print_descriptor(proxy, COLORED_NEW);
}

void gatt_remove_descriptor(GDBusProxy *proxy)
{
	GList *l;

	l = g_list_find(descriptors, proxy);
	if (!l)
		return;

	descriptors = g_list_delete_link(descriptors, l);

	print_descriptor(proxy, COLORED_DEL);
}

static void list_attributes(const char *path, GList *source)
{
	GList *l;

	for (l = source; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;
		const char *proxy_path;

		proxy_path = g_dbus_proxy_get_path(proxy);

		if (!g_str_has_prefix(proxy_path, path))
			continue;

		if (source == services) {
			print_service_proxy(proxy, NULL);
			list_attributes(proxy_path, characteristics);
		} else if (source == characteristics) {
			print_characteristic(proxy, NULL);
			list_attributes(proxy_path, descriptors);
		} else if (source == descriptors)
			print_descriptor(proxy, NULL);
	}
}

void gatt_list_attributes(const char *path)
{
	list_attributes(path, services);
	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static GDBusProxy *select_attribute(const char *path)
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(services, NULL, path,
					"org.bluez.GattService1");
	if (proxy)
		return proxy;

	proxy = g_dbus_proxy_lookup(characteristics, NULL, path,
					"org.bluez.GattCharacteristic1");
	if (proxy)
		return proxy;

	return g_dbus_proxy_lookup(descriptors, NULL, path,
					"org.bluez.GattDescriptor1");
}

static GDBusProxy *select_proxy_by_uuid(GDBusProxy *parent, const char *uuid,
					GList *source)
{
	GList *l;
	const char *value;
	DBusMessageIter iter;

	for (l = source; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;

		if (parent && !g_str_has_prefix(g_dbus_proxy_get_path(proxy),
						g_dbus_proxy_get_path(parent)))
			continue;

		if (g_dbus_proxy_get_property(proxy, "UUID", &iter) == FALSE)
			continue;

		dbus_message_iter_get_basic(&iter, &value);

		if (strcasecmp(uuid, value) == 0)
			return proxy;
	}

	return NULL;
}

static GDBusProxy *select_attribute_by_uuid(GDBusProxy *parent,
							const char *uuid)
{
	GDBusProxy *proxy;

	proxy = select_proxy_by_uuid(parent, uuid, services);
	if (proxy)
		return proxy;

	proxy = select_proxy_by_uuid(parent, uuid, characteristics);
	if (proxy)
		return proxy;

	return select_proxy_by_uuid(parent, uuid, descriptors);
}

GDBusProxy *gatt_select_attribute(GDBusProxy *parent, const char *arg)
{
	if (arg[0] == '/')
		return select_attribute(arg);

	if (parent) {
		GDBusProxy *proxy = select_attribute_by_uuid(parent, arg);
		if (proxy)
			return proxy;
	}

	return select_attribute_by_uuid(parent, arg);
}

static char *attribute_generator(const char *text, int state, GList *source)
{
	static int index;

	if (!state) {
		index = 0;
	}

	return g_dbus_proxy_path_lookup(source, &index, text);
}

char *gatt_attribute_generator(const char *text, int state)
{
	static GList *list = NULL;

	if (!state) {
		GList *list1;

		if (list) {
			g_list_free(list);
			list = NULL;
		}

		list1 = g_list_copy(characteristics);
		list1 = g_list_concat(list1, g_list_copy(descriptors));

		list = g_list_copy(services);
		list = g_list_concat(list, list1);
	}

	return attribute_generator(text, state, list);
}

static void read_reply(DBusMessage *message, void *user_data)
{
	DBusError error;
	DBusMessageIter iter, array;
	uint8_t *value;
	int len;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to read: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		bt_shell_printf("Invalid response to read\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &len);

	if (len < 0) {
		bt_shell_printf("Unable to parse value\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_hexdump(value, len);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void read_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	uint16_t *offset = user_data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	g_dbus_dict_append_entry(&dict, "offset", DBUS_TYPE_UINT16, offset);

	dbus_message_iter_close_container(iter, &dict);
}

static void read_attribute(GDBusProxy *proxy, uint16_t offset)
{
	if (g_dbus_proxy_method_call(proxy, "ReadValue", read_setup, read_reply,
						&offset, NULL) == FALSE) {
		bt_shell_printf("Failed to read\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to read %s\n", g_dbus_proxy_get_path(proxy));
}

void gatt_read_attribute(GDBusProxy *proxy, int argc, char *argv[])
{
	const char *iface;
	uint16_t offset = 0;

	iface = g_dbus_proxy_get_interface(proxy);
	if (!strcmp(iface, "org.bluez.GattCharacteristic1") ||
				!strcmp(iface, "org.bluez.GattDescriptor1")) {

		if (argc == 2)
			offset = atoi(argv[1]);

		read_attribute(proxy, offset);
		return;
	}

	bt_shell_printf("Unable to read attribute %s\n",
						g_dbus_proxy_get_path(proxy));
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void write_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to write: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

struct write_attribute_data {
	struct iovec *iov;
	uint16_t offset;
};

static void write_setup(DBusMessageIter *iter, void *user_data)
{
	struct write_attribute_data *wd = user_data;
	DBusMessageIter array, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&wd->iov->iov_base,
						wd->iov->iov_len);
	dbus_message_iter_close_container(iter, &array);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	g_dbus_dict_append_entry(&dict, "offset", DBUS_TYPE_UINT16,
								&wd->offset);

	dbus_message_iter_close_container(iter, &dict);
}

static void write_attribute(GDBusProxy *proxy, char *val_str, uint16_t offset)
{
	struct iovec iov;
	struct write_attribute_data wd;
	uint8_t value[MAX_ATTR_VAL_LEN];
	char *entry;
	unsigned int i;

	for (i = 0; (entry = strsep(&val_str, " \t")) != NULL; i++) {
		long int val;
		char *endptr = NULL;

		if (*entry == '\0')
			continue;

		if (i >= G_N_ELEMENTS(value)) {
			bt_shell_printf("Too much data\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		val = strtol(entry, &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Invalid value at index %d\n", i);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		value[i] = val;
	}

	iov.iov_base = value;
	iov.iov_len = i;

	/* Write using the fd if it has been acquired and fit the MTU */
	if (proxy == write_io.proxy && (write_io.io && write_io.mtu >= i)) {
		bt_shell_printf("Attempting to write fd %d\n",
						io_get_fd(write_io.io));
		if (io_send(write_io.io, &iov, 1) < 0) {
			bt_shell_printf("Failed to write: %s", strerror(errno));
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
		return;
	}

	wd.iov = &iov;
	wd.offset = offset;

	if (g_dbus_proxy_method_call(proxy, "WriteValue", write_setup,
					write_reply, &wd, NULL) == FALSE) {
		bt_shell_printf("Failed to write\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to write %s\n",
					g_dbus_proxy_get_path(proxy));
}

void gatt_write_attribute(GDBusProxy *proxy, int argc, char *argv[])
{
	const char *iface;
	uint16_t offset = 0;

	iface = g_dbus_proxy_get_interface(proxy);
	if (!strcmp(iface, "org.bluez.GattCharacteristic1") ||
				!strcmp(iface, "org.bluez.GattDescriptor1")) {

		if (argc > 2)
			offset = atoi(argv[2]);

		write_attribute(proxy, argv[1], offset);
		return;
	}

	bt_shell_printf("Unable to write attribute %s\n",
						g_dbus_proxy_get_path(proxy));

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static bool pipe_read(struct io *io, void *user_data)
{
	struct chrc *chrc = user_data;
	uint8_t buf[MAX_ATTR_VAL_LEN];
	int fd = io_get_fd(io);
	ssize_t bytes_read;

	if (io != notify_io.io && !chrc)
		return true;

	bytes_read = read(fd, buf, sizeof(buf));
	if (bytes_read < 0)
		return false;

	if (chrc)
		bt_shell_printf("[" COLORED_CHG "] Attribute %s written:\n",
							chrc->path);
	else
		bt_shell_printf("[" COLORED_CHG "] %s Notification:\n",
				g_dbus_proxy_get_path(notify_io.proxy));

	bt_shell_hexdump(buf, bytes_read);

	return true;
}

static bool pipe_hup(struct io *io, void *user_data)
{
	struct chrc *chrc = user_data;

	if (chrc) {
		bt_shell_printf("Attribute %s %s pipe closed\n", chrc->path,
				io == chrc->write_io ? "Write" : "Notify");

		if (io == chrc->write_io) {
			io_destroy(chrc->write_io);
			chrc->write_io = NULL;
		} else {
			io_destroy(chrc->notify_io);
			chrc->notify_io = NULL;
		}

		return false;
	}

	bt_shell_printf("%s closed\n", io == notify_io.io ? "Notify" : "Write");

	if (io == notify_io.io)
		notify_io_destroy();
	else
		write_io_destroy();

	return false;
}

static struct io *pipe_io_new(int fd, void *user_data)
{
	struct io *io;

	io = io_new(fd);

	io_set_close_on_destroy(io, true);

	io_set_read_handler(io, pipe_read, user_data, NULL);

	io_set_disconnect_handler(io, pipe_hup, user_data, NULL);

	return io;
}

static void acquire_write_reply(DBusMessage *message, void *user_data)
{
	DBusError error;
	int fd;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to acquire write: %s\n", error.name);
		dbus_error_free(&error);
		write_io.proxy = NULL;
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (write_io.io)
		write_io_destroy();

	if ((dbus_message_get_args(message, NULL, DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_UINT16, &write_io.mtu,
					DBUS_TYPE_INVALID) == false)) {
		bt_shell_printf("Invalid AcquireWrite response\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("AcquireWrite success: fd %d MTU %u\n", fd,
								write_io.mtu);

	write_io.io = pipe_io_new(fd, NULL);
	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void acquire_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dbus_message_iter_close_container(iter, &dict);
}

void gatt_acquire_write(GDBusProxy *proxy, const char *arg)
{
	const char *iface;

	iface = g_dbus_proxy_get_interface(proxy);
	if (strcmp(iface, "org.bluez.GattCharacteristic1")) {
		bt_shell_printf("Unable to acquire write: %s not a"
				" characteristic\n",
				g_dbus_proxy_get_path(proxy));
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "AcquireWrite", acquire_setup,
				acquire_write_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to AcquireWrite\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	write_io.proxy = proxy;
}

void gatt_release_write(GDBusProxy *proxy, const char *arg)
{
	if (proxy != write_io.proxy || !write_io.io) {
		bt_shell_printf("Write not acquired\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	write_io_destroy();

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void acquire_notify_reply(DBusMessage *message, void *user_data)
{
	DBusError error;
	int fd;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to acquire notify: %s\n", error.name);
		dbus_error_free(&error);
		write_io.proxy = NULL;
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (notify_io.io) {
		io_destroy(notify_io.io);
		notify_io.io = NULL;
	}

	notify_io.mtu = 0;

	if ((dbus_message_get_args(message, NULL, DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_UINT16, &notify_io.mtu,
					DBUS_TYPE_INVALID) == false)) {
		bt_shell_printf("Invalid AcquireNotify response\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("AcquireNotify success: fd %d MTU %u\n", fd,
								notify_io.mtu);

	notify_io.io = pipe_io_new(fd, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void gatt_acquire_notify(GDBusProxy *proxy, const char *arg)
{
	const char *iface;

	iface = g_dbus_proxy_get_interface(proxy);
	if (strcmp(iface, "org.bluez.GattCharacteristic1")) {
		bt_shell_printf("Unable to acquire notify: %s not a"
				" characteristic\n",
				g_dbus_proxy_get_path(proxy));
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "AcquireNotify", acquire_setup,
				acquire_notify_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to AcquireNotify\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	notify_io.proxy = proxy;
}

void gatt_release_notify(GDBusProxy *proxy, const char *arg)
{
	if (proxy != notify_io.proxy || !notify_io.io) {
		bt_shell_printf("Notify not acquired\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	notify_io_destroy();

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void notify_reply(DBusMessage *message, void *user_data)
{
	bool enable = GPOINTER_TO_UINT(user_data);
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to %s notify: %s\n",
				enable ? "start" : "stop", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Notify %s\n", enable == TRUE ? "started" : "stopped");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void notify_attribute(GDBusProxy *proxy, bool enable)
{
	const char *method;

	if (enable == TRUE)
		method = "StartNotify";
	else
		method = "StopNotify";

	if (g_dbus_proxy_method_call(proxy, method, NULL, notify_reply,
				GUINT_TO_POINTER(enable), NULL) == FALSE) {
		bt_shell_printf("Failed to %s notify\n",
				enable ? "start" : "stop");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void gatt_notify_attribute(GDBusProxy *proxy, bool enable)
{
	const char *iface;

	iface = g_dbus_proxy_get_interface(proxy);
	if (!strcmp(iface, "org.bluez.GattCharacteristic1")) {
		notify_attribute(proxy, enable);
		return;
	}

	bt_shell_printf("Unable to notify attribute %s\n",
						g_dbus_proxy_get_path(proxy));

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void register_app_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter opt;
	const char *path = "/";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&opt);
	dbus_message_iter_close_container(iter, &opt);

}

static void register_app_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to register application: %s\n",
				error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Application registered\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void gatt_add_manager(GDBusProxy *proxy)
{
	managers = g_list_append(managers, proxy);
}

void gatt_remove_manager(GDBusProxy *proxy)
{
	managers = g_list_remove(managers, proxy);
}

static int match_proxy(const void *a, const void *b)
{
	GDBusProxy *proxy1 = (void *) a;
	GDBusProxy *proxy2 = (void *) b;

	return strcmp(g_dbus_proxy_get_path(proxy1),
						g_dbus_proxy_get_path(proxy2));
}

static DBusMessage *release_profile(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	g_dbus_unregister_interface(conn, APP_PATH, PROFILE_INTERFACE);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, release_profile) },
	{ }
};

static gboolean get_uuids(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter entry;
	GList *uuid;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &entry);

	for (uuid = uuids; uuid; uuid = g_list_next(uuid->next))
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&uuid->data);

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static const GDBusPropertyTable properties[] = {
	{ "UUIDs", "as", get_uuids },
	{ }
};

void gatt_register_app(DBusConnection *conn, GDBusProxy *proxy,
					int argc, char *argv[])
{
	GList *l;
	int i;

	l = g_list_find_custom(managers, proxy, match_proxy);
	if (!l) {
		bt_shell_printf("Unable to find GattManager proxy\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	for (i = 0; i < argc; i++)
		uuids = g_list_append(uuids, g_strdup(argv[i]));

	if (uuids) {
		if (g_dbus_register_interface(conn, APP_PATH,
						PROFILE_INTERFACE, methods,
						NULL, properties, NULL,
						NULL) == FALSE) {
			bt_shell_printf("Failed to register application"
					" object\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	if (g_dbus_proxy_method_call(l->data, "RegisterApplication",
						register_app_setup,
						register_app_reply, NULL,
						NULL) == FALSE) {
		bt_shell_printf("Failed register application\n");
		g_dbus_unregister_interface(conn, APP_PATH, PROFILE_INTERFACE);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void unregister_app_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to unregister application: %s\n",
				error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Application unregistered\n");

	if (!uuids)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	g_list_free_full(uuids, g_free);
	uuids = NULL;

	g_dbus_unregister_interface(conn, APP_PATH, PROFILE_INTERFACE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void unregister_app_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = "/";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

void gatt_unregister_app(DBusConnection *conn, GDBusProxy *proxy)
{
	GList *l;

	l = g_list_find_custom(managers, proxy, match_proxy);
	if (!l) {
		bt_shell_printf("Unable to find GattManager proxy\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(l->data, "UnregisterApplication",
						unregister_app_setup,
						unregister_app_reply, conn,
						NULL) == FALSE) {
		bt_shell_printf("Failed unregister profile\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void desc_free(void *data)
{
	struct desc *desc = data;

	g_free(desc->path);
	g_free(desc->uuid);
	g_strfreev(desc->flags);
	g_free(desc->value);
	g_free(desc);
}

static void desc_unregister(void *data)
{
	struct desc *desc = data;

	print_desc(desc, COLORED_DEL);

	g_dbus_unregister_interface(desc->chrc->service->conn, desc->path,
						DESC_INTERFACE);
}

static void chrc_free(void *data)
{
	struct chrc *chrc = data;

	g_list_free_full(chrc->descs, desc_unregister);
	g_free(chrc->path);
	g_free(chrc->uuid);
	g_strfreev(chrc->flags);
	g_free(chrc->value);
	g_free(chrc);
}

static void chrc_unregister(void *data)
{
	struct chrc *chrc = data;

	print_chrc(chrc, COLORED_DEL);

	g_dbus_unregister_interface(chrc->service->conn, chrc->path,
						CHRC_INTERFACE);
}

static void inc_unregister(void *data)
{
	char *path = data;

	g_free(path);
}

static void service_free(void *data)
{
	struct service *service = data;

	g_list_free_full(service->chrcs, chrc_unregister);
	g_list_free_full(service->inc, inc_unregister);
	g_free(service->path);
	g_free(service->uuid);
	g_free(service);
}

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &service->uuid);

	return TRUE;
}

static gboolean service_get_primary(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	dbus_bool_t primary;

	primary = service->primary ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &primary);

	return TRUE;
}


static gboolean service_get_includes(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter array;
	struct service *service = data;
	char *inc  = NULL;
	GList *l;

	if (service->inc) {
		for (l =  service->inc ; l; l = g_list_next(l)) {

			inc = l->data;
			dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array);

			dbus_message_iter_append_basic(&array,
				DBUS_TYPE_OBJECT_PATH, &inc);

		}

		dbus_message_iter_close_container(iter, &array);

		return TRUE;
	}

	return FALSE;

}

static gboolean service_exist_includes(const GDBusPropertyTable *property,
							void *data)
{
	struct service *service = data;

	if (service->inc)
		return TRUE;
	else
		return FALSE;

}


static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_get_uuid },
	{ "Primary", "b", service_get_primary },
	{ "Includes", "ao", service_get_includes,
		NULL,	service_exist_includes },
	{ }
};

static void service_set_primary(const char *input, void *user_data)
{
	struct service *service = user_data;

	if (!strcmp(input, "yes"))
		service->primary = true;
	else if (!strcmp(input, "no")) {
		service->primary = false;
	} else {
		bt_shell_printf("Invalid option: %s\n", input);
		local_services = g_list_remove(local_services, service);
		print_service(service, COLORED_DEL);
		g_dbus_unregister_interface(service->conn, service->path,
						SERVICE_INTERFACE);
	}
}

void gatt_register_service(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct service *service;
	bool primary = true;

	service = g_new0(struct service, 1);
	service->conn = conn;
	service->uuid = g_strdup(argv[1]);
	service->path = g_strdup_printf("%s/service%p", APP_PATH, service);
	service->primary = primary;

	if (g_dbus_register_interface(conn, service->path,
					SERVICE_INTERFACE, NULL, NULL,
					service_properties, service,
					service_free) == FALSE) {
		bt_shell_printf("Failed to register service object\n");
		service_free(service);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	print_service(service, COLORED_NEW);

	local_services = g_list_append(local_services, service);

	bt_shell_prompt_input(service->path, "Primary (yes/no):",
		 service_set_primary, service);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static struct service *service_find(const char *pattern)
{
	GList *l;

	for (l = local_services; l; l = g_list_next(l)) {
		struct service *service = l->data;

		/* match object path */
		if (!strcmp(service->path, pattern))
			return service;

		/* match UUID */
		if (!strcmp(service->uuid, pattern))
			return service;
	}

	return NULL;
}

void gatt_unregister_service(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct service *service;

	service = service_find(argv[1]);
	if (!service) {
		bt_shell_printf("Failed to unregister service object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	local_services = g_list_remove(local_services, service);

	print_service(service, COLORED_DEL);

	g_dbus_unregister_interface(service->conn, service->path,
						SERVICE_INTERFACE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static char *inc_find(struct service  *serv, char *path)
{
	GList *lc;

	for (lc = serv->inc; lc; lc =  g_list_next(lc)) {
		char *incp = lc->data;
		/* match object path */
		if (!strcmp(incp, path))
			return incp;
	}

	return NULL;
}

void gatt_register_include(DBusConnection *conn, GDBusProxy *proxy,
					int argc, char *argv[])
{
	struct service *service, *inc_service;
	char *inc_path;

	if (!local_services) {
		bt_shell_printf("No service registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service = g_list_last(local_services)->data;


	inc_service = service_find(argv[1]);
	if (!inc_service) {
		bt_shell_printf("Failed to find  service object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	inc_path = g_strdup(service->path);

	inc_service->inc = g_list_append(inc_service->inc, inc_path);

	print_service(inc_service, COLORED_NEW);
	print_inc_service(service, COLORED_NEW);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

void gatt_unregister_include(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct service *ser_inc, *service;
	char *path = NULL;

	service = service_find(argv[1]);
	if (!service) {
		bt_shell_printf("Failed to unregister include service"
							" object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ser_inc = service_find(argv[2]);
	if (!ser_inc) {
		bt_shell_printf("Failed to find include service object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	path = inc_find(service, ser_inc->path);
	if (path) {
		service->inc = g_list_remove(service->inc, path);
		inc_unregister(path);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static gboolean chrc_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &chrc->uuid);

	return TRUE;
}

static gboolean chrc_get_service(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
						&chrc->service->path);

	return TRUE;
}

static gboolean chrc_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&chrc->value, chrc->value_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean chrc_get_notifying(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;
	dbus_bool_t value;

	value = chrc->notifying ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean chrc_get_flags(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;
	int i;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; chrc->flags[i]; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&chrc->flags[i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean chrc_get_write_acquired(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;
	dbus_bool_t value;

	value = chrc->write_io ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean chrc_write_acquired_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct chrc *chrc = data;
	int i;

	for (i = 0; chrc->flags[i]; i++) {
		if (!strcmp("write-without-response", chrc->flags[i]))
			return TRUE;
	}

	return FALSE;
}

static gboolean chrc_get_notify_acquired(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct chrc *chrc = data;
	dbus_bool_t value;

	value = chrc->notify_io ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean chrc_notify_acquired_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct chrc *chrc = data;
	int i;

	for (i = 0; chrc->flags[i]; i++) {
		if (!strcmp("notify", chrc->flags[i]))
			return TRUE;
	}

	return FALSE;
}

static const GDBusPropertyTable chrc_properties[] = {
	{ "UUID", "s", chrc_get_uuid, NULL, NULL },
	{ "Service", "o", chrc_get_service, NULL, NULL },
	{ "Value", "ay", chrc_get_value, NULL, NULL },
	{ "Notifying", "b", chrc_get_notifying, NULL, NULL },
	{ "Flags", "as", chrc_get_flags, NULL, NULL },
	{ "WriteAcquired", "b", chrc_get_write_acquired, NULL,
					chrc_write_acquired_exists },
	{ "NotifyAcquired", "b", chrc_get_notify_acquired, NULL,
					chrc_notify_acquired_exists },
	{ }
};

static const char *path_to_address(const char *path)
{
	GDBusProxy *proxy;
	DBusMessageIter iter;
	const char *address = path;

	proxy = bt_shell_get_env(path);

	if (g_dbus_proxy_get_property(proxy, "Address", &iter))
		dbus_message_iter_get_basic(&iter, &address);

	return address;
}

static int parse_options(DBusMessageIter *iter, uint16_t *offset, uint16_t *mtu,
						char **device, char **link,
						bool *prep_authorize)
{
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);
		if (strcasecmp(key, "offset") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			if (offset)
				dbus_message_iter_get_basic(&value, offset);
		} else if (strcasecmp(key, "MTU") == 0) {
			if (var != DBUS_TYPE_UINT16)
				return -EINVAL;
			if (mtu)
				dbus_message_iter_get_basic(&value, mtu);
		} else if (strcasecmp(key, "device") == 0) {
			if (var != DBUS_TYPE_OBJECT_PATH)
				return -EINVAL;
			if (device)
				dbus_message_iter_get_basic(&value, device);
		} else if (strcasecmp(key, "link") == 0) {
			if (var != DBUS_TYPE_STRING)
				return -EINVAL;
			if (link)
				dbus_message_iter_get_basic(&value, link);
		} else if (strcasecmp(key, "prepare-authorize") == 0) {
			if (var != DBUS_TYPE_BOOLEAN)
				return -EINVAL;
			if (prep_authorize)
				dbus_message_iter_get_basic(&value,
								prep_authorize);
		}

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static DBusMessage *read_value(DBusMessage *msg, uint8_t *value,
						uint16_t value_len)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;

	reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&value, value_len);
	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

struct authorize_attribute_data {
	DBusConnection *conn;
	void *attribute;
	uint16_t offset;
};

static void authorize_read_response(const char *input, void *user_data)
{
	struct authorize_attribute_data *aad = user_data;
	struct chrc *chrc = aad->attribute;
	DBusMessage *reply;
	char *err;

	if (!strcmp(input, "no")) {
		err = "org.bluez.Error.NotAuthorized";

		goto error;
	}

	if (aad->offset > chrc->value_len) {
		err = "org.bluez.Error.InvalidOffset";

		goto error;
	}

	reply = read_value(pending_message, &chrc->value[aad->offset],
						chrc->value_len - aad->offset);

	g_dbus_send_message(aad->conn, reply);

	g_free(aad);

	return;

error:
	g_dbus_send_error(aad->conn, pending_message, err, NULL);
	g_free(aad);
}

static bool is_device_trusted(const char *path)
{
	GDBusProxy *proxy;
	DBusMessageIter iter;
	bool trusted;

	proxy = bt_shell_get_env(path);

	if (g_dbus_proxy_get_property(proxy, "Trusted", &iter))
		dbus_message_iter_get_basic(&iter, &trusted);

	return trusted;
}

static DBusMessage *chrc_read_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;
	DBusMessageIter iter;
	uint16_t offset = 0;
	char *device, *link;
	char *str;

	dbus_message_iter_init(msg, &iter);

	if (parse_options(&iter, &offset, NULL, &device, &link, NULL))
		return g_dbus_create_error(msg,
					"org.bluez.Error.InvalidArguments",
					NULL);

	bt_shell_printf("ReadValue: %s offset %u link %s\n",
					path_to_address(device), offset, link);

	if (!is_device_trusted(device) && chrc->authorization_req) {
		struct authorize_attribute_data *aad;

		aad = g_new0(struct authorize_attribute_data, 1);
		aad->conn = conn;
		aad->attribute = chrc;
		aad->offset = offset;

		str = g_strdup_printf("Authorize attribute(%s) read (yes/no):",
								chrc->path);

		bt_shell_prompt_input("gatt", str, authorize_read_response,
									aad);
		g_free(str);

		pending_message = dbus_message_ref(msg);

		return NULL;
	}

	if (offset > chrc->value_len)
		return g_dbus_create_error(msg, "org.bluez.Error.InvalidOffset",
									NULL);

	return read_value(msg, &chrc->value[offset], chrc->value_len - offset);
}

static int parse_value_arg(DBusMessageIter *iter, uint8_t **value, int *len)
{
	DBusMessageIter array;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, value, len);

	return 0;
}

static int write_value(int *dst_len, uint8_t **dst_value, uint8_t *src_val,
				int src_len, uint16_t offset, uint16_t max_len)
{
	if ((offset + src_len) > max_len)
		return -EOVERFLOW;

	if ((offset + src_len) != *dst_len) {
		*dst_len = offset + src_len;
		*dst_value = g_realloc(*dst_value, *dst_len);
	}

	memcpy(*dst_value + offset, src_val, src_len);

	return 0;
}

static void authorize_write_response(const char *input, void *user_data)
{
	struct authorize_attribute_data *aad = user_data;
	struct chrc *chrc = aad->attribute;
	bool prep_authorize = false;
	DBusMessageIter iter;
	DBusMessage *reply;
	int value_len;
	uint8_t *value;
	char *err;

	dbus_message_iter_init(pending_message, &iter);
	if (parse_value_arg(&iter, &value, &value_len)) {
		err = "org.bluez.Error.InvalidArguments";

		goto error;
	}

	dbus_message_iter_next(&iter);
	if (parse_options(&iter, NULL, NULL, NULL, NULL, &prep_authorize)) {
		err = "org.bluez.Error.InvalidArguments";

		goto error;
	}

	if (!strcmp(input, "no")) {
		err = "org.bluez.Error.NotAuthorized";

		goto error;
	}

	/* Authorization check of prepare writes */
	if (prep_authorize) {
		reply = g_dbus_create_reply(pending_message, DBUS_TYPE_INVALID);
		g_dbus_send_message(aad->conn, reply);
		g_free(aad);

		return;
	}

	if (write_value(&chrc->value_len, &chrc->value, value, value_len,
					aad->offset, chrc->max_val_len)) {
		err = "org.bluez.Error.InvalidValueLength";

		goto error;
	}

	bt_shell_printf("[" COLORED_CHG "] Attribute %s written" , chrc->path);

	g_dbus_emit_property_changed(aad->conn, chrc->path, CHRC_INTERFACE,
								"Value");

	reply = g_dbus_create_reply(pending_message, DBUS_TYPE_INVALID);
	g_dbus_send_message(aad->conn, reply);

	g_free(aad);

	return;

error:
	g_dbus_send_error(aad->conn, pending_message, err, NULL);
	g_free(aad);
}

static DBusMessage *chrc_write_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;
	uint16_t offset = 0;
	bool prep_authorize = false;
	char *device = NULL;
	DBusMessageIter iter;
	int value_len;
	uint8_t *value;
	char *str;

	dbus_message_iter_init(msg, &iter);

	if (parse_value_arg(&iter, &value, &value_len))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidArguments", NULL);

	dbus_message_iter_next(&iter);
	if (parse_options(&iter, &offset, NULL, &device, NULL, &prep_authorize))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidArguments", NULL);

	if (!is_device_trusted(device) && chrc->authorization_req) {
		struct authorize_attribute_data *aad;

		aad = g_new0(struct authorize_attribute_data, 1);
		aad->conn = conn;
		aad->attribute = chrc;
		aad->offset = offset;

		str = g_strdup_printf("Authorize attribute(%s) write (yes/no):",
								chrc->path);

		bt_shell_prompt_input("gatt", str, authorize_write_response,
									aad);
		g_free(str);

		pending_message = dbus_message_ref(msg);

		return NULL;
	}

	/* Authorization check of prepare writes */
	if (prep_authorize)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	if (write_value(&chrc->value_len, &chrc->value, value, value_len,
						offset, chrc->max_val_len))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidValueLength", NULL);

	bt_shell_printf("[" COLORED_CHG "] Attribute %s written" , chrc->path);

	g_dbus_emit_property_changed(conn, chrc->path, CHRC_INTERFACE, "Value");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *chrc_create_pipe(struct chrc *chrc, DBusMessage *msg)
{
	int pipefd[2];
	struct io *io;
	bool dir;
	DBusMessage *reply;

	if (pipe2(pipefd, O_DIRECT | O_NONBLOCK | O_CLOEXEC) < 0)
		return g_dbus_create_error(msg, "org.bluez.Error.Failed", "%s",
							strerror(errno));

	dir = dbus_message_has_member(msg, "AcquireWrite");

	io = pipe_io_new(pipefd[!dir], chrc);
	if (!io) {
		close(pipefd[0]);
		close(pipefd[1]);
		return g_dbus_create_error(msg, "org.bluez.Error.Failed", "%s",
							strerror(errno));
	}

	reply = g_dbus_create_reply(msg, DBUS_TYPE_UNIX_FD, &pipefd[dir],
					DBUS_TYPE_UINT16, &chrc->mtu,
					DBUS_TYPE_INVALID);

	close(pipefd[dir]);

	if (dir)
		chrc->write_io = io;
	else
		chrc->notify_io = io;

	bt_shell_printf("[" COLORED_CHG "] Attribute %s %s pipe acquired\n",
					chrc->path, dir ? "Write" : "Notify");

	return reply;
}

static DBusMessage *chrc_acquire_write(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *device = NULL, *link= NULL;

	dbus_message_iter_init(msg, &iter);

	if (chrc->write_io)
		return g_dbus_create_error(msg,
					"org.bluez.Error.NotPermitted",
					NULL);

	if (parse_options(&iter, NULL, &chrc->mtu, &device, &link, NULL))
		return g_dbus_create_error(msg,
					"org.bluez.Error.InvalidArguments",
					NULL);

	bt_shell_printf("AcquireWrite: %s link %s\n", path_to_address(device),
									link);

	reply = chrc_create_pipe(chrc, msg);

	if (chrc->write_io)
		g_dbus_emit_property_changed(conn, chrc->path, CHRC_INTERFACE,
							"WriteAcquired");

	return reply;
}

static DBusMessage *chrc_acquire_notify(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *device = NULL, *link = NULL;

	dbus_message_iter_init(msg, &iter);

	if (chrc->notify_io)
		return g_dbus_create_error(msg,
					"org.bluez.Error.NotPermitted",
					NULL);

	if (parse_options(&iter, NULL, &chrc->mtu, &device, &link, NULL))
		return g_dbus_create_error(msg,
					"org.bluez.Error.InvalidArguments",
					NULL);

	bt_shell_printf("AcquireNotify: %s link %s\n", path_to_address(device),
									link);

	reply = chrc_create_pipe(chrc, msg);

	if (chrc->notify_io)
		g_dbus_emit_property_changed(conn, chrc->path, CHRC_INTERFACE,
							"NotifyAcquired");

	return reply;
}

static DBusMessage *chrc_start_notify(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;

	if (!chrc->notifying)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	chrc->notifying = true;
	bt_shell_printf("[" COLORED_CHG "] Attribute %s notifications enabled",
							chrc->path);
	g_dbus_emit_property_changed(conn, chrc->path, CHRC_INTERFACE,
							"Notifying");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *chrc_stop_notify(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;

	if (chrc->notifying)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	chrc->notifying = false;
	bt_shell_printf("[" COLORED_CHG "] Attribute %s notifications disabled",
							chrc->path);
	g_dbus_emit_property_changed(conn, chrc->path, CHRC_INTERFACE,
							"Notifying");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *chrc_confirm(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct chrc *chrc = user_data;

	bt_shell_printf("Attribute %s indication confirm received", chrc->path);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable chrc_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", GDBUS_ARGS({ "options", "a{sv}" }),
					GDBUS_ARGS({ "value", "ay" }),
					chrc_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" },
						{ "options", "a{sv}" }),
					NULL, chrc_write_value) },
	{ GDBUS_METHOD("AcquireWrite", GDBUS_ARGS({ "options", "a{sv}" }),
					NULL, chrc_acquire_write) },
	{ GDBUS_METHOD("AcquireNotify", GDBUS_ARGS({ "options", "a{sv}" }),
					NULL, chrc_acquire_notify) },
	{ GDBUS_ASYNC_METHOD("StartNotify", NULL, NULL, chrc_start_notify) },
	{ GDBUS_METHOD("StopNotify", NULL, NULL, chrc_stop_notify) },
	{ GDBUS_METHOD("Confirm", NULL, NULL, chrc_confirm) },
	{ }
};

static uint8_t *str2bytearray(char *arg, int *val_len)
{
	uint8_t value[MAX_ATTR_VAL_LEN];
	char *entry;
	unsigned int i;

	for (i = 0; (entry = strsep(&arg, " \t")) != NULL; i++) {
		long int val;
		char *endptr = NULL;

		if (*entry == '\0')
			continue;

		if (i >= G_N_ELEMENTS(value)) {
			bt_shell_printf("Too much data\n");
			return NULL;
		}

		val = strtol(entry, &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Invalid value at index %d\n", i);
			return NULL;
		}

		value[i] = val;
	}

	*val_len = i;

	return g_memdup(value, i);
}

static void chrc_set_value(const char *input, void *user_data)
{
	struct chrc *chrc = user_data;

	g_free(chrc->value);

	chrc->value = str2bytearray((char *) input, &chrc->value_len);

	if (!chrc->value) {
		print_chrc(chrc, COLORED_DEL);
		chrc_unregister(chrc);
	}

	chrc->max_val_len = chrc->value_len;
}

static gboolean attr_authorization_flag_exists(char **flags)
{
	int i;

	for (i = 0; flags[i]; i++) {
		if (!strcmp("authorize", flags[i]))
			return TRUE;
	}

	return FALSE;
}

void gatt_register_chrc(DBusConnection *conn, GDBusProxy *proxy,
					int argc, char *argv[])
{
	struct service *service;
	struct chrc *chrc;

	if (!local_services) {
		bt_shell_printf("No service registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service = g_list_last(local_services)->data;

	chrc = g_new0(struct chrc, 1);
	chrc->service = service;
	chrc->uuid = g_strdup(argv[1]);
	chrc->path = g_strdup_printf("%s/chrc%p", service->path, chrc);
	chrc->flags = g_strsplit(argv[2], ",", -1);
	chrc->authorization_req = attr_authorization_flag_exists(chrc->flags);

	if (g_dbus_register_interface(conn, chrc->path, CHRC_INTERFACE,
					chrc_methods, NULL, chrc_properties,
					chrc, chrc_free) == FALSE) {
		bt_shell_printf("Failed to register characteristic object\n");
		chrc_free(chrc);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service->chrcs = g_list_append(service->chrcs, chrc);

	print_chrc(chrc, COLORED_NEW);

	bt_shell_prompt_input(chrc->path, "Enter value:", chrc_set_value, chrc);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static struct chrc *chrc_find(const char *pattern)
{
	GList *l, *lc;
	struct service *service;
	struct chrc *chrc;

	for (l = local_services; l; l = g_list_next(l)) {
		service = l->data;

		for (lc = service->chrcs; lc; lc =  g_list_next(lc)) {
			chrc = lc->data;

			/* match object path */
			if (!strcmp(chrc->path, pattern))
				return chrc;

			/* match UUID */
			if (!strcmp(chrc->uuid, pattern))
				return chrc;
		}
	}

	return NULL;
}

void gatt_unregister_chrc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct chrc *chrc;

	chrc = chrc_find(argv[1]);
	if (!chrc) {
		bt_shell_printf("Failed to unregister characteristic object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	chrc->service->chrcs = g_list_remove(chrc->service->chrcs, chrc);

	chrc_unregister(chrc);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static DBusMessage *desc_read_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct desc *desc = user_data;
	DBusMessageIter iter;
	uint16_t offset = 0;
	char *device = NULL, *link = NULL;

	dbus_message_iter_init(msg, &iter);

	if (parse_options(&iter, &offset, NULL, &device, &link, NULL))
		return g_dbus_create_error(msg,
					"org.bluez.Error.InvalidArguments",
					NULL);

	bt_shell_printf("ReadValue: %s offset %u link %s\n",
			path_to_address(device), offset, link);

	if (offset > desc->value_len)
		return g_dbus_create_error(msg, "org.bluez.Error.InvalidOffset",
									NULL);

	return read_value(msg, &desc->value[offset], desc->value_len - offset);
}

static DBusMessage *desc_write_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct desc *desc = user_data;
	DBusMessageIter iter;
	uint16_t offset = 0;
	char *device = NULL, *link = NULL;
	int value_len;
	uint8_t *value;

	dbus_message_iter_init(msg, &iter);

	if (parse_value_arg(&iter, &value, &value_len))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidArguments", NULL);

	dbus_message_iter_next(&iter);
	if (parse_options(&iter, &offset, NULL, &device, &link, NULL))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidArguments", NULL);

	if (write_value(&desc->value_len, &desc->value, value,
					value_len, offset, desc->max_val_len))
		return g_dbus_create_error(msg,
				"org.bluez.Error.InvalidValueLength", NULL);

	bt_shell_printf("WriteValue: %s offset %u link %s\n",
			path_to_address(device), offset, link);

	bt_shell_printf("[" COLORED_CHG "] Attribute %s written" , desc->path);

	g_dbus_emit_property_changed(conn, desc->path, CHRC_INTERFACE, "Value");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable desc_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", GDBUS_ARGS({ "options", "a{sv}" }),
					GDBUS_ARGS({ "value", "ay" }),
					desc_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" },
						{ "options", "a{sv}" }),
					NULL, desc_write_value) },
	{ }
};

static gboolean desc_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct desc *desc = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &desc->uuid);

	return TRUE;
}

static gboolean desc_get_chrc(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct desc *desc = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
						&desc->chrc->path);

	return TRUE;
}

static gboolean desc_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct desc *desc = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	if (desc->value)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
							&desc->value,
							desc->value_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean desc_get_flags(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct desc *desc = data;
	int i;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; desc->flags[i]; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&desc->flags[i]);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable desc_properties[] = {
	{ "UUID", "s", desc_get_uuid, NULL, NULL },
	{ "Characteristic", "o", desc_get_chrc, NULL, NULL },
	{ "Value", "ay", desc_get_value, NULL, NULL },
	{ "Flags", "as", desc_get_flags, NULL, NULL },
	{ }
};

static void desc_set_value(const char *input, void *user_data)
{
	struct desc *desc = user_data;

	g_free(desc->value);

	desc->value = str2bytearray((char *) input, &desc->value_len);

	if (!desc->value) {
		print_desc(desc, COLORED_DEL);
		desc_unregister(desc);
	}

	desc->max_val_len = desc->value_len;
}

void gatt_register_desc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct service *service;
	struct desc *desc;

	if (!local_services) {
		bt_shell_printf("No service registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service = g_list_last(local_services)->data;

	if (!service->chrcs) {
		bt_shell_printf("No characteristic registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	desc = g_new0(struct desc, 1);
	desc->chrc = g_list_last(service->chrcs)->data;
	desc->uuid = g_strdup(argv[1]);
	desc->path = g_strdup_printf("%s/desc%p", desc->chrc->path, desc);
	desc->flags = g_strsplit(argv[2], ",", -1);

	if (g_dbus_register_interface(conn, desc->path, DESC_INTERFACE,
					desc_methods, NULL, desc_properties,
					desc, desc_free) == FALSE) {
		bt_shell_printf("Failed to register descriptor object\n");
		desc_free(desc);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	desc->chrc->descs = g_list_append(desc->chrc->descs, desc);

	print_desc(desc, COLORED_NEW);

	bt_shell_prompt_input(desc->path, "Enter value:", desc_set_value, desc);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static struct desc *desc_find(const char *pattern)
{
	GList *l, *lc, *ld;
	struct service *service;
	struct chrc *chrc;
	struct desc *desc;

	for (l = local_services; l; l = g_list_next(l)) {
		service = l->data;

		for (lc = service->chrcs; lc; lc = g_list_next(lc)) {
			chrc = lc->data;

			for (ld = chrc->descs; ld; ld = g_list_next(ld)) {
				desc = ld->data;

				/* match object path */
				if (!strcmp(desc->path, pattern))
					return desc;

				/* match UUID */
				if (!strcmp(desc->uuid, pattern))
					return desc;
			}
		}
	}

	return NULL;
}

void gatt_unregister_desc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[])
{
	struct desc *desc;

	desc = desc_find(argv[1]);
	if (!desc) {
		bt_shell_printf("Failed to unregister descriptor object\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	desc->chrc->descs = g_list_remove(desc->chrc->descs, desc);

	desc_unregister(desc);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}
