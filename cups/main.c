/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <gdbus.h>

#include "cups.h"
#include "sdp-xml.h"

extern int sdp_search_spp(sdp_session_t *sdp, uint8_t *channel);
extern int sdp_search_hcrp(sdp_session_t *sdp, unsigned short *ctrl_psm, unsigned short *data_psm);

extern int spp_print(bdaddr_t *src, bdaddr_t *dst, uint8_t channel, int fd, int copies, const char *cups_class);
extern int hcrp_print(bdaddr_t *src, bdaddr_t *dst, unsigned short ctrl_psm, unsigned short data_psm, int fd, int copies, const char *cups_class);

#define PRINTER_SERVICE_CLASS_NAME "printer"

struct cups_device {
	char *bdaddr;
	char *name;
	char *id;
};

static GSList *device_list = NULL;
static GMainLoop *loop = NULL;
static DBusConnection *conn = NULL;

#define ATTRID_1284ID 0x0300

static char *parse_xml_sdp(const char *xml)
{
	sdp_record_t *sdp_record;
	sdp_list_t *l;
	char *str = NULL;

	sdp_record = sdp_xml_parse_record(xml, strlen(xml));
	if (sdp_record == NULL)
		return NULL;
	for (l = sdp_record->attrlist; l != NULL; l = l->next) {
		sdp_data_t *data;

		data = (sdp_data_t *) l->data;
		if (data->attrId != ATTRID_1284ID)
			continue;
		/* Ignore the length, it's null terminated */
		str = g_strdup(data->val.str + 2);
		break;
	}
	sdp_record_free(sdp_record);

	return str;
}

static char *device_get_ieee1284_id(const char *adapter, const char *bdaddr)
{
	guint service_handle;
	DBusMessage *message, *reply;
	DBusMessageIter iter, reply_iter, iter_array;
	const char *hcr_print = "00001126-0000-1000-8000-00805f9b34fb";
	char *xml, *id;

	/* Look for the service handle of the HCRP service */
	message = dbus_message_new_method_call("org.bluez", adapter,
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &bdaddr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &hcr_print);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, NULL);

	dbus_message_unref(message);

	if (!reply)
		return NULL;

	dbus_message_iter_init(reply, &reply_iter);
	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		dbus_message_unref(reply);
		return NULL;
	}

	/* Hopefully we only get one handle, or take a punt */
	dbus_message_iter_recurse(&reply_iter, &iter_array);
	while (dbus_message_iter_get_arg_type(&iter_array) == DBUS_TYPE_UINT32) {
		dbus_message_iter_get_basic(&iter_array, &service_handle);
		dbus_message_iter_next(&iter_array);
	}

	dbus_message_unref(reply);

	/* Now get the XML for the HCRP service record */
	message = dbus_message_new_method_call("org.bluez", adapter,
						"org.bluez.Adapter",
						"GetRemoteServiceRecordAsXML");
	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &bdaddr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &service_handle);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, NULL);

	dbus_message_unref(message);

	if (!reply)
		return NULL;

	dbus_message_iter_init(reply, &reply_iter);
	dbus_message_iter_get_basic(&reply_iter, &xml);

	id = parse_xml_sdp(xml);

	dbus_message_unref(reply);

	return id;
}

static void add_device_to_list(const char *name, const char *bdaddr, const char *id)
{
	struct cups_device *device;
	GSList *l;

	/* Look for the device in the list */
	for (l = device_list; l != NULL; l = l->next) {
		device = (struct cups_device *) l->data;

		if (strcmp(device->bdaddr, bdaddr) == 0) {
			g_free(device->name);
			device->name = g_strdup(name);
			return;
		}
	}

	/* Or add it to the list if it's not there */
	device = g_new0(struct cups_device, 1);
	device->bdaddr = g_strdup(bdaddr);
	device->name = g_strdup(name);
	device->id = g_strdup(id);

	device_list = g_slist_prepend(device_list, device);
}

static char *escape_name(const char *str, char orig, char dest)
{
	char *ret, *s;

	ret = g_strdup(str);
	while ((s = strchr(ret, orig)) != NULL)
		s[0] = dest;
	return ret;
}

static void print_printer_details(const char *name, const char *bdaddr, const char *id)
{
	char *uri, *escaped;
	guint len;

	escaped = escape_name(name, '\"', '\'');
	len = strlen("bluetooth://") + 12 + 1;
	uri = g_malloc(len);
	snprintf(uri, len, "bluetooth://%c%c%c%c%c%c%c%c%c%c%c%c",
		 bdaddr[0], bdaddr[1],
		 bdaddr[3], bdaddr[4],
		 bdaddr[6], bdaddr[7],
		 bdaddr[9], bdaddr[10],
		 bdaddr[12], bdaddr[13],
		 bdaddr[15], bdaddr[16]);
	printf("network %s \"Unknown\" \"%s (Bluetooth)\"", uri, escaped);
	if (id != NULL)
		printf(" \"%s\"\n", id);
	else
		printf ("\n");
	g_free(escaped);
	g_free(uri);
}

static gboolean device_is_printer(const char *adapter, const char *bdaddr)
{
	char *class;
	DBusMessage *message, *reply;
	DBusMessageIter iter, reply_iter;

	message = dbus_message_new_method_call("org.bluez", adapter,
					       "org.bluez.Adapter",
					       "GetRemoteMinorClass");
	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &bdaddr);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, NULL);

	dbus_message_unref(message);

	if (!reply)
		return FALSE;

	dbus_message_iter_init(reply, &reply_iter);
	dbus_message_iter_get_basic(&reply_iter, &class);

	if (class != NULL && strcmp(class, PRINTER_SERVICE_CLASS_NAME) == 0) {
		dbus_message_unref(reply);
		return TRUE;
	}

	return FALSE;
}

static char *device_get_name(const char *adapter, const char *bdaddr)
{
	DBusMessage *message, *reply;
	DBusMessageIter iter, reply_iter;
	char *name;

	message = dbus_message_new_method_call("org.bluez", adapter,
						"org.bluez.Adapter",
						"GetRemoteName");
	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &bdaddr);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, NULL);

	dbus_message_unref(message);

	if (!reply)
		return NULL;

	dbus_message_iter_init(reply, &reply_iter);
	dbus_message_iter_get_basic(&reply_iter, &name);

	name = g_strdup(name);
	dbus_message_unref(reply);

	return name;
}

static void remote_device_found(const char *adapter, const char *bdaddr, guint class, int rssi)
{
	uint8_t major_index = (class >> 8) & 0x1F;
	uint8_t minor_index;
	uint8_t shift_minor = 0;
	gboolean found = FALSE;
	char *name, *id;

	/* Check if we have a printer
	 * From hcid/dbus-adapter.c minor_class_str() */
	if (major_index != 6)
		return;

	minor_index = (class >> 4) & 0x0F;
	while (shift_minor < 4) {
		if (((minor_index >> shift_minor) & 0x01) == 0x01) {
			if (shift_minor == 3) {
				found = TRUE;
				break;
			}
		}
		shift_minor++;
	}

	if (!found)
		return;

	name = device_get_name(adapter, bdaddr);
	id = device_get_ieee1284_id(adapter, bdaddr);
	add_device_to_list(name, bdaddr, id);
	g_free(name);
	g_free(id);
}

static void remote_name_updated(const char *bdaddr, const char *name)
{
	add_device_to_list(name, bdaddr, NULL);
}

static void discovery_completed(void)
{
	GSList *l;

	for (l = device_list; l != NULL; l = l->next) {
		struct cups_device *device = (struct cups_device *) l->data;

		if (device->name == NULL)
			device->name = escape_name(device->bdaddr, ':', '-');
		print_printer_details(device->name, device->bdaddr, device->id);
		g_free(device->name);
		g_free(device->bdaddr);
		g_free(device->id);
		g_free(device);
	}

	g_slist_free(device_list);
	device_list = NULL;

	g_main_loop_quit(loop);
}

static void remote_device_disappeared(const char *bdaddr)
{
	GSList *l;

	for (l = device_list; l != NULL; l = l->next) {
		struct cups_device *device = (struct cups_device *) l->data;

		if (strcmp(device->bdaddr, bdaddr) == 0) {
			g_free(device->name);
			g_free(device->bdaddr);
			g_free(device);
			device_list = g_slist_delete_link(device_list, l);
			return;
		}
	}
}

static gboolean list_known_printers(const char *adapter)
{
	DBusMessageIter reply_iter, iter_array;
	DBusError error;
	DBusMessage *message, *reply;

	message = dbus_message_new_method_call ("org.bluez", adapter,
						"org.bluez.Adapter",
						"ListRemoteDevices");
	if (message == NULL)
		return FALSE;

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (&error != NULL && dbus_error_is_set(&error))
		return FALSE;

	dbus_message_iter_init(reply, &reply_iter);
	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		dbus_message_unref(reply);
		return FALSE;
	}

	dbus_message_iter_recurse(&reply_iter, &iter_array);
	while (dbus_message_iter_get_arg_type(&iter_array) == DBUS_TYPE_STRING) {
		char *bdaddr;

		dbus_message_iter_get_basic(&iter_array, &bdaddr);
		if (device_is_printer(adapter, bdaddr)) {
			char *name, *id;
			name = device_get_name(adapter, bdaddr);
			id = device_get_ieee1284_id(adapter, bdaddr);
			add_device_to_list(name, bdaddr, id);
			g_free(name);
			g_free(id);
		}
		dbus_message_iter_next(&iter_array);
	}

	dbus_message_unref(reply);

	return FALSE;
}

static DBusHandlerResult filter_func(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	const char *adapter;

	if (dbus_message_is_signal(message, "org.bluez.Adapter",
						"RemoteDeviceFound")) {
		char *bdaddr;
		guint class;
		int rssi;

		dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &bdaddr,
					DBUS_TYPE_UINT32, &class,
					DBUS_TYPE_INT32, &rssi,
					DBUS_TYPE_INVALID);
		adapter = dbus_message_get_path(message);
		remote_device_found(adapter, bdaddr, class, rssi);
	} else if (dbus_message_is_signal(message, "org.bluez.Adapter",
							"RemoteNameUpdated")) {
		char *bdaddr, *name;

		dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &bdaddr,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);
		remote_name_updated(bdaddr, name);
	} else if (dbus_message_is_signal(message, "org.bluez.Adapter",
						"RemoteDeviceDisappeared")) {
		char *bdaddr;

		dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &bdaddr,
					DBUS_TYPE_INVALID);
		remote_device_disappeared(bdaddr);
	} else if (dbus_message_is_signal(message, "org.bluez.Adapter",
						"DiscoveryCompleted")) {
		discovery_completed();
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static gboolean list_printers(void)
{
	/* 1. Connect to the bus
	 * 2. Get the manager
	 * 3. Get the default adapter
	 * 4. Get a list of devices
	 * 5. Get the class of each device
	 * 6. Print the details from each printer device
	 */
	DBusError error;
	dbus_bool_t hcid_exists;
	DBusMessage *reply, *message;
	DBusMessageIter reply_iter;
	char *adapter, *match;
	guint len;

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
	if (conn == NULL)
		return FALSE;

	dbus_error_init(&error);
	hcid_exists = dbus_bus_name_has_owner(conn, "org.bluez", &error);
	if (&error != NULL && dbus_error_is_set(&error))
		return FALSE;

	if (!hcid_exists)
		return FALSE;

	/* Get the default adapter */
	message = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Manager",
						"DefaultAdapter");
	if (message == NULL) {
		dbus_connection_unref(conn);
		return FALSE;
	}

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (&error != NULL && dbus_error_is_set(&error)) {
		dbus_connection_unref(conn);
		return FALSE;
	}

	dbus_message_iter_init(reply, &reply_iter);
	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_STRING) {
		dbus_message_unref(reply);
		dbus_connection_unref(conn);
		return FALSE;
	}

	dbus_message_iter_get_basic(&reply_iter, &adapter);
	adapter = g_strdup(adapter);
	dbus_message_unref(reply);

	if (!dbus_connection_add_filter(conn, filter_func, adapter, g_free)) {
		g_free(adapter);
		dbus_connection_unref(conn);
		return FALSE;
	}

#define MATCH_FORMAT				\
	"type='signal',"			\
	"interface='org.bluez.Adapter',"	\
	"sender='org.bluez',"			\
	"path='%s'"

	len = strlen(MATCH_FORMAT) - 2 + strlen(adapter) + 1;
	match = g_malloc(len);
	snprintf(match, len, "type='signal',"
				"interface='org.bluez.Adapter',"
				"sender='org.bluez',"
				"path='%s'",
				adapter);
	dbus_bus_add_match(conn, match, &error);
	g_free(match);

	message = dbus_message_new_method_call("org.bluez", adapter,
					"org.bluez.Adapter",
					"DiscoverDevicesWithoutNameResolving");

	if (!dbus_connection_send_with_reply(conn, message, NULL, -1)) {
		dbus_message_unref(message);
		dbus_connection_unref(conn);
		g_free(adapter);
		return FALSE;
	}
	dbus_message_unref(message);

	/* Also add the the recent devices */
	g_timeout_add(0, (GSourceFunc) list_known_printers, adapter);

	loop = g_main_loop_new(NULL, TRUE);
	g_main_loop_run(loop);

	dbus_connection_unref(conn);

	return TRUE;
}

/*
 *  Usage: printer-uri job-id user title copies options [file]
 *
 */

int main(int argc, char *argv[])
{
	sdp_session_t *sdp;
	bdaddr_t bdaddr;
	unsigned short ctrl_psm, data_psm;
	uint8_t channel, b[6];
	char *ptr, str[3], device[18], service[12];
	const char *uri, *cups_class;
	int i, err, fd, copies, proto;

	/* Make sure status messages are not buffered */
	setbuf(stderr, NULL);

	/* Ignore SIGPIPE signals */
#ifdef HAVE_SIGSET
	sigset(SIGPIPE, SIG_IGN);
#elif defined(HAVE_SIGACTION)
	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	signal(SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */

	if (argc == 1) {
		if (list_printers() == TRUE)
			return CUPS_BACKEND_OK;
		else
			return CUPS_BACKEND_FAILED;
	}

	if (argc < 6 || argc > 7) {
		fprintf(stderr, "Usage: bluetooth job-id user title copies options [file]\n");
		return CUPS_BACKEND_FAILED;
	}

	if (argc == 6) {
		fd = 0;
		copies = 1;
	} else {
		if ((fd = open(argv[6], O_RDONLY)) < 0) {
			perror("ERROR: Unable to open print file");
			return CUPS_BACKEND_FAILED;
		}
		copies = atoi(argv[4]);
	}

	uri = getenv("DEVICE_URI");
	if (!uri)
		uri = argv[0];

	if (strncasecmp(uri, "bluetooth://", 12)) {
		fprintf(stderr, "ERROR: No device URI found\n");
		return CUPS_BACKEND_FAILED;
	}

	ptr = argv[0] + 12;
	for (i = 0; i < 6; i++) {
		strncpy(str, ptr, 2);
		b[i] = (uint8_t) strtol(str, NULL, 16);
		ptr += 2;
	}
	sprintf(device, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		b[0], b[1], b[2], b[3], b[4], b[5]);

	str2ba(device, &bdaddr);

	ptr = strchr(ptr, '/');
	if (ptr) {
		strncpy(service, ptr + 1, 12);

		if (!strncasecmp(ptr + 1, "spp", 3))
			proto = 1;
		else if (!strncasecmp(ptr + 1, "hcrp", 4))
			proto = 2;
		else
			proto = 0;
	} else {
		strcpy(service, "auto");
		proto = 0;
	}

	cups_class = getenv("CLASS");

	fprintf(stderr, "DEBUG: %s device %s service %s fd %d copies %d class %s\n",
			argv[0], device, service, fd, copies,
					cups_class ? cups_class : "(none)");

	fputs("STATE: +connecting-to-device\n", stderr);

service_search:
	sdp = sdp_connect(BDADDR_ANY, &bdaddr, SDP_RETRY_IF_BUSY);
	if (!sdp) {
		fprintf(stderr, "ERROR: Can't open Bluetooth connection\n");
		return CUPS_BACKEND_FAILED;
	}

	switch (proto) {
	case 1:
		err = sdp_search_spp(sdp, &channel);
		break;
	case 2:
		err = sdp_search_hcrp(sdp, &ctrl_psm, &data_psm);
		break;
	default:
		proto = 2;
		err = sdp_search_hcrp(sdp, &ctrl_psm, &data_psm);
		if (err) {
			proto = 1;
			err = sdp_search_spp(sdp, &channel);
		}
		break;
	}

	sdp_close(sdp);

	if (err) {
		if (cups_class) {
			fputs("INFO: Unable to contact printer, queuing on "
					"next printer in class...\n", stderr);
			sleep(5);
			return CUPS_BACKEND_FAILED;
		}
		sleep(20);
		fprintf(stderr, "ERROR: Can't get service information\n");
		goto service_search;
	}

connect:
	switch (proto) {
	case 1:
		err = spp_print(BDADDR_ANY, &bdaddr, channel,
						fd, copies, cups_class);
		break;
	case 2:
		err = hcrp_print(BDADDR_ANY, &bdaddr, ctrl_psm, data_psm,
						fd, copies, cups_class);
		break;
	default:
		err = CUPS_BACKEND_FAILED;
		fprintf(stderr, "ERROR: Unsupported protocol\n");
		break;
	}

	if (err == CUPS_BACKEND_FAILED && cups_class) {
		fputs("INFO: Unable to contact printer, queuing on "
					"next printer in class...\n", stderr);
		sleep(5);
		return CUPS_BACKEND_FAILED;
	} else if (err == CUPS_BACKEND_RETRY) {
		sleep(20);
		goto connect;
	}

	if (fd != 0)
		close(fd);

	if (!err)
		fprintf(stderr, "INFO: Ready to print\n");

	return err;
}
