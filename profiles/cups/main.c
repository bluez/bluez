// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"

#include "gdbus/gdbus.h"

#include "cups.h"

#define DISCOVERY_TIMEOUT 10

struct id_lookup {
	char *name;
	char *bdaddr;
	sdp_session_t *sdp;
	guint watch;
};

static GSList *printer_list = NULL;
static GSList *lookup_list = NULL;
static GMainLoop *loop = NULL;
static gboolean adapter_found = FALSE;

static char *device_get_ieee1284_id(const char *address)
{
	sdp_session_t *sdp;
	bdaddr_t bdaddr;
	char *id;

	str2ba(address, &bdaddr);

	sdp = sdp_connect(BDADDR_ANY, &bdaddr, SDP_RETRY_IF_BUSY);
	if (!sdp)
		return NULL;

	id = sdp_search_ieee1284_id(sdp);

	sdp_close(sdp);

	return id;
}

static void print_printer_details(const char *name, const char *bdaddr,
								const char *id)
{
	char *uri, *escaped;

	escaped = g_strdelimit(g_strdup(name), "\"", '\'');
	uri = g_strdup_printf("bluetooth://%c%c%c%c%c%c%c%c%c%c%c%c",
				bdaddr[0], bdaddr[1],
				bdaddr[3], bdaddr[4],
				bdaddr[6], bdaddr[7],
				bdaddr[9], bdaddr[10],
				bdaddr[12], bdaddr[13],
				bdaddr[15], bdaddr[16]);
	printf("direct %s \"%s\" \"%s (Bluetooth)\"", uri, escaped, escaped);
	if (id != NULL)
		printf(" \"%s\"\n", id);
	else
		printf("\n");
	g_free(escaped);
	g_free(uri);
}

static void lookup_done(struct id_lookup *lookup, const char *id)
{
	print_printer_details(lookup->name, lookup->bdaddr, id);

	lookup_list = g_slist_remove(lookup_list, lookup);

	if (lookup->watch)
		g_source_remove(lookup->watch);

	sdp_close(lookup->sdp);
	g_free(lookup->name);
	g_free(lookup->bdaddr);
	g_free(lookup);
}

static void lookup_complete(uint8_t type, uint16_t status, uint8_t *rsp,
						size_t size, void *user_data)
{
	struct id_lookup *lookup = user_data;
	char *id = NULL;

	if (!status && type == SDP_SVC_SEARCH_ATTR_RSP)
		id = sdp_parse_ieee1284_id(rsp, size);

	lookup->watch = 0;
	lookup_done(lookup, id);
	free(id);
}

static gboolean lookup_process(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct id_lookup *lookup = user_data;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		lookup->watch = 0;
		lookup_done(lookup, NULL);
		return FALSE;
	}

	/* On failure or completion sdp_process() calls lookup_complete() */
	if (sdp_process(lookup->sdp) < 0)
		return FALSE;

	return TRUE;
}

static gboolean lookup_connected(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct id_lookup *lookup = user_data;
	socklen_t len = sizeof(int);
	int sk_err = 0;

	lookup->watch = 0;

	if (getsockopt(g_io_channel_unix_get_fd(chan), SOL_SOCKET, SO_ERROR,
						&sk_err, &len) < 0 || sk_err ||
			sdp_set_notify(lookup->sdp, lookup_complete,
					lookup) < 0 ||
			sdp_search_ieee1284_id_async(lookup->sdp) < 0) {
		lookup_done(lookup, NULL);
		return FALSE;
	}

	lookup->watch = g_io_add_watch(chan,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				lookup_process, lookup);

	return FALSE;
}

static void lookup_start(const char *name, const char *bdaddr)
{
	struct id_lookup *lookup;
	sdp_session_t *sdp;
	GIOChannel *chan;
	bdaddr_t ba;

	str2ba(bdaddr, &ba);

	sdp = sdp_connect(BDADDR_ANY, &ba, SDP_NON_BLOCKING);
	if (!sdp) {
		print_printer_details(name, bdaddr, NULL);
		return;
	}

	lookup = g_new0(struct id_lookup, 1);
	lookup->name = g_strdup(name);
	lookup->bdaddr = g_strdup(bdaddr);
	lookup->sdp = sdp;

	chan = g_io_channel_unix_new(sdp_get_socket(sdp));
	lookup->watch = g_io_add_watch(chan,
				G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				lookup_connected, lookup);
	g_io_channel_unref(chan);

	lookup_list = g_slist_prepend(lookup_list, lookup);
}

static void device_added(GDBusProxy *proxy)
{
	DBusMessageIter iter;
	dbus_uint32_t class;
	const char *bdaddr, *name;

	if (!g_dbus_proxy_get_property(proxy, "Class", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &class);

	/* Imaging major class with the printer bit set */
	if (((class & 0x1f00) >> 8) != 0x06 || !(class & 0x80))
		return;

	if (!g_dbus_proxy_get_property(proxy, "Address", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &bdaddr);

	if (!g_dbus_proxy_get_property(proxy, "Alias", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &name);

	if (g_slist_find_custom(printer_list, bdaddr, (GCompareFunc) strcmp))
		return;

	printer_list = g_slist_prepend(printer_list, g_strdup(bdaddr));

	lookup_start(name, bdaddr);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		adapter_found = TRUE;
		g_dbus_proxy_method_call(proxy, "StartDiscovery", NULL, NULL,
								NULL, NULL);
	} else if (!strcmp(interface, "org.bluez.Device1")) {
		device_added(proxy);
	}
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Device1") && !strcmp(name, "Class"))
		device_added(proxy);
}

static void client_ready(GDBusClient *client, void *user_data)
{
	if (!adapter_found)
		g_main_loop_quit(loop);
}

static gboolean discovery_timeout(gpointer user_data)
{
	/* List the printers whose device ID did not arrive in time */
	while (lookup_list)
		lookup_done(lookup_list->data, NULL);

	g_main_loop_quit(loop);

	return FALSE;
}

static gboolean list_printers(void)
{
	DBusConnection *conn;
	GDBusClient *client;

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
	if (conn == NULL)
		return TRUE;

	if (!dbus_bus_name_has_owner(conn, "org.bluez", NULL)) {
		dbus_connection_unref(conn);
		return TRUE;
	}

	loop = g_main_loop_new(NULL, FALSE);

	client = g_dbus_client_new(conn, "org.bluez", "/org/bluez");
	if (client == NULL) {
		g_main_loop_unref(loop);
		dbus_connection_unref(conn);
		return FALSE;
	}

	g_dbus_client_set_ready_watch(client, client_ready, NULL);
	g_dbus_client_set_proxy_handlers(client, proxy_added, NULL,
						property_changed, NULL);

	/* bluetoothd stops the discovery when we drop off the bus */
	g_timeout_add_seconds(DISCOVERY_TIMEOUT, discovery_timeout, NULL);

	g_main_loop_run(loop);

	g_dbus_client_unref(client);
	g_main_loop_unref(loop);
	dbus_connection_unref(conn);

	return TRUE;
}

static gboolean print_ieee1284(const char *bdaddr)
{
	char *id;

	id = device_get_ieee1284_id(bdaddr);
	if (id == NULL)
		return FALSE;

	printf("%s", id);
	free(id);

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
	char *ptr, str[3], device[18], service[13];
	const char *uri, *cups_class;
	int i, err, fd, copies, proto;

	/* Make sure status messages are not buffered */
	setbuf(stderr, NULL);

	/* Make sure output is not buffered */
	setbuf(stdout, NULL);

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
	} else if (argc == 3 && strcmp(argv[1], "--get-deviceid") == 0) {
		if (bachk(argv[2]) < 0) {
			fprintf(stderr, "Invalid Bluetooth address '%s'\n",
					argv[2]);
			return CUPS_BACKEND_FAILED;
		}
		if (print_ieee1284(argv[2]) == FALSE)
			return CUPS_BACKEND_FAILED;
		return CUPS_BACKEND_OK;
	}

	if (argc < 6 || argc > 7) {
		fprintf(stderr, "Usage: bluetooth job-id user title copies"
				" options [file]\n");
		fprintf(stderr, "       bluetooth --get-deviceid [bdaddr]\n");
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

	fprintf(stderr,
		"DEBUG: %s device %s service %s fd %d copies %d class %s\n",
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
