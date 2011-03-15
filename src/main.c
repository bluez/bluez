/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include <glib.h>

#include <dbus/dbus.h>

#include <gdbus.h>

#include "log.h"

#include "hcid.h"
#include "sdpd.h"
#include "attrib-server.h"
#include "adapter.h"
#include "event.h"
#include "dbus-common.h"
#include "agent.h"
#include "manager.h"

#ifdef HAVE_CAPNG
#include <cap-ng.h>
#endif

#define BLUEZ_NAME "org.bluez"

#define LAST_ADAPTER_EXIT_TIMEOUT 30

#define DEFAULT_DISCOVERABLE_TIMEOUT 180 /* 3 minutes */

struct main_opts main_opts;

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static void parse_config(GKeyFile *config)
{
	GError *err = NULL;
	char *str;
	int val;
	gboolean boolean;

	if (!config)
		return;

	DBG("parsing main.conf");

	val = g_key_file_get_integer(config, "General",
						"DiscoverableTimeout", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("discovto=%d", val);
		main_opts.discovto = val;
		main_opts.flags |= 1 << HCID_SET_DISCOVTO;
	}

	val = g_key_file_get_integer(config, "General",
						"PairableTimeout", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("pairto=%d", val);
		main_opts.pairto = val;
	}

	val = g_key_file_get_integer(config, "General", "PageTimeout", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("pageto=%d", val);
		main_opts.pageto = val;
		main_opts.flags |= 1 << HCID_SET_PAGETO;
	}

	str = g_key_file_get_string(config, "General", "Name", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("name=%s", str);
		g_free(main_opts.name);
		main_opts.name = g_strdup(str);
		main_opts.flags |= 1 << HCID_SET_NAME;
		g_free(str);
	}

	str = g_key_file_get_string(config, "General", "Class", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("class=%s", str);
		main_opts.class = strtol(str, NULL, 16);
		main_opts.flags |= 1 << HCID_SET_CLASS;
		g_free(str);
	}

	val = g_key_file_get_integer(config, "General",
					"DiscoverSchedulerInterval", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("discov_interval=%d", val);
		main_opts.discov_interval = val;
	}

	boolean = g_key_file_get_boolean(config, "General",
						"InitiallyPowered", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else if (boolean == FALSE)
		main_opts.mode = MODE_OFF;

	boolean = g_key_file_get_boolean(config, "General",
						"RememberPowered", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else
		main_opts.remember_powered = boolean;

	str = g_key_file_get_string(config, "General", "DeviceID", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else {
		DBG("deviceid=%s", str);
		strncpy(main_opts.deviceid, str,
					sizeof(main_opts.deviceid) - 1);
		g_free(str);
	}

	boolean = g_key_file_get_boolean(config, "General",
						"ReverseServiceDiscovery", &err);
	if (err) {
		DBG("%s", err->message);
		g_clear_error(&err);
	} else
		main_opts.reverse_sdp = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"NameResolving", &err);
	if (err)
		g_clear_error(&err);
	else
		main_opts.name_resolv = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"DebugKeys", &err);
	if (err)
		g_clear_error(&err);
	else
		main_opts.debug_keys = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"AttributeServer", &err);
	if (err)
		g_clear_error(&err);
	else
		main_opts.attrib_server = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"EnableLE", &err);
	if (err)
		g_clear_error(&err);
	else
		main_opts.le = boolean;

	main_opts.link_mode = HCI_LM_ACCEPT;

	main_opts.link_policy = HCI_LP_RSWITCH | HCI_LP_SNIFF |
						HCI_LP_HOLD | HCI_LP_PARK;
}

static void init_defaults(void)
{
	/* Default HCId settings */
	memset(&main_opts, 0, sizeof(main_opts));
	main_opts.scan	= SCAN_PAGE;
	main_opts.mode	= MODE_CONNECTABLE;
	main_opts.name	= g_strdup("BlueZ");
	main_opts.discovto	= DEFAULT_DISCOVERABLE_TIMEOUT;
	main_opts.remember_powered = TRUE;
	main_opts.reverse_sdp = TRUE;
	main_opts.name_resolv = TRUE;

	if (gethostname(main_opts.host_name, sizeof(main_opts.host_name) - 1) < 0)
		strcpy(main_opts.host_name, "noname");
}

static GMainLoop *event_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(event_loop);
}

static void sig_debug(int sig)
{
	__btd_toggle_debug();
}

static gchar *option_debug = NULL;
static gchar *option_plugin = NULL;
static gchar *option_noplugin = NULL;
static gboolean option_detach = TRUE;
static gboolean option_version = FALSE;
static gboolean option_udev = FALSE;

static guint last_adapter_timeout = 0;

static gboolean exit_timeout(gpointer data)
{
	g_main_loop_quit(event_loop);
	last_adapter_timeout = 0;
	return FALSE;
}

void btd_start_exit_timer(void)
{
	if (option_udev == FALSE)
		return;

	if (last_adapter_timeout > 0)
		g_source_remove(last_adapter_timeout);

	last_adapter_timeout = g_timeout_add_seconds(LAST_ADAPTER_EXIT_TIMEOUT,
						exit_timeout, NULL);
}

void btd_stop_exit_timer(void)
{
	if (last_adapter_timeout == 0)
		return;

	g_source_remove(last_adapter_timeout);
	last_adapter_timeout = 0;
}

static void disconnect_dbus(void)
{
	DBusConnection *conn = get_dbus_connection();

	if (!conn || !dbus_connection_get_is_connected(conn))
		return;

	manager_cleanup(conn, "/");

	set_dbus_connection(NULL);

	dbus_connection_unref(conn);
}

static int connect_dbus(void)
{
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, BLUEZ_NAME, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			return -EIO;
		}
		return -EALREADY;
	}

	if (!manager_init(conn, "/"))
		return -EIO;

	set_dbus_connection(conn);

	return 0;
}

static gboolean parse_debug(const char *key, const char *value,
				gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return TRUE;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..," },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "nodetach", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ "udev", 'u', 0, G_OPTION_ARG_NONE, &option_udev,
				"Run from udev mode of operation" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sigaction sa;
	uint16_t mtu = 0;
	GKeyFile *config;

	init_defaults();

#ifdef HAVE_CAPNG
	/* Drop capabilities */
	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED,
					CAP_NET_BIND_SERVICE, CAP_NET_ADMIN,
						CAP_NET_RAW, CAP_IPC_LOCK, -1);
	capng_apply(CAPNG_SELECT_BOTH);
#endif

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &err) == FALSE) {
		if (err != NULL) {
			g_printerr("%s\n", err->message);
			g_error_free(err);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_udev == TRUE) {
		int err;

		option_detach = TRUE;
		err = connect_dbus();
		if (err < 0) {
			if (err == -EALREADY)
				exit(0);
			exit(1);
		}
	}

	if (option_detach == TRUE && option_udev == FALSE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	umask(0077);

	__btd_log_init(option_debug, option_detach);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	config = load_config(CONFIGDIR "/main.conf");

	parse_config(config);

	agent_init();

	if (option_udev == FALSE) {
		if (connect_dbus() < 0) {
			error("Unable to get on D-Bus");
			exit(1);
		}
	} else {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	start_sdp_server(mtu, main_opts.deviceid, SDP_SERVER_COMPAT);

	if (main_opts.attrib_server) {
		if (attrib_server_init() < 0)
			error("Can't initialize attribute server");
	}

	/* Loading plugins has to be done after D-Bus has been setup since
	 * the plugins might wanna expose some paths on the bus. However the
	 * best order of how to init various subsystems of the Bluetooth
	 * daemon needs to be re-worked. */
	plugin_init(config, option_plugin, option_noplugin);

	event_loop = g_main_loop_new(NULL, FALSE);

	if (adapter_ops_setup() < 0) {
		error("adapter_ops_setup failed");
		exit(1);
	}

	rfkill_init();

	DBG("Entering main loop");

	g_main_loop_run(event_loop);

	disconnect_dbus();

	rfkill_exit();

	plugin_cleanup();

	if (main_opts.attrib_server)
		attrib_server_exit();

	stop_sdp_server();

	agent_exit();

	g_main_loop_unref(event_loop);

	if (config)
		g_key_file_free(config);

	info("Exit");

	__btd_log_cleanup();

	return 0;
}
