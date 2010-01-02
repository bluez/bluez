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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "logging.h"

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "dbus-common.h"
#include "agent.h"
#include "manager.h"

#ifdef HAVE_CAPNG
#include <cap-ng.h>
#endif

#define LAST_ADAPTER_EXIT_TIMEOUT 30

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

	debug("parsing main.conf");

	val = g_key_file_get_integer(config, "General",
						"DiscoverableTimeout", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("discovto=%d", val);
		main_opts.discovto = val;
		main_opts.flags |= 1 << HCID_SET_DISCOVTO;
	}

	val = g_key_file_get_integer(config, "General",
						"PairableTimeout", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("pairto=%d", val);
		main_opts.pairto = val;
	}

	val = g_key_file_get_integer(config, "General", "PageTimeout", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("pageto=%d", val);
		main_opts.pageto = val;
		main_opts.flags |= 1 << HCID_SET_PAGETO;
	}

	str = g_key_file_get_string(config, "General", "Name", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("name=%s", str);
		g_free(main_opts.name);
		main_opts.name = g_strdup(str);
		main_opts.flags |= 1 << HCID_SET_NAME;
		g_free(str);
	}

	str = g_key_file_get_string(config, "General", "Class", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("class=%s", str);
		main_opts.class = strtol(str, NULL, 16);
		main_opts.flags |= 1 << HCID_SET_CLASS;
		g_free(str);
	}

	val = g_key_file_get_integer(config, "General",
					"DiscoverSchedulerInterval", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("discov_interval=%d", val);
		main_opts.discov_interval = val;
	}

	boolean = g_key_file_get_boolean(config, "General",
						"InitiallyPowered", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else if (boolean == FALSE)
		main_opts.mode = MODE_OFF;

	boolean = g_key_file_get_boolean(config, "General",
						"RememberPowered", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else
		main_opts.remember_powered = boolean;

	str = g_key_file_get_string(config, "General", "DeviceID", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else {
		debug("deviceid=%s", str);
		strncpy(main_opts.deviceid, str,
					sizeof(main_opts.deviceid) - 1);
		g_free(str);
	}

	boolean = g_key_file_get_boolean(config, "General",
						"ReverseServiceDiscovery", &err);
	if (err) {
		debug("%s", err->message);
		g_clear_error(&err);
	} else
		main_opts.reverse_sdp = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"NameResolving", &err);
	if (err)
		g_clear_error(&err);
	else
		main_opts.name_resolv = boolean;

	main_opts.link_mode = HCI_LM_ACCEPT;

	main_opts.link_policy = HCI_LP_RSWITCH | HCI_LP_SNIFF |
						HCI_LP_HOLD | HCI_LP_PARK;
}

/*
 * Device name expansion
 *   %d - device id
 */
char *expand_name(char *dst, int size, char *str, int dev_id)
{
	register int sp, np, olen;
	char *opt, buf[10];

	if (!str || !dst)
		return NULL;

	sp = np = 0;
	while (np < size - 1 && str[sp]) {
		switch (str[sp]) {
		case '%':
			opt = NULL;

			switch (str[sp+1]) {
			case 'd':
				sprintf(buf, "%d", dev_id);
				opt = buf;
				break;

			case 'h':
				opt = main_opts.host_name;
				break;

			case '%':
				dst[np++] = str[sp++];
				/* fall through */
			default:
				sp++;
				continue;
			}

			if (opt) {
				/* substitute */
				olen = strlen(opt);
				if (np + olen < size - 1)
					memcpy(dst + np, opt, olen);
				np += olen;
			}
			sp += 2;
			continue;

		case '\\':
			sp++;
			/* fall through */
		default:
			dst[np++] = str[sp++];
			break;
		}
	}
	dst[np] = '\0';
	return dst;
}

static void init_defaults(void)
{
	/* Default HCId settings */
	memset(&main_opts, 0, sizeof(main_opts));
	main_opts.scan	= SCAN_PAGE;
	main_opts.mode	= MODE_CONNECTABLE;
	main_opts.name	= g_strdup("BlueZ");
	main_opts.discovto	= HCID_DEFAULT_DISCOVERABLE_TIMEOUT;
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
	toggle_debug();
}

static gboolean option_detach = TRUE;
static gboolean option_debug = FALSE;
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

static GOptionEntry options[] = {
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
				"Enable debug information output" },
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

	if (option_udev == TRUE) {
		int err;

		option_detach = TRUE;
		err = hcid_dbus_init();
		if (err < 0) {
			if (err == -EALREADY)
				exit(0);
			exit(1);
		}
	}

	g_option_context_free(context);

	if (option_detach == TRUE && option_udev == FALSE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	umask(0077);

	start_logging("bluetoothd", "Bluetooth daemon %s", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	if (option_debug == TRUE) {
		info("Enabling debug information");
		enable_debug();
	}

	config = load_config(CONFIGDIR "/main.conf");

	parse_config(config);

	agent_init();

	if (option_udev == FALSE) {
		if (hcid_dbus_init() < 0) {
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

	/* Loading plugins has to be done after D-Bus has been setup since
	 * the plugins might wanna expose some paths on the bus. However the
	 * best order of how to init various subsystems of the Bluetooth
	 * daemon needs to be re-worked. */
	plugin_init(config);

	event_loop = g_main_loop_new(NULL, FALSE);

	if (adapter_ops_setup() < 0) {
		error("adapter_ops_setup failed");
		exit(1);
	}

	rfkill_init();

	debug("Entering main loop");

	g_main_loop_run(event_loop);

	hcid_dbus_unregister();

	hcid_dbus_exit();

	rfkill_exit();

	plugin_cleanup();

	stop_sdp_server();

	agent_exit();

	g_main_loop_unref(event_loop);

	if (config)
		g_key_file_free(config);

	info("Exit");

	stop_logging();

	return 0;
}
