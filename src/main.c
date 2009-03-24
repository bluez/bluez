/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

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
#include "storage.h"

#define HCID_DEFAULT_DISCOVERABLE_TIMEOUT 180 /* 3 minutes */

enum {
	HCID_SET_NAME,
	HCID_SET_CLASS,
	HCID_SET_PAGETO,
	HCID_SET_DISCOVTO,
};

struct main_opts main_opts;

static int child_pipe[2];

static gboolean starting = TRUE;

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
		debug("inqmode=%d", val);
		main_opts.inqmode = val;
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

	main_opts.link_mode = HCI_LM_ACCEPT;

	main_opts.link_policy = HCI_LP_RSWITCH | HCI_LP_SNIFF |
						HCI_LP_HOLD | HCI_LP_PARK;
}

static void update_service_classes(const bdaddr_t *bdaddr, uint8_t value)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, sk;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return;

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		close(sk);
		g_free(dl);
		return;
	}

	dr = dl->dev_req;

	for (i = 0; i < dl->dev_num; i++, dr++) {
		struct hci_dev_info di;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		if (!hci_test_bit(HCI_UP, &di.flags))
			continue;

		if (bacmp(bdaddr, BDADDR_ANY) != 0 &&
				bacmp(bdaddr, &di.bdaddr) != 0)
			continue;

		manager_update_adapter(di.dev_id, value, starting);
	}

	g_free(dl);

	close(sk);
}

/*
 * Device name expansion
 *   %d - device id
 */
static char *expand_name(char *dst, int size, char *str, int dev_id)
{
	register int sp, np, olen;
	char *opt, buf[10];

	if (!str && !dst)
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

static gboolean child_exit(GIOChannel *io, GIOCondition cond, void *user_data)
{
	int status, fd = g_io_channel_unix_get_fd(io);
	pid_t child_pid;

	if (read(fd, &child_pid, sizeof(child_pid)) != sizeof(child_pid)) {
		error("child_exit: unable to read child pid from pipe");
		return TRUE;
	}

	if (waitpid(child_pid, &status, 0) != child_pid)
		error("waitpid(%d) failed", child_pid);
	else
		debug("child %d exited", child_pid);

	return TRUE;
}

static void at_child_exit(void)
{
	pid_t pid = getpid();

	if (write(child_pipe[1], &pid, sizeof(pid)) != sizeof(pid))
		error("unable to write to child pipe");
}

static void configure_device(int dev_id)
{
	struct hci_dev_info di;
	uint16_t policy;
	int dd;

	if (hci_devinfo(dev_id, &di) < 0)
		return;

	if (hci_test_bit(HCI_RAW, &di.flags))
		return;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d: %s (%d)",
						dev_id, strerror(errno), errno);
		return;
	}

	/* Set device name */
	if ((main_opts.flags & (1 << HCID_SET_NAME)) && main_opts.name) {
		change_local_name_cp cp;

		memset(cp.name, 0, sizeof(cp.name));
		expand_name((char *) cp.name, sizeof(cp.name),
						main_opts.name, dev_id);

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
					CHANGE_LOCAL_NAME_CP_SIZE, &cp);
	}

	/* Set device class */
	if ((main_opts.flags & (1 << HCID_SET_CLASS))) {
		write_class_of_dev_cp cp;
		uint32_t class;
		uint8_t cls[3];

		if (read_local_class(&di.bdaddr, cls) < 0) {
			class = htobl(main_opts.class);
			cls[2] = get_service_classes(&di.bdaddr);
			memcpy(cp.dev_class, &class, 3);
		} else {
			if (!(main_opts.scan & SCAN_INQUIRY))
				cls[1] &= 0xdf; /* Clear discoverable bit */
			cls[2] = get_service_classes(&di.bdaddr);
			memcpy(cp.dev_class, cls, 3);
		}

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
					WRITE_CLASS_OF_DEV_CP_SIZE, &cp);
	}

	/* Set page timeout */
	if ((main_opts.flags & (1 << HCID_SET_PAGETO))) {
		write_page_timeout_cp cp;

		cp.timeout = htobs(main_opts.pageto);
		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT,
					WRITE_PAGE_TIMEOUT_CP_SIZE, &cp);
	}

	/* Set default link policy */
	policy = htobs(main_opts.link_policy);
	hci_send_cmd(dd, OGF_LINK_POLICY,
				OCF_WRITE_DEFAULT_LINK_POLICY, 2, &policy);

	hci_close_dev(dd);
}

static void init_device(int dev_id)
{
	struct hci_dev_req dr;
	struct hci_dev_info di;
	pid_t pid;
	int dd;

	/* Do initialization in the separate process */
	pid = fork();
	switch (pid) {
		case 0:
			atexit(at_child_exit);
			break;
		case -1:
			error("Fork failed. Can't init device hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		default:
			debug("child %d forked", pid);
			return;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		exit(1);
	}

	memset(&dr, 0, sizeof(dr));
	dr.dev_id = dev_id;

	/* Set link mode */
	dr.dev_opt = main_opts.link_mode;
	if (ioctl(dd, HCISETLINKMODE, (unsigned long) &dr) < 0) {
		error("Can't set link mode on hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
	}

	/* Set link policy */
	dr.dev_opt = main_opts.link_policy;
	if (ioctl(dd, HCISETLINKPOL, (unsigned long) &dr) < 0 &&
							errno != ENETDOWN) {
		error("Can't set link policy on hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
	}

	/* Start HCI device */
	if (ioctl(dd, HCIDEVUP, dev_id) < 0 && errno != EALREADY) {
		error("Can't init device hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		goto fail;
	}

	if (hci_devinfo(dev_id, &di) < 0)
		goto fail;

	if (hci_test_bit(HCI_RAW, &di.flags))
		goto done;

done:
	hci_close_dev(dd);
	exit(0);

fail:
	hci_close_dev(dd);
	exit(1);
}

static void device_devreg_setup(int dev_id, gboolean devup)
{
	struct hci_dev_info di;

	init_device(dev_id);

	memset(&di, 0, sizeof(di));

	if (hci_devinfo(dev_id, &di) < 0)
		return;

	if (!hci_test_bit(HCI_RAW, &di.flags))
		manager_register_adapter(dev_id, devup);
}

static void device_devup_setup(int dev_id)
{
	configure_device(dev_id);

	start_security_manager(dev_id);

	/* Return value 1 means ioctl(DEVDOWN) was performed */
	if (manager_start_adapter(dev_id) == 1)
		stop_security_manager(dev_id);
}

static void init_all_devices(int ctl)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	dl = g_try_malloc0(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
	if (!dl) {
		info("Can't allocate devlist buffer: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void *) dl) < 0) {
		info("Can't get device list: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		gboolean devup;

		devup = hci_test_bit(HCI_UP, &dr->dev_opt);

		info("HCI dev %d registered", dr->dev_id);
		device_devreg_setup(dr->dev_id, devup);
		if (devup) {
			info("HCI dev %d already up", dr->dev_id);
			device_devup_setup(dr->dev_id);
		}
	}

	g_free(dl);
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

	if (gethostname(main_opts.host_name, sizeof(main_opts.host_name) - 1) < 0)
		strcpy(main_opts.host_name, "noname");
}

static inline void device_event(GIOChannel *chan, evt_stack_internal *si)
{
	evt_si_device *sd = (void *) &si->data;

	switch (sd->event) {
	case HCI_DEV_REG:
		info("HCI dev %d registered", sd->dev_id);
		device_devreg_setup(sd->dev_id, FALSE);
		break;

	case HCI_DEV_UNREG:
		info("HCI dev %d unregistered", sd->dev_id);
		manager_unregister_adapter(sd->dev_id);
		break;

	case HCI_DEV_UP:
		info("HCI dev %d up", sd->dev_id);
		device_devup_setup(sd->dev_id);
		break;

	case HCI_DEV_DOWN:
		info("HCI dev %d down", sd->dev_id);
		manager_stop_adapter(sd->dev_id);
		stop_security_manager(sd->dev_id);
		break;
	}
}

static gboolean io_stack_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	hci_event_hdr *eh;
	int type;
	size_t len;
	GIOError err;

	ptr = buf;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		error("Read from control socket failed: %s (%d)",
							strerror(errno), errno);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	if (eh->evt != EVT_STACK_INTERNAL)
		return TRUE;

	ptr += HCI_EVENT_HDR_SIZE;

	si = (evt_stack_internal *) ptr;
	switch (si->type) {
	case EVT_SI_DEVICE:
		device_event(chan, si);
		break;
	}

	return TRUE;
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

static GOptionEntry options[] = {
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't run as daemon in background" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
				"Enable debug information output" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	struct sockaddr_hci addr;
	struct hci_filter flt;
	struct sigaction sa;
	GIOChannel *ctl_io, *child_io;
	uint16_t mtu = 0;
	GKeyFile *config;

	init_defaults();

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

	if (option_detach == TRUE) {
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

	/* Create and bind HCI socket */
	main_opts.sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (main_opts.sock < 0) {
		error("Can't open HCI socket: %s (%d)", strerror(errno),
								errno);
		exit(1);
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(main_opts.sock, SOL_HCI, HCI_FILTER, &flt,
							sizeof(flt)) < 0) {
		error("Can't set filter: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(main_opts.sock, (struct sockaddr *) &addr,
							sizeof(addr)) < 0) {
		error("Can't bind HCI socket: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	config = load_config(CONFIGDIR "/main.conf");

	parse_config(config);

	if (pipe(child_pipe) < 0) {
		error("pipe(): %s (%d)", strerror(errno), errno);
		exit(1);
	}

	child_io = g_io_channel_unix_new(child_pipe[0]);
	g_io_channel_set_close_on_unref(child_io, TRUE);
	g_io_add_watch(child_io,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			child_exit, NULL);
	g_io_channel_unref(child_io);

	agent_init();

	if (hcid_dbus_init() < 0) {
		error("Unable to get on D-Bus");
		exit(1);
	}

	start_sdp_server(mtu, main_opts.deviceid, SDP_SERVER_COMPAT);
	set_service_classes_callback(update_service_classes);

	/* Loading plugins has to be done after D-Bus has been setup since
	 * the plugins might wanna expose some paths on the bus. However the
	 * best order of how to init various subsystems of the Bluetooth
	 * daemon needs to be re-worked. */
	plugin_init(config);

	event_loop = g_main_loop_new(NULL, FALSE);

	ctl_io = g_io_channel_unix_new(main_opts.sock);
	g_io_channel_set_close_on_unref(ctl_io, TRUE);

	g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	g_io_channel_unref(ctl_io);

	/* Initialize already connected devices */
	init_all_devices(main_opts.sock);

	starting = FALSE;

	manager_startup_complete();

	debug("Entering main loop");

	g_main_loop_run(event_loop);

	hcid_dbus_unregister();

	hcid_dbus_exit();

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
