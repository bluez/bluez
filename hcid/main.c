/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "dbus-common.h"
#include "dbus-service.h"
#include "dbus-database.h"
#include "dbus-hci.h"
#include "device.h"
#include "agent.h"

struct hcid_opts hcid;
struct device_opts default_device;
struct device_opts *parser_device;
static struct device_list *device_list = NULL;
static int child_pipe[2];

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static inline void init_device_defaults(struct device_opts *device_opts)
{
	memset(device_opts, 0, sizeof(*device_opts));
	device_opts->scan = SCAN_PAGE;
	device_opts->mode = MODE_CONNECTABLE;
	device_opts->name = g_strdup("BlueZ");
	device_opts->discovto = HCID_DEFAULT_DISCOVERABLE_TIMEOUT;
}

struct device_opts *alloc_device_opts(char *ref)
{
	struct device_list *device;

	device = g_try_new(struct device_list, 1);
	if (!device) {
		info("Can't allocate devlist opts buffer: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	device->ref = g_strdup(ref);
	device->next = device_list;
	device_list = device;

	memcpy(&device->opts, &default_device, sizeof(struct device_opts));
	device->opts.name = g_strdup(default_device.name);

	return &device->opts;
}

static void free_device_opts(void)
{
	struct device_list *device, *next;

	g_free(default_device.name);

	for (device = device_list; device; device = next) {
		g_free(device->ref);
		g_free(device->opts.name);
		next = device->next;
		g_free(device);
	}

	device_list = NULL;
}

static inline struct device_opts *find_device_opts(char *ref)
{
	struct device_list *device;

	for (device = device_list; device; device = device->next)
		if (!strcmp(ref, device->ref))
			return &device->opts;

	return NULL;
}

static struct device_opts *get_device_opts(int hdev)
{
	struct device_opts *device_opts = NULL;
	struct hci_dev_info di;

	/* First try to get BD_ADDR based settings ... */
	if (hci_devinfo(hdev, &di) == 0) {
		char addr[18];
		ba2str(&di.bdaddr, addr);
		device_opts = find_device_opts(addr);
	}

	/* ... then try HCI based settings ... */
	if (!device_opts) {
		char ref[8];
		snprintf(ref, sizeof(ref) - 1, "hci%d", hdev);
		device_opts = find_device_opts(ref);
	}

	/* ... and last use the default settings. */
	if (!device_opts)
		device_opts = &default_device;

	return device_opts;
}

static struct device_opts *get_opts(int hdev)
{
	struct device_opts *device_opts = NULL;
	struct hci_dev_info di;
	char addr[18];
	int sock;

	if (hdev < 0)
		return NULL;

	sock = hci_open_dev(hdev);
	if (sock < 0)
		goto no_address;

	if (hci_devinfo(hdev, &di) < 0) {
		close(sock);
		goto no_address;
	}

	close(sock);

	ba2str(&di.bdaddr, addr);
	device_opts = find_device_opts(addr);

no_address:
	if (!device_opts) {
		char ref[8];
		snprintf(ref, sizeof(ref) - 1, "hci%d", hdev);
		device_opts = find_device_opts(ref);
	}

	if (!device_opts)
		device_opts = &default_device;

	return device_opts;
}

uint8_t get_startup_scan(int hdev)
{
	struct device_opts *device_opts = get_opts(hdev);
	if (!device_opts)
		return SCAN_DISABLED;

	return device_opts->scan;
}

uint8_t get_startup_mode(int hdev)
{
	struct device_opts *device_opts = get_opts(hdev);
	if (!device_opts)
		return MODE_OFF;

	return device_opts->mode;
}

int get_discoverable_timeout(int hdev)
{
	struct device_opts *device_opts = NULL;
	struct hci_dev_info di;
	char addr[18];
	int sock, timeout;

	if (hdev < 0)
		return HCID_DEFAULT_DISCOVERABLE_TIMEOUT;

	sock = hci_open_dev(hdev);
	if (sock < 0)
		goto no_address;

	if (hci_devinfo(hdev, &di) < 0) {
		close(sock);
		goto no_address;
	}

	close(sock);

	if (read_discoverable_timeout(&di.bdaddr, &timeout) == 0)
		return timeout;

	ba2str(&di.bdaddr, addr);
	device_opts = find_device_opts(addr);

no_address:
	if (!device_opts) {
		char ref[8];
		snprintf(ref, sizeof(ref) - 1, "hci%d", hdev);
		device_opts = find_device_opts(ref);
	}

	if (!device_opts)
		device_opts = &default_device;

	return device_opts->discovto;
}

void update_service_classes(const bdaddr_t *bdaddr, uint8_t value)
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
		uint8_t cls[3];
		int dd;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		if (!hci_test_bit(HCI_UP, &di.flags))
			continue;

		if (get_device_class(di.dev_id, cls) < 0)
			continue;

		dd = hci_open_dev(di.dev_id);
		if (dd < 0)
			continue;

		set_service_classes(dd, cls, value);

		hci_close_dev(dd);

		update_adapter(di.dev_id);
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
				opt = hcid.host_name;
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
	struct device_opts *device_opts;
	struct hci_dev_req dr;
	struct hci_dev_info di;
	char mode[14];
	int dd;

	device_opts = get_device_opts(dev_id);

	if (hci_devinfo(dev_id, &di) < 0)
		return;

	if (hci_test_bit(HCI_RAW, &di.flags))
		return;

	/* Set default discoverable timeout if not set */
	if (!(device_opts->flags & (1 << HCID_SET_DISCOVTO)))
		device_opts->discovto = HCID_DEFAULT_DISCOVERABLE_TIMEOUT;

	/* Set scan mode */
	if (read_device_mode(&di.bdaddr, mode, sizeof(mode)) == 0) {
		if (!strcmp(mode, "off") && hcid.offmode == HCID_OFFMODE_NOSCAN) {
			device_opts->mode = MODE_OFF;
			device_opts->scan = SCAN_DISABLED;
		} else if (!strcmp(mode, "connectable")) {
			device_opts->mode = MODE_CONNECTABLE;
			device_opts->scan = SCAN_PAGE;
		} else if (!strcmp(mode, "discoverable")) {
			/* Set discoverable only if timeout is 0 */
			if (!get_discoverable_timeout(dev_id)) {
				device_opts->scan = SCAN_PAGE | SCAN_INQUIRY;
				device_opts->mode = MODE_DISCOVERABLE;
			} else {
				device_opts->scan = SCAN_PAGE;
				device_opts->mode = MODE_CONNECTABLE;
			}
		} else if (!strcmp(mode, "limited")) {
			/* Set discoverable only if timeout is 0 */
			if (!get_discoverable_timeout(dev_id)) {
				device_opts->scan = SCAN_PAGE | SCAN_INQUIRY;
				device_opts->mode = MODE_LIMITED;
			} else {
				device_opts->scan = SCAN_PAGE;
				device_opts->mode = MODE_CONNECTABLE;
			}
		}
	}

	/* Do configuration in the separate process */
	switch (fork()) {
		case 0:
			atexit(at_child_exit);
			break;
		case -1:
			error("Fork failed. Can't init device hci%d: %s (%d)",
						dev_id, strerror(errno), errno);
		default:
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

	/* Set packet type */
	if ((device_opts->flags & (1 << HCID_SET_PTYPE))) {
		dr.dev_opt = device_opts->pkt_type;
		if (ioctl(dd, HCISETPTYPE, (unsigned long) &dr) < 0) {
			error("Can't set packet type on hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		}
	}

	/* Set link mode */
	if ((device_opts->flags & (1 << HCID_SET_LM))) {
		dr.dev_opt = device_opts->link_mode;
		if (ioctl(dd, HCISETLINKMODE, (unsigned long) &dr) < 0) {
			error("Can't set link mode on hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		}
	}

	/* Set link policy */
	if ((device_opts->flags & (1 << HCID_SET_LP))) {
		dr.dev_opt = device_opts->link_policy;
		if (ioctl(dd, HCISETLINKPOL, (unsigned long) &dr) < 0) {
			error("Can't set link policy on hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		}
	}

	/* Set device name */
	if ((device_opts->flags & (1 << HCID_SET_NAME)) && device_opts->name) {
		change_local_name_cp cp;

		memset(cp.name, 0, sizeof(cp.name));
		expand_name((char *) cp.name, sizeof(cp.name),
						device_opts->name, dev_id);

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
					CHANGE_LOCAL_NAME_CP_SIZE, &cp);
	}

	/* Set device class */
	if ((device_opts->flags & (1 << HCID_SET_CLASS))) {
		write_class_of_dev_cp cp;
		uint32_t class;
		uint8_t cls[3];

		if (read_local_class(&di.bdaddr, cls) < 0) {
			class = htobl(device_opts->class);
			cls[2] = get_service_classes(&di.bdaddr);
			memcpy(cp.dev_class, &class, 3);
		} else {
			if (!(device_opts->scan & SCAN_INQUIRY))
				cls[1] &= 0xdf; /* Clear discoverable bit */
			cls[2] = get_service_classes(&di.bdaddr);
			memcpy(cp.dev_class, cls, 3);
		}

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
					WRITE_CLASS_OF_DEV_CP_SIZE, &cp);
	}

	/* Set page timeout */
	if ((device_opts->flags & (1 << HCID_SET_PAGETO))) {
		write_page_timeout_cp cp;

		cp.timeout = htobs(device_opts->pageto);
		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT,
					WRITE_PAGE_TIMEOUT_CP_SIZE, &cp);
	}

	/* Set voice setting */
	if ((device_opts->flags & (1 << HCID_SET_VOICE))) {
		write_voice_setting_cp cp;

		cp.voice_setting = htobl(device_opts->voice);
		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_VOICE_SETTING,
					WRITE_VOICE_SETTING_CP_SIZE, &cp);
	}

	exit(0);
}

static void init_device(int dev_id)
{
	struct hci_dev_info di;
	int dd;

	/* Do initialization in the separate process */
	switch (fork()) {
		case 0:
			atexit(at_child_exit);
			break;
		case -1:
			error("Fork failed. Can't init device hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		default:
			return;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		exit(1);
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

	if (hcid.offmode == HCID_OFFMODE_DEVDOWN) {
		char mode[16];

		if (read_device_mode(&di.bdaddr, mode, sizeof(mode)) == 0 &&
						strcmp(mode, "off") == 0) {
			ioctl(dd, HCIDEVDOWN, dev_id);
			goto done;
		}
	}

done:
	hci_close_dev(dd);
	exit(0);

fail:
	hci_close_dev(dd);
	exit(1);
}

static void device_devreg_setup(int dev_id)
{
	struct hci_dev_info di;

	if (hcid.auto_init)
		init_device(dev_id);

	if (hci_devinfo(dev_id, &di) < 0)
		return;

	if (!hci_test_bit(HCI_RAW, &di.flags))
		hcid_dbus_register_device(dev_id);
}

static void device_devup_setup(int dev_id)
{
	add_adapter(dev_id);
	if (hcid.auto_init)
		configure_device(dev_id);
	if (hcid.security)
		start_security_manager(dev_id);
	start_adapter(dev_id);
	hcid_dbus_start_device(dev_id);
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
		info("HCI dev %d registered", dr->dev_id);
		device_devreg_setup(dr->dev_id);
		if (hci_test_bit(HCI_UP, &dr->dev_opt)) {
			info("HCI dev %d already up", dr->dev_id);
			device_devup_setup(dr->dev_id);
		}
	}

	g_free(dl);
}

static void init_defaults(void)
{
	hcid.auto_init = 1;
	hcid.security  = HCID_SEC_AUTO;

	init_device_defaults(&default_device);
}

static inline void device_event(GIOChannel *chan, evt_stack_internal *si)
{
	evt_si_device *sd = (void *) &si->data;

	switch (sd->event) {
	case HCI_DEV_REG:
		info("HCI dev %d registered", sd->dev_id);
		device_devreg_setup(sd->dev_id);
		break;

	case HCI_DEV_UNREG:
		info("HCI dev %d unregistered", sd->dev_id);
		hcid_dbus_unregister_device(sd->dev_id);
		remove_adapter(sd->dev_id);
		break;

	case HCI_DEV_UP:
		info("HCI dev %d up", sd->dev_id);
		device_devup_setup(sd->dev_id);
		break;

	case HCI_DEV_DOWN:
		info("HCI dev %d down", sd->dev_id);
		hcid_dbus_stop_device(sd->dev_id);
		if (hcid.security)
			stop_security_manager(sd->dev_id);
		stop_adapter(sd->dev_id);
		break;
	}
}

static gboolean io_stack_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	hci_event_hdr *eh;
	int type;
	size_t len;
	GIOError err;

	ptr = buf;

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
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

static void sig_hup(int sig)
{
	info("Reloading config file");

	free_device_opts();

	init_defaults();

	if (read_config(hcid.config_file) < 0)
		error("Config reload failed");

	init_security_data();

	init_all_devices(hcid.sock);
}

static void sig_debug(int sig)
{
	toggle_debug();
}

static void usage(void)
{
	printf("hcid - HCI daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\thcid [-n] [-d] [-m mtu] [-f config file]\n");
}

int main(int argc, char *argv[])
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	struct sigaction sa;
	GIOChannel *ctl_io, *child_io;
	uint16_t mtu = 0;
	int opt, daemonize = 1, debug = 0, sdp = 1, experimental = 0;
	GKeyFile *config;

	/* Default HCId settings */
	memset(&hcid, 0, sizeof(hcid));
	hcid.auto_init   = 1;
	hcid.config_file = HCID_CONFIG_FILE;
	hcid.security    = HCID_SEC_AUTO;
	hcid.pairing     = HCID_PAIRING_MULTI;
	hcid.offmode     = HCID_OFFMODE_NOSCAN;

	if (gethostname(hcid.host_name, sizeof(hcid.host_name) - 1) < 0)
		strcpy(hcid.host_name, "noname");

	strcpy((char *) hcid.pin_code, "BlueZ");
	hcid.pin_len = 5;

	init_defaults();

	while ((opt = getopt(argc, argv, "ndsm:xf:")) != EOF) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'd':
			debug = 1;
			break;

		case 's':
			sdp = 1;
			break;

		case 'm':
			mtu = atoi(optarg);
			break;

		case 'x':
			experimental = 1;
			break;

		case 'f':
			hcid.config_file = g_strdup(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (daemonize && daemon(0, 0)) {
		error("Can't daemonize: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	umask(0077);

	start_logging("hcid", "Bluetooth HCI daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	if (debug) {
		info("Enabling debug information");
		enable_debug();
	}

	/* Create and bind HCI socket */
	if ((hcid.sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		error("Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(hcid.sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		error("Can't set filter: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(hcid.sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind HCI socket: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	config = load_config(CONFIGDIR "/main.conf");

	if (read_config(hcid.config_file) < 0)
		error("Config load failed");

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

	init_adapters();

	agent_init();

	if (experimental)
		hcid_dbus_set_experimental();

	if (hcid_dbus_init() < 0) {
		error("Unable to get on D-Bus");
		exit(1);
	}

	start_sdp_server(mtu, hcid.deviceid, SDP_SERVER_COMPAT);
	set_service_classes_callback(update_service_classes);

	/* Loading plugins has to be done after D-Bus has been setup since
	 * the plugins might wanna expose some paths on the bus. However the
	 * best order of how to init various subsystems of the Bluetooth
	 * daemon needs to be re-worked. */
	plugin_init(config);

	init_security_data();

	event_loop = g_main_loop_new(NULL, FALSE);

	ctl_io = g_io_channel_unix_new(hcid.sock);
	g_io_channel_set_close_on_unref(ctl_io, TRUE);

	g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	g_io_channel_unref(ctl_io);

	/* Initialize already connected devices */
	init_all_devices(hcid.sock);

	g_main_loop_run(event_loop);

	hcid_dbus_unregister();

	plugin_cleanup();

	stop_sdp_server();

	free_device_opts();

	agent_exit();

	hcid_dbus_exit();

	g_main_loop_unref(event_loop);

	if (config)
		g_key_file_free(config);

	info("Exit");

	stop_logging();

	return 0;
}
