// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 */

/*
 * hci_rfkill - generic HW rfkill stack test driver.
 *
 * Applies to any hci_dev with rfkill registered, regardless of vendor or
 * transport (USB, UART, PCIe, virtual, etc.). Many transport drivers (e.g.
 * btintel_pcie) are bound to real hardware and have no userspace-attachable
 * transport to emulate the way emulator/vhci.c does for /dev/vhci. Instead,
 * net/bluetooth's hci_debugfs.c exposes a generic debugfs test hook
 * ("force_hw_rfkill" under /sys/kernel/debug/bluetooth/hciN/) that calls
 * hci_rfkill_set_hw_state() directly. That is the exact same entry point
 * any driver's real HW rfkill interrupt path (e.g. btintel_pcie's
 * MSIX/doorbell flow, or another vendor's equivalent) calls into, so
 * writing this hook exercises the full net/bluetooth rfkill core
 * notification chain (hci_rfkill_set_block() -> HCI_RFKILLED flag ->
 * device power on/off) without needing the driver to assert its real HW
 * rfkill line. This tool writes that hook to simulate the HW rfkill line
 * toggling and reads back both the debugfs state and the corresponding
 * /sys/class/rfkill hard-block state to confirm the hci_dev (and rfkill
 * core) picked up the change.
 *
 * Note: this only covers the net/bluetooth stack side of the flow. The
 * driver-side interrupt/doorbell/register-read logic that decides when to
 * call hci_rfkill_set_hw_state() in the first place is vendor/transport
 * specific and is not exercised by this tool; that still requires real
 * hardware or a transport-level (e.g. PCIe) emulation to test.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <dirent.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"

#define DEBUGFS_PATH "/sys/kernel/debug/bluetooth"
#define RFKILL_CLASS_PATH "/sys/class/rfkill"

static bool verbose;

static void print_verbose(const char *format, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

static int debugfs_hw_rfkill_write(const char *hci_name, bool enable)
{
	char path[128];
	int fd, err;
	char val = enable ? 'Y' : 'N';

	snprintf(path, sizeof(path), DEBUGFS_PATH "/%s/force_hw_rfkill",
							hci_name);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open %s: %s\n", path,
							strerror(errno));
		return err;
	}

	if (write(fd, &val, sizeof(val)) != sizeof(val)) {
		err = -errno;
		fprintf(stderr, "Failed to write %s: %s\n", path,
							strerror(errno));
		close(fd);
		return err;
	}

	close(fd);

	return 0;
}

static int debugfs_hw_rfkill_read(const char *hci_name, bool *enable)
{
	char path[128];
	char buf[8];
	int fd, err;
	ssize_t len;

	snprintf(path, sizeof(path), DEBUGFS_PATH "/%s/force_hw_rfkill",
							hci_name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open %s: %s\n", path,
							strerror(errno));
		return err;
	}

	memset(buf, 0, sizeof(buf));
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len < 1)
		return -EIO;

	*enable = (buf[0] == 'Y');

	return 0;
}

/* Locate the /sys/class/rfkill/rfkillN entry whose "name" matches the given
 * hci device name (e.g. "hci0") and read back its hard-block state.
 */
static int rfkill_class_hard_read(const char *hci_name, bool *blocked)
{
	DIR *dir;
	struct dirent *entry;
	int ret = -ENOENT;
	int val;

	dir = opendir(RFKILL_CLASS_PATH);
	if (!dir)
		return -errno;

	while ((entry = readdir(dir)) != NULL) {
		char path[PATH_MAX];
		char name[64];
		FILE *f;

		if (strncmp(entry->d_name, "rfkill", 6))
			continue;

		snprintf(path, sizeof(path), RFKILL_CLASS_PATH "/%s/name",
							entry->d_name);

		f = fopen(path, "r");
		if (!f)
			continue;

		memset(name, 0, sizeof(name));
		if (!fgets(name, sizeof(name), f)) {
			fclose(f);
			continue;
		}
		fclose(f);

		name[strcspn(name, "\n")] = '\0';

		if (strcmp(name, hci_name))
			continue;

		snprintf(path, sizeof(path), RFKILL_CLASS_PATH "/%s/hard",
							entry->d_name);

		f = fopen(path, "r");
		if (!f) {
			ret = -errno;
			break;
		}

		if (fscanf(f, "%d", &val) == 1) {
			*blocked = (val != 0);
			ret = 0;
		} else {
			ret = -EIO;
		}
		fclose(f);
		break;
	}

	closedir(dir);

	return ret;
}

/* Parse the numeric device id out of an "hciN" name without requiring the
 * device to be up (unlike lib/bluetooth's hci_devid(), which internally
 * calls hci_devba() and fails with ENETDOWN on a down/blocked device --
 * exactly the state this tool may have just put the adapter into).
 */
static int hci_name_to_id(const char *hci_name)
{
	const char *p;
	char *end;
	unsigned long id;

	if (strncmp(hci_name, "hci", 3))
		return -1;

	p = hci_name + 3;
	if (!*p)
		return -1;

	while (*p) {
		if (!isdigit((unsigned char)*p))
			return -1;
		p++;
	}

	errno = 0;
	id = strtoul(hci_name + 3, &end, 10);
	if (errno == ERANGE || *end || id > USHRT_MAX)
		return -1;

	return id;
}

/* Query whether the given hci device currently has HCI_UP set, using the
 * same raw HCI control socket + ioctl approach as tools/hciconfig.c.
 */
static int hci_dev_is_up(int hdev_id, bool *up)
{
	struct hci_dev_info di;
	int ctl, err;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (ctl < 0)
		return -errno;

	memset(&di, 0, sizeof(di));
	di.dev_id = hdev_id;

	if (ioctl(ctl, HCIGETDEVINFO, (void *) &di) < 0) {
		err = -errno;
		close(ctl);
		return err;
	}

	close(ctl);

	*up = !!(di.flags & (1U << HCI_UP));

	return 0;
}

/* Bring the given hci device up or down via HCIDEVUP/HCIDEVDOWN, mirroring
 * tools/hciconfig.c's cmd_up()/cmd_down(). Used to restore the adapter to
 * its pre-test state, since unblocking HW rfkill does not automatically
 * reopen the device (that is normally done by bluetoothd reacting to the
 * rfkill unblock event via mgmt).
 */
static int hci_dev_set_up(int hdev_id, bool up)
{
	int ctl, err;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (ctl < 0)
		return -errno;

	if (ioctl(ctl, up ? HCIDEVUP : HCIDEVDOWN, hdev_id) < 0) {
		err = -errno;
		close(ctl);
		/* HCIDEVUP returns EALREADY if the device is already up
		 * (mirrors tools/hciconfig.c's cmd_up()); HCIDEVDOWN has
		 * no such case.
		 */
		return (up && err == -EALREADY) ? 0 : err;
	}

	close(ctl);

	return 0;
}

static int run_test(const char *hci_name, bool enable, bool *write_succeeded)
{
	bool val;
	int err;

	*write_succeeded = false;
	printf("Setting HW rfkill %s on %s\n", enable ? "ON" : "OFF",
								hci_name);

	err = debugfs_hw_rfkill_write(hci_name, enable);
	if (err)
		return err;
	*write_succeeded = true;

	err = debugfs_hw_rfkill_read(hci_name, &val);
	if (err) {
		fprintf(stderr, "Failed to read back debugfs state: %s\n",
							strerror(-err));
		return err;
	}

	if (val != enable) {
		fprintf(stderr, "debugfs force_hw_rfkill mismatch: wrote %d, "
					"read %d\n", enable, val);
		return -EIO;
	}

	print_verbose("debugfs force_hw_rfkill now reports: %s\n",
						val ? "Y" : "N");

	err = rfkill_class_hard_read(hci_name, &val);
	if (err) {
		fprintf(stderr, "Failed to read rfkill class state for %s: "
					"%s\n", hci_name, strerror(-err));
		return err;
	}

	print_verbose("rfkill class hard-block state: %s\n",
						val ? "blocked" : "unblocked");

	if (val != enable) {
		fprintf(stderr, "rfkill class state mismatch: expected "
					"%s, got %s\n",
					enable ? "blocked" : "unblocked",
					val ? "blocked" : "unblocked");
		return -EIO;
	}

	printf("OK: hci_dev and rfkill class agree HW rfkill is %s\n",
						enable ? "ON" : "OFF");

	return 0;
}

static void usage(void)
{
	printf("hci_rfkill - generic HW rfkill stack test driver\n"
		"Usage:\n");
	printf("\thci_rfkill [options] <hciN>\n");
	printf("options:\n"
		"\t-t, --toggle       Toggle HW rfkill on then off "
							"(default)\n"
		"\t-e, --enable       Only assert HW rfkill (block)\n"
		"\t-d, --disable      Only de-assert HW rfkill (unblock)\n"
		"\t-r, --restore      Restore the adapter to its pre-test\n"
		"\t                   up/down state afterwards (unblocking\n"
		"\t                   HW rfkill does not reopen the device\n"
		"\t                   on its own; that is normally done by\n"
		"\t                   bluetoothd reacting to the rfkill\n"
		"\t                   event via mgmt). Note: combined with\n"
		"\t                   -e, restoring an adapter that was up\n"
		"\t                   will fail with ERFKILL, since it is\n"
		"\t                   left HW-blocked on purpose\n"
		"\t-v, --verbose      Show verbose output\n"
		"\t-h, --help         Show help options\n");
}

static const struct option main_options[] = {
	{ "toggle",	no_argument,	NULL, 't' },
	{ "enable",	no_argument,	NULL, 'e' },
	{ "disable",	no_argument,	NULL, 'd' },
	{ "restore",	no_argument,	NULL, 'r' },
	{ "verbose",	no_argument,	NULL, 'v' },
	{ "help",	no_argument,	NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *hci_name;
	int mode = 't';
	bool restore = false;
	int opt;
	int hdev_id = -1;
	bool was_up = false;
	bool have_pre_state = false;
	bool write_succeeded;
	int ret = EXIT_SUCCESS;
	int err;

	while ((opt = getopt_long(argc, argv, "tedrvh",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 't':
		case 'e':
		case 'd':
			mode = opt;
			break;
		case 'r':
			restore = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			usage();
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage();
		return EXIT_FAILURE;
	}

	hci_name = argv[0];

	hdev_id = hci_name_to_id(hci_name);
	if (hdev_id < 0) {
		fprintf(stderr, "Invalid hci device name %s\n", hci_name);
		return EXIT_FAILURE;
	}

	if (restore) {
		err = hci_dev_is_up(hdev_id, &was_up);
		if (err) {
			fprintf(stderr, "Failed to query %s up state: %s\n",
						hci_name, strerror(-err));
			return EXIT_FAILURE;
		}

		have_pre_state = true;
		print_verbose("%s pre-test state: %s\n", hci_name,
						was_up ? "up" : "down");
	}

	switch (mode) {
	case 'e':
		if (run_test(hci_name, true, &write_succeeded))
			ret = EXIT_FAILURE;
		break;
	case 'd':
		if (run_test(hci_name, false, &write_succeeded))
			ret = EXIT_FAILURE;
		break;
	case 't':
	default:
		err = run_test(hci_name, true, &write_succeeded);
		if (err)
			ret = EXIT_FAILURE;
		if (write_succeeded) {
			if (run_test(hci_name, false, &write_succeeded))
				ret = EXIT_FAILURE;
		}
		break;
	}

	if (restore && have_pre_state) {
		err = hci_dev_set_up(hdev_id, was_up);
		if (err) {
			fprintf(stderr, "Failed to restore %s to its "
					"pre-test %s state: %s\n", hci_name,
					was_up ? "up" : "down",
					strerror(-err));
			ret = EXIT_FAILURE;
		} else {
			print_verbose("%s restored to pre-test state: %s\n",
					hci_name, was_up ? "up" : "down");
		}
	}

	return ret;
}
