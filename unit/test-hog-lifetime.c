// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Regression for outstanding HID report requests surviving detach.
 * Uses socketpairs and the real HoG/GAttrib/ATT implementation; no hardware.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <glib.h>

#include "profiles/input/hog-lib.c"

static void pump(void)
{
	while (g_main_context_iteration(NULL, FALSE))
		;
}

static void test_report(gconstpointer data)
{
	const char *name = data;
	bool blob = !strcmp(name, "blob");
	bool write_test = !strcmp(name, "write");
	bool normal = !strcmp(name, "normal");
	bool reconnect = !strcmp(name, "reconnect");
	int attfd[2], uhidfd[2];
	GIOChannel *io;
	GAttrib *attrib;
	struct bt_hog *hog;
	struct report *report;
	struct uhid_event ev = { 0 }, reply;
	uint8_t pdu[64];
	uint8_t response[2] = {
		write_test ? 0x13 : blob ? 0x0d : 0x0b, 0x55
	};
	size_t size = write_test ? 1 : 2;
	ssize_t n;

	g_assert_cmpint(socketpair(AF_UNIX,
			SOCK_SEQPACKET | SOCK_NONBLOCK, 0, attfd), ==, 0);
	g_assert_cmpint(socketpair(AF_UNIX,
			SOCK_SEQPACKET | SOCK_NONBLOCK, 0, uhidfd), ==, 0);
	io = g_io_channel_unix_new(attfd[0]);
	g_io_channel_set_close_on_unref(io, TRUE);
	attrib = g_attrib_new(io, 23, false);
	g_io_channel_unref(io);
	hog = bt_hog_new(uhidfd[0], "lifetime-test", 2, 1, 1, 0, NULL);
	g_assert(hog && attrib);
	hog->attrib = g_attrib_ref(attrib);
	report = g_new0(struct report, 1);
	report->hog = hog;
	report->type = HOG_REPORT_TYPE_FEATURE;
	report->value_handle = 0x31;
	hog->reports = g_slist_append(hog->reports, report);

	if (write_test) {
		ev.type = UHID_SET_REPORT;
		ev.u.set_report.id = 123;
		ev.u.set_report.rtype = UHID_FEATURE_REPORT;
		ev.u.set_report.size = 1;
		ev.u.set_report.data[0] = 0x55;
		set_report(&ev, hog);
		g_assert(hog->setrep_att != 0);
	} else {
		ev.type = UHID_GET_REPORT;
		ev.u.get_report.id = 123;
		ev.u.get_report.rtype = UHID_FEATURE_REPORT;
		get_report(&ev, hog);
		g_assert(hog->getrep_att != 0);
	}

	pump();
	n = read(attfd[1], pdu, sizeof(pdu));
	g_assert(n >= 3 && pdu[0] == (write_test ? 0x12 : 0x0a));

	if (blob) {
		uint8_t first[23] = { 0x0b };

		g_assert_cmpint(write(attfd[1], first, sizeof(first)),
						==, sizeof(first));
		pump();
		n = read(attfd[1], pdu, sizeof(pdu));
		g_assert(n == 5 && pdu[0] == 0x0c);
	}

	if (!normal) {
		bt_hog_detach(hog, true);

		if (!reconnect) {
			bt_hog_unref(hog);
			hog = NULL;
		}
	}

	g_assert(write(attfd[1], response, size) == size);
	pump();
	n = read(uhidfd[1], &reply, sizeof(reply));

	if (normal) {
		g_assert(n == sizeof(reply));
		g_assert(reply.type == UHID_GET_REPORT_REPLY);
		g_assert(reply.u.get_report_reply.id == 123);
		g_assert(reply.u.get_report_reply.err == 0);
		g_assert(reply.u.get_report_reply.data[0] == 0x55);
	} else {
		g_assert(n == -1 && errno == EAGAIN);
	}

	if (reconnect) {
		/* Reuse the detached object for another report request. */
		g_assert(hog->getrep_att == 0 && hog->setrep_att == 0);
		hog->attrib = g_attrib_ref(attrib);
		ev.u.get_report.id = 124;
		get_report(&ev, hog);
		pump();
		n = read(attfd[1], pdu, sizeof(pdu));
		g_assert(n == 3 && pdu[0] == 0x0a);
		g_assert(write(attfd[1], response, 2) == 2);
		pump();
		g_assert_cmpint(read(uhidfd[1], &reply, sizeof(reply)),
						==, sizeof(reply));
		g_assert(reply.u.get_report_reply.id == 124);
		g_assert(reply.u.get_report_reply.err == 0);
	}

	if (hog)
		bt_hog_unref(hog);

	g_attrib_unref(attrib);
	close(attfd[1]);
	close(uhidfd[0]);
	close(uhidfd[1]);
	pump();
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/hog/detach/read", "read", test_report);
	g_test_add_data_func("/hog/detach/blob", "blob", test_report);
	g_test_add_data_func("/hog/detach/write", "write", test_report);
	g_test_add_data_func("/hog/normal", "normal", test_report);
	g_test_add_data_func("/hog/reconnect", "reconnect", test_report);

	return g_test_run();
}
