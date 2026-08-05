// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"

#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/log.h"
#include "src/sdp-xml.h"

static void parse_xml(gconstpointer data, gsize len)
{
	sdp_record_t *rec = NULL;

	rec = sdp_xml_parse_record(data, len);
	if (rec) {
		tester_test_passed();
		sdp_record_free(rec);
	} else {
		tester_test_failed();
	}
}

static void parse_xml_for_filename(gconstpointer data)
{
	const char *filename = (const char *) data;
	char *path = NULL;
	GError *error = NULL;
	char *contents = NULL;
	gsize len;

	path = g_build_filename(TOP_SRCDIR, "unit", "sdp-xml", filename, NULL);
	if (!g_file_get_contents(path, &contents, &len, &error)) {
		g_warning("Can't load file '%s': %s", path, error->message);
		g_free(path);
		g_error_free(error);
		tester_test_failed();
	}
	parse_xml(contents, len);
	g_free(contents);
	g_free(path);
}

#define DEFINE_TEST(fname)							\
	tester_add("/" fname, fname, NULL, parse_xml_for_filename, NULL);

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	DEFINE_TEST("Bluetooth_HID-sdp_record.xml");
	DEFINE_TEST("qt-SerialPortSDPRecord.xml");

	return tester_run();
}
