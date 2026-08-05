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

struct test_data {
	GString *s;
	char *filename;
	gboolean expected_result;
};

static void parse_xml(gconstpointer data, gsize len, gboolean expected_result)
{
	sdp_record_t *rec = NULL;
	gboolean ret;

	rec = sdp_xml_parse_record(data, len);
	ret = rec ? TRUE : FALSE;
	if (ret == expected_result)
		tester_test_passed();
	else
		tester_test_failed();
	if (rec)
		sdp_record_free(rec);
}

static void parse_xml_for_filename(gconstpointer data)
{
	struct test_data *t = (struct test_data *) data;
	char *path = NULL;
	GError *error = NULL;
	char *contents = NULL;
	gsize len;

	path = g_build_filename(TOP_SRCDIR, "unit", "sdp-xml", t->filename, NULL);
	if (!g_file_get_contents(path, &contents, &len, &error)) {
		g_warning("Can't load file '%s': %s", path, error->message);
		g_free(path);
		g_error_free(error);
		tester_test_failed();
	}
	parse_xml(contents, len, t->expected_result);
	g_free(contents);
	g_free(path);
}

#define DEFINE_TEST(fname, res)							\
	data.expected_result = res;						\
	data.filename = fname;							\
	tester_add("/" fname, &data, NULL, parse_xml_for_filename, NULL);

int main(int argc, char *argv[])
{
	struct test_data data;

	tester_init(&argc, &argv);

	DEFINE_TEST("Bluetooth_HID-sdp_record.xml", TRUE);
	DEFINE_TEST("qt-SerialPortSDPRecord.xml", TRUE);

	return tester_run();
}
