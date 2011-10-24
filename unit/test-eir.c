/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation
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

#include <check.h>

#include <stdint.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>

#include "eir.h"

START_TEST(test_basic)
{
	struct eir_data data;
	unsigned char buf[HCI_MAX_EIR_LENGTH];
	int err;

	memset(buf, 0, sizeof(buf));
	memset(&data, 0, sizeof(data));

	err = eir_parse(&data, buf, HCI_MAX_EIR_LENGTH);
	ck_assert(err == 0);
	ck_assert(data.services == NULL);
	ck_assert(data.name == NULL);

	eir_data_free(&data);
}
END_TEST

static void add_test(Suite *s, const char *name, TFun func)
{
	TCase *t;

	t = tcase_create(name);
	tcase_add_test(t, func);
	suite_add_tcase(s, t);
}

int main(int argc, char *argv[])
{
	int fails;
	SRunner *sr;
	Suite *s;

	s = suite_create("EIR");

	add_test(s, "basic", test_basic);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	fails = srunner_ntests_failed(sr);

	srunner_free(sr);

	if (fails > 0)
		return -1;

	return 0;
}
