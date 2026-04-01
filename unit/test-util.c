// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Bastien Nocera <hadess@hadess.net>
 *
 *
 */

#include <assert.h>

#include "src/shared/util.h"
#include "src/shared/tester.h"

/* XXX glib.h must not be included, or it will clobber the
 * MIN/MAX macros.
 */

static void test_min_max(const void *data)
{
	assert(MIN(3, 4) == 3);
	assert(MAX(3, 4) == 4);
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/util/min_max", NULL, NULL,
			test_min_max, NULL);

	return tester_run();
}
