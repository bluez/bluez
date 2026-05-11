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
#include <sys/stat.h>
#include <fcntl.h>

#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "bluetooth/bluetooth.h"

/* XXX glib.h must not be included, or it will clobber the
 * MIN/MAX macros.
 */

static void test_cleanup_free(const void *data)
{
	_cleanup_free_ char *p1 = NULL;
	_cleanup_free_ char *p2 = NULL;
	_cleanup_free_ char *is_null = NULL;

	p1 = malloc0(10);
	p2 = malloc0(15);

	p1[0] = 1;
	p2[0] = 1;

	{
		_cleanup_free_ uint8_t *data = NULL;
		_cleanup_free_ uint8_t *is_null_too = NULL;

		data = malloc0(128);
		data[0] = 1;

		assert(is_null_too == NULL);
	}
	{
		_cleanup_free_ uint8_t *data = NULL;
		data = malloc0(128 * 2);
		data[0] = 3;
	}

	assert(is_null == NULL);
	tester_test_passed();
}

CLEANUP_FREEFUNC(bdaddr_t, free);

static void test_cleanup_type(const void *data)
{
#define ADDR "FF:FF:FF:FF:FF:FF"
	_cleanup_type_(bdaddr_t) bdaddr_t *address = NULL;
	char str[33];

	address = strtoba(ADDR);
	assert(bacmp(address, BDADDR_ALL) == 0);
	printf("%d = ba2str(address, str)\n", ba2str(address, str));
	assert(ba2str(address, str) == 17);
	assert(strcmp(str, ADDR) == 0);
	tester_test_passed();
}

static void test_cleanup_fd(const void *data)
{
	_cleanup_fd_ int fd = -1;

	fd = open("/dev/null", O_RDONLY);
	assert(fd != 0);
	tester_test_passed();
}

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
	tester_add("/util/cleanup_free", NULL, NULL,
			test_cleanup_free, NULL);
	tester_add("/util/cleanup_type", NULL, NULL,
			test_cleanup_type, NULL);
	tester_add("/util/cleanup_fd", NULL, NULL,
			test_cleanup_fd, NULL);

	return tester_run();
}
