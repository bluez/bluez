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

struct str2utf8_data {
	const char *input;	/* Not NUL terminated, len bytes are used */
	size_t len;
	const char *expected;
};

#define FFFD "\xef\xbf\xbd"		/* U+FFFD REPLACEMENT CHARACTER */

static const struct str2utf8_data str2utf8_tests[] = {
	/* Nothing to do */
	{ "", 0, "" },
	{ "Pixel 7", 7, "Pixel 7" },
	/* Well-formed multi-byte sequences are kept as they are */
	{ "\xe2\x82\xac 5", 5, "\xe2\x82\xac 5" },		/* U+20AC */
	{ "\xf0\x9f\x94\x8a", 4, "\xf0\x9f\x94\x8a" },		/* U+1F50A */
	/* Leading and trailing whitespace is removed */
	{ "  spaced  ", 10, "spaced" },
	{ "\t\r\nname\n\r\t", 10, "name" },
	{ "   ", 3, "" },
	/* The name is not NUL terminated, only len bytes are used */
	{ "truncated", 4, "trun" },
	/* A byte that can never appear in UTF-8 */
	{ "ab\xff""cd", 5, "ab" FFFD "cd" },
	/* A continuation byte cannot start a sequence */
	{ "ab\x80""cd", 5, "ab" FFFD "cd" },
	/* One U+FFFD per maximal subpart, not per byte */
	{ "ab\xe2\x82""cd", 6, "ab" FFFD "cd" },
	/* A sequence cut short by len is still one maximal subpart */
	{ "ab\xe2\x82\xac", 4, "ab" FFFD },
	/* Latin-1 text is not valid UTF-8 */
	{ "caf\xe9", 4, "caf" FFFD },
	/* Overlong encodings are rejected, C0 and C1 are never valid */
	{ "\xc0\x80", 2, FFFD FFFD },
	{ "\xc0\xaf", 2, FFFD FFFD },
	/* UTF-16 surrogates have no UTF-8 encoding */
	{ "\xed\xa0\x80", 3, FFFD FFFD FFFD },
	/* U+10FFFF is the last code point, F5 to FF are out of range */
	{ "\xf4\x90\x80\x80", 4, FFFD FFFD FFFD FFFD },
	{ "\xf5\x80\x80\x80", 4, FFFD FFFD FFFD FFFD },
	/* The last code point itself is fine */
	{ "\xf4\x8f\xbf\xbf", 4, "\xf4\x8f\xbf\xbf" },
	/* Replacement and stripping combined */
	{ " \xff ", 3, FFFD },
};

static void test_str2utf8(const void *data)
{
	size_t i;

	for (i = 0; i < sizeof(str2utf8_tests) /
				sizeof(str2utf8_tests[0]); i++) {
		const struct str2utf8_data *test = &str2utf8_tests[i];
		char *str = str2utf8((const uint8_t *) test->input,
								test->len);

		assert(str);
		if (strcmp(str, test->expected)) {
			printf("test %zu: expected \"%s\", got \"%s\"\n", i,
							test->expected, str);
			free(str);
			tester_test_failed();
			return;
		}

		/* The result is always well-formed UTF-8 */
		assert(strisutf8(str, strlen(str)));

		free(str);
	}

	tester_test_passed();
}

static void test_str2utf8_null(const void *data)
{
	assert(!str2utf8(NULL, 0));
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
	tester_add("/util/str2utf8", NULL, NULL,
			test_str2utf8, NULL);
	tester_add("/util/str2utf8_null", NULL, NULL,
			test_str2utf8_null, NULL);

	return tester_run();
}
