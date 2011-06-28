/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#include <stdint.h>
#include <string.h>

#include <glib.h>

#include "util.h"

GQuark test_error_quark(void)
{
	return g_quark_from_static_string("test-error-quark");
}

static void dump_bytes(const uint8_t *buf, size_t buf_len)
{
	size_t i;

	for (i = 0; i < buf_len; i++)
		g_printerr("%02x ", buf[i]);

	g_printerr("\n");
}

void dump_bufs(const void *mem1, size_t len1, const void *mem2, size_t len2)
{
	g_printerr("\nExpected: ");
	dump_bytes(mem1, len1);
	g_printerr("Got:      ");
	dump_bytes(mem2, len2);
}

void assert_memequal(const void *mem1, size_t len1,
						const void *mem2, size_t len2)
{
	if (len1 == len2 && memcmp(mem1, mem2, len1) == 0)
		return;

	dump_bufs(mem1, len1, mem2, len2);

	g_assert(0);
}
