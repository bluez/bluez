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

enum {
	TEST_ERROR_TIMEOUT,
	TEST_ERROR_UNEXPECTED,
};

#define TEST_ERROR test_error_quark()
GQuark test_error_quark(void);

void dump_bufs(const void *mem1, size_t len1, const void *mem2, size_t len2);
void assert_memequal(const void *mem1, size_t len1,
						const void *mem2, size_t len2);
