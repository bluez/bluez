/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <glib.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"

static void test_basic(void)
{
	struct queue *queue;
	unsigned int n, i;

	queue = queue_new();
	g_assert(queue != NULL);

	for (n = 0; n < 1024; n++) {
		for (i = 1; i < n + 2; i++)
			queue_push_tail(queue, UINT_TO_PTR(i));

		g_assert(queue_length(queue) == n + 1);

		for (i = 1; i < n + 2; i++) {
			void *ptr;

			ptr = queue_pop_head(queue);
			g_assert(ptr != NULL);
			g_assert(i == PTR_TO_UINT(ptr));
		}

		g_assert(queue_isempty(queue) == true);
	}

	queue_destroy(queue, NULL);
}

static void foreach_destroy(void *data, void *user_data)
{
	struct queue *queue = user_data;

	queue_destroy(queue, NULL);
}

static void test_foreach_destroy(void)
{
	struct queue *queue;

	queue = queue_new();
	g_assert(queue != NULL);

	queue_push_tail(queue, UINT_TO_PTR(1));
	queue_push_tail(queue, UINT_TO_PTR(2));

	queue_foreach(queue, foreach_destroy, queue);
}

static void foreach_remove_all(void *data, void *user_data)
{
	struct queue *queue = user_data;

	queue_remove_all(queue, NULL, NULL, NULL);
}

static void test_foreach_remove_all(void)
{
	struct queue *queue;

	queue = queue_new();
	g_assert(queue != NULL);

	queue_push_tail(queue, UINT_TO_PTR(1));
	queue_push_tail(queue, UINT_TO_PTR(2));

	queue_foreach(queue, foreach_remove_all, queue);
	queue_destroy(queue, NULL);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/queue/basic", test_basic);
	g_test_add_func("/queue/foreach_destroy", test_foreach_destroy);
	g_test_add_func("/queue/foreach_remove_all", test_foreach_remove_all);

	return g_test_run();
}
