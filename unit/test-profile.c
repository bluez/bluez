// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/tester.h"

#include "src/adapter.h"
#include "src/profile.h"

#define FAIL_TEST() \
	do { tester_warn("%s:%d: failed in %s", __FILE__, __LINE__, __func__); \
		tester_test_failed(); } while (0)

struct test_config {
	const struct btd_profile *profiles;
	unsigned int profiles_count;
	unsigned int shuffle_count;
	const char *cycle_break;
};

struct test_data {
	const struct test_config *cfg;
};

#define define_test(name, _cfg, setup, function)		\
	do {							\
		static struct test_data data;			\
		data.cfg = _cfg;				\
		tester_add(name, &data, setup, function,	\
						test_teardown);	\
	} while (0)

static void test_teardown(const void *user_data)
{
	tester_teardown_complete();
}

#define SORT_PROFILE(expect_pos_, ...) \
	{ .name = UINT_TO_PTR(expect_pos_), __VA_ARGS__ }
#define AFTER(...) \
	.after_services = BTD_PROFILE_UUID_CB(NULL, __VA_ARGS__)

const struct test_config sort_priority = {
	.profiles = (const struct btd_profile []) {
		SORT_PROFILE(3, .priority = 1),
		SORT_PROFILE(4, .priority = 1),
		SORT_PROFILE(1, .priority = 2),
		SORT_PROFILE(5, .priority = 0),
		SORT_PROFILE(2, .priority = 2),
		SORT_PROFILE(6, .priority = 0),
	},
	.profiles_count = 6,
};

const struct test_config sort_after_service = {
	.profiles = (const struct btd_profile []) {
		SORT_PROFILE(4, .priority = 1, AFTER("B", "C")),
		SORT_PROFILE(3, .priority = 1, .remote_uuid = "C"),
		SORT_PROFILE(2, .priority = 2, AFTER("B")),
		SORT_PROFILE(1, .priority = 2, .remote_uuid = "B"),
		SORT_PROFILE(6, .priority = 0),
		SORT_PROFILE(5, .priority = 1, AFTER("invalid")),
	},
	.profiles_count = 6,
};

const struct test_config sort_cycle = {
	.profiles = (const struct btd_profile []) {
		SORT_PROFILE(2, .remote_uuid = "B", AFTER("F")),
		SORT_PROFILE(4, .remote_uuid = "D", AFTER("A", "C")),
		SORT_PROFILE(5, .remote_uuid = "E", AFTER("D")),
		SORT_PROFILE(3, .remote_uuid = "C", AFTER("B")),
		SORT_PROFILE(6, .remote_uuid = "F", AFTER("E")),
		SORT_PROFILE(1, .remote_uuid = "A"),
	},
	.profiles_count = 6,
	.cycle_break = "F",
};

const struct test_config sort_fuzz = {
	.profiles_count = 50,
	.shuffle_count = 100,
};

static const struct btd_profile *sort_get(void *item, void *user_data)
{
	return item;
}

static bool check_sort(struct queue *list, unsigned int count,
							const char *cycle_break)
{
	int priority = INT_MAX;
	GHashTable *uuids, *items;
	const struct queue_entry *entry;
	unsigned int n;

	uuids = g_hash_table_new(g_str_hash, g_str_equal);
	items = g_hash_table_new(NULL, NULL);

	if (queue_length(list) != count) {
		FAIL_TEST();
		return false;
	}

	for (entry = queue_get_entries(list), n = 0; entry;
						entry = entry->next, ++n) {
		const struct btd_profile *profile = entry->data;

		g_hash_table_add(uuids, (void *)profile->remote_uuid);
	}

	if (cycle_break)
		g_hash_table_remove(uuids, (void *)cycle_break);

	for (entry = queue_get_entries(list), n = 0; entry;
						entry = entry->next, ++n) {
		const struct btd_profile *profile = entry->data;
		unsigned int i;

		/* No duplicates */
		if (g_hash_table_contains(items, profile)) {
			FAIL_TEST();
			return false;
		}
		g_hash_table_add(items, (void *)profile);

		/* Decreasing priority */
		if (profile->priority > priority) {
			FAIL_TEST();
			return false;
		} else if (profile->priority < priority) {
			priority = profile->priority;
		}

		/* Ordered by after_services */
		g_hash_table_remove(uuids, (void *)profile->remote_uuid);

		for (i = 0; i < profile->after_services.count; ++i) {
			if (g_hash_table_contains(uuids,
					profile->after_services.uuids[i])) {
				FAIL_TEST();
				return false;
			}
		}

		/* Manual sort check */
		if (profile->name && profile->name != UINT_TO_PTR(n + 1)) {
			FAIL_TEST();
			return false;
		}
	}

	g_hash_table_destroy(uuids);
	g_hash_table_destroy(items);

	return true;
}

static struct queue *make_profile_list(const struct btd_profile *profiles,
							unsigned int count)
{
	struct queue *list = queue_new();
	unsigned int i;

	for (i = 0; i < count; ++i) {
		struct btd_profile *profile;

		profile = util_memdup(&profiles[i], sizeof(*profile));
		if (profile->remote_uuid)
			profile->remote_uuid = g_strdup(profile->remote_uuid);
		else
			profile->remote_uuid = g_strdup_printf("%d", i);

		queue_push_tail(list, profile);
	}

	return list;
}

static void free_profile_list(struct queue *list)
{
	const struct queue_entry *entry;

	for (entry = queue_get_entries(list); entry; entry = entry->next) {
		const struct btd_profile *profile = entry->data;

		g_free((void *)profile->remote_uuid);
		free((void *)profile);
	}

	queue_destroy(list, NULL);
}

static void *queue_peek_nth(struct queue *list, unsigned int i)
{
	const struct queue_entry *entry;
	unsigned int n = 0;

	for (entry = queue_get_entries(list); entry; entry = entry->next, n++) {
		if (n == i)
			return entry->data;
	}

	return NULL;
}

static void shuffle_list(struct queue *list)
{
	struct queue *shuffled = queue_new();

	while (!queue_isempty(list)) {
		int i = g_random_int_range(0, queue_length(list));
		void *data = queue_peek_nth(list, i);

		queue_remove(list, data);
		queue_push_tail(shuffled, data);
	}

	/* Put back to original list */
	while (!queue_isempty(shuffled))
		queue_push_tail(list, queue_pop_head(shuffled));
	queue_destroy(shuffled, NULL);
}

static void btd_profile_sort(struct queue *queue, btd_profile_list_get get,
							void *user_data)
{
	const struct queue_entry *entry;
	GSList *list = NULL, *item;

	for (entry = queue_get_entries(queue); entry; entry = entry->next)
		list = g_slist_append(list, entry->data);

	list = btd_profile_sort_list(list, get, user_data);

	queue_remove_all(queue, NULL, NULL, NULL);

	for (item = list; item; item = item->next)
		queue_push_tail(queue, item->data);

	g_slist_free(list);
}

static void test_sort(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	const struct test_config *cfg = data->cfg;
	struct queue *list;

	list = make_profile_list(cfg->profiles, cfg->profiles_count);

	btd_profile_sort(list, sort_get, NULL);
	check_sort(list, cfg->profiles_count, cfg->cycle_break);

	free_profile_list(list);
	tester_test_passed();
}

static void test_sort_fuzz(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	const struct test_config *cfg = data->cfg;
	unsigned int i, j;

	for (i = 0; i < cfg->shuffle_count; ++i) {
		struct queue *list;
		struct btd_profile profiles[64] = { 0 };
		char *uuids[64];

		g_random_set_seed(i);

		for (j = 0; j < ARRAY_SIZE(uuids); ++j)
			uuids[j] = g_strdup_printf("%d", j);

		for (j = 0; j < cfg->profiles_count; ++j) {
			int count;

			profiles[j].priority = 3 - 3 * j / cfg->profiles_count;

			if (g_random_int_range(0, 3) == 0 || j == 0)
				continue;

			count = g_random_int_range(1, j + 1);
			if (count > 5)
				count = 5;
			profiles[j].after_services.count = count;
			profiles[j].after_services.uuids = (const char **)uuids
				+ g_random_int_range(0, j + 1 - count);
		}

		list = make_profile_list(profiles, cfg->profiles_count);
		shuffle_list(list);

		btd_profile_sort(list, sort_get, NULL);
		if (!check_sort(list, cfg->profiles_count, NULL))
			return;

		free_profile_list(list);

		for (j = 0; j < ARRAY_SIZE(uuids); ++j)
			g_free(uuids[j]);
	}

	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	define_test("Sort Priority - Success", &sort_priority, NULL, test_sort);
	define_test("Sort After Service - Success", &sort_after_service, NULL,
								test_sort);
	define_test("Sort Cycle - Success", &sort_cycle, NULL, test_sort);
	define_test("Sort Fuzz - Success", &sort_fuzz, NULL, test_sort_fuzz);

	return tester_run();
}
