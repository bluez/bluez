// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

/* Timeouts for btvirt: on the simulated clock of the time travel calendar
 * when it is enabled, otherwise on the mainloop like
 * src/shared/timeout-mainloop.c.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"

#include "timetravel.h"

/* Calendar timer IDs are kept apart from the mainloop ones */
#define TT_TIMEOUT_ID	0x80000000U

struct timeout_data {
	int id;
	timeout_func_t func;
	timeout_destroy_func_t destroy;
	unsigned int timeout;
	void *user_data;
};

static void timeout_callback(int id, void *user_data)
{
	struct timeout_data *data = user_data;

	if (data->func(data->user_data) &&
			!mainloop_modify_timeout(data->id, data->timeout))
		return;

	mainloop_remove_timeout(data->id);
}

static void timeout_destroy(void *user_data)
{
	struct timeout_data *data = user_data;

	if (data->destroy)
		data->destroy(data->user_data);

	free(data);
}

unsigned int timeout_add(unsigned int timeout, timeout_func_t func,
			void *user_data, timeout_destroy_func_t destroy)
{
	struct timeout_data *data;

	if (tt_enabled())
		return TT_TIMEOUT_ID | tt_timeout_add(timeout, func, user_data,
								destroy);

	data = new0(struct timeout_data, 1);
	data->func = func;
	data->user_data = user_data;
	data->timeout = timeout;
	data->destroy = destroy;

	data->id = mainloop_add_timeout(timeout, timeout_callback, data,
							timeout_destroy);
	if (data->id < 0) {
		free(data);
		return 0;
	}

	return (unsigned int) data->id;
}

void timeout_remove(unsigned int id)
{
	if (!id)
		return;

	if (id & TT_TIMEOUT_ID) {
		tt_timeout_remove(id & ~TT_TIMEOUT_ID);
		return;
	}

	mainloop_remove_timeout((int) id);
}

unsigned int timeout_add_seconds(unsigned int timeout, timeout_func_t func,
			void *user_data, timeout_destroy_func_t destroy)
{
	return timeout_add(timeout * 1000, func, user_data, destroy);
}
