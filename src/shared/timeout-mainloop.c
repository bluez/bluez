// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdlib.h>

#include "mainloop.h"
#include "util.h"
#include "timeout.h"

struct timeout_data {
	int id;
	timeout_func_t func;
	timeout_destroy_func_t destroy;
	unsigned int timeout;
	void *user_data;
	bool running;
	bool removed;
};

static void timeout_callback(int id, void *user_data)
{
	struct timeout_data *data = user_data;
	bool ret;

	data->running = true;
	ret = data->func(data->user_data);
	data->running = false;

	/* The callback removed the timeout, so data was only kept around to
	 * be checked here and its id may already be reused.
	 */
	if (data->removed) {
		free(data);
		return;
	}

	if (ret && !mainloop_modify_timeout(data->id, data->timeout))
		return;

	mainloop_remove_timeout(data->id);
}

static void timeout_destroy(void *user_data)
{
	struct timeout_data *data = user_data;

	if (data->destroy)
		data->destroy(data->user_data);

	if (data->running) {
		data->removed = true;
		return;
	}

	free(data);
}

unsigned int timeout_add(unsigned int timeout, timeout_func_t func,
			void *user_data, timeout_destroy_func_t destroy)
{
	struct timeout_data *data;

	data = new0(struct timeout_data, 1);
	data->func = func;
	data->user_data = user_data;
	data->timeout = timeout;
	data->destroy = destroy;

	/* A timeout of 0 runs as soon as the mainloop gets to it, as with the
	 * other backends, while mainloop_add_timeout() leaves it disarmed.
	 */
	if (timeout)
		data->id = mainloop_add_timeout(timeout, timeout_callback, data,
							timeout_destroy);
	else
		data->id = mainloop_add_idle(timeout_callback, data,
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

	mainloop_remove_timeout((int) id);
}

unsigned int timeout_add_seconds(unsigned int timeout, timeout_func_t func,
			void *user_data, timeout_destroy_func_t destroy)
{
	return timeout_add(timeout * 1000, func, user_data, destroy);
}
