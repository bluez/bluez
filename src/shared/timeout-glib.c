/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#include "timeout.h"

#include <glib.h>

struct timeout_data {
	timeout_func_t func;
	timeout_destroy_func_t destroy;
	void *user_data;
};

static gboolean timeout_callback(gpointer user_data)
{
	struct timeout_data *data  = user_data;

	if (data->func(data->user_data))
		return TRUE;

	return FALSE;
}

static void timeout_destroy(gpointer user_data)
{
	struct timeout_data *data = user_data;

	if (data->destroy)
		data->destroy(data->user_data);

	g_free(data);
}

int timeout_add(unsigned int ms, timeout_func_t func, void *user_data,
						timeout_destroy_func_t destroy)
{
	guint id;
	struct timeout_data *data = g_malloc0(sizeof(*data));

	data->func = func;
	data->destroy = destroy;
	data->user_data = user_data;

	id = g_timeout_add_full(G_PRIORITY_DEFAULT, ms, timeout_callback, data,
							timeout_destroy);
	if (!id)
		g_free(data);

	return id;
}

void timeout_remove(unsigned int id)
{
	GSource *source = g_main_context_find_source_by_id(NULL, id);
	if (source)
		g_source_destroy(source);
}
