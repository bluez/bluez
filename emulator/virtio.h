/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#include <stdbool.h>

struct vtio;

struct vtio *vtio_open(enum btdev_type type, const char *path);
void vtio_close(struct vtio *vtio);

typedef void (*vtio_debug_func_t)(const char *str, void *user_data);
bool vtio_set_debug(struct vtio *vtio,
			vtio_debug_func_t callback, void *user_data);
