// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

/* Stub replacement for daemon main.c for tests */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

#include "../src/btd.h"

struct btd_opts btd_opts;

GKeyFile *btd_get_main_conf(void)
{
	return NULL;
}

bool btd_kernel_experimental_enabled(const char *uuid)
{
	return false;
}

void btd_exit(void)
{
}
