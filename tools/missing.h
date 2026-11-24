// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  Khem Raj <raj.khem@gmail.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if !HAVE_DECL_BASENAME
#include <string.h>
static inline const char *basename(const char *path)
{
	const char *base = strrchr(path, '/');

	return base ? base + 1 : path;
}
#endif
