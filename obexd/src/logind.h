/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  Enable functionality only when the user is active
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef SYSTEMD

typedef int (*logind_init_cb)(void);
typedef void (*logind_exit_cb)(void);

int logind_register(logind_init_cb init_cb, logind_exit_cb exit_cb);
void logind_unregister(logind_init_cb init_cb, logind_exit_cb exit_cb);
int logind_set(gboolean enabled);

#else

#define logind_register(init_cb, exit_cb) init_cb()
#define logind_unregister(init_cb, exit_cb) exit_cb()
#define logind_set(enabled) 0

#endif
