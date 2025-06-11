/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  Enable functionality only when the user is active
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

typedef int (*logind_init_cb)(gboolean at_register);
typedef void (*logind_exit_cb)(gboolean at_unregister);

#ifdef SYSTEMD

int logind_register(logind_init_cb init_cb, logind_exit_cb exit_cb);
void logind_unregister(logind_init_cb init_cb, logind_exit_cb exit_cb);
int logind_set(gboolean enabled);

#else

static inline int logind_register(logind_init_cb init_cb,
					logind_exit_cb exit_cb)
{
	return init_cb(TRUE);
}
static inline void logind_unregister(logind_init_cb init_cb,
					logind_exit_cb exit_cb)
{
	return exit_cb(TRUE);
}
static inline int logind_set(gboolean enabled)
{
	return 0;
}

#endif
