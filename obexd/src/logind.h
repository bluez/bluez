/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  Enable functionality only when the user is active
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifndef OBEXD_SRC_LOGIND_H
#define OBEXD_SRC_LOGIND_H

struct logind_cb_context {
	const char *state;
	int seats;
	int res;
};

typedef void (*logind_cb)(gpointer ctxt);

#ifdef SYSTEMD

/*
 * Register callback and call it with the current state
 */
int logind_register(logind_cb init_cb);
/*
 * Unregister callback but DO NOT call it -
 * unregistration usually happens when the user is logging out,
 * and other programs are going away.
 *
 * If possible, close resources at exit instead of at unregister.
 * Otherwise, you will need to explicitly call your callback.
 */
void logind_unregister(logind_cb cb);
/*
 * Override the detected login state
 */
int logind_set(gboolean enabled);

/* Recommended way to detect (in)activity */
#define LOGIND_USER_IS_ACTIVE(ctxt) \
	(!g_strcmp0(ctxt->state, "active") && !!(ctxt->seats))

#else /* SYSTEMD */

static inline int logind_register(logind_cb cb)
{
	(void)cb;
	struct logind_cb_context ctxt = {
		.state = "active",
		.seats = 1,
		.res = 0
	};
	cb(&ctxt);
	return ctxt.res;
}
static inline void logind_unregister(logind_cb cb)
{
	(void)cb;
}
static inline int logind_set(gboolean enabled)
{
	return 0;
}

#define LOGIND_USER_IS_ACTIVE(...) 1

#endif /* SYSTEMD */

#endif /* OBEXD_SRC_LOGIND_H */
