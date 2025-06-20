// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  Enable functionality only when the user is active
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef SYSTEMD

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>

#include <systemd/sd-login.h>

#include "obexd/src/log.h"
#include "obexd/src/logind.h"

static sd_login_monitor * monitor;
static int uid;
static gboolean monitoring_enabled = TRUE;
static guint event_source;
static guint timeout_source;

GSList *callbacks;

static void call_cb(gpointer data, gpointer user_data)
{
	(*((logind_cb *)data))(user_data);
}

static void logind_cb_context_init(struct logind_cb_context *ctxt)
{
	ctxt->res = sd_login_monitor_flush(monitor);
	if (ctxt->res < 0)
		return;

	ctxt->res = ctxt->seats = sd_uid_get_seats(uid, 1, NULL);
	if (ctxt->res < 0)
		return;

	/*
	 * the documentation for sd_uid_get_state() isn't clear about
	 * what to do with the state on error.  The following should
	 * be safe even if the behaviour changes in future
	 */
	ctxt->state = 0;
	ctxt->res = sd_uid_get_state(uid, (char **)&ctxt->state);
	if (ctxt->res <= 0) {
		free((char *)ctxt->state);
		return;
	}

	ctxt->res = 0;
	return;
}

static gboolean timeout_handler(gpointer user_data);

static int check_event(void)
{
	struct logind_cb_context ctxt;
	uint64_t timeout_usec;
	int res;

	res = sd_login_monitor_flush(monitor);
	if (res < 0)
		return res;
	if (!monitoring_enabled)
		return 0;

	logind_cb_context_init(&ctxt);
	if (ctxt.res)
		return ctxt.res;
	g_slist_foreach(callbacks, call_cb, &ctxt);
	free((char *)ctxt.state);
	if (ctxt.res)
		return ctxt.res;

	res = sd_login_monitor_get_timeout(monitor, &timeout_usec);
	if (res < 0)
		return res;

	if (timeout_usec != (uint64_t)-1) {
		uint64_t time_usec;
		struct timespec ts;
		guint interval;

		res = clock_gettime(CLOCK_MONOTONIC, &ts);
		if (res < 0)
			return -errno;
		time_usec = (uint64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
		if (time_usec > timeout_usec)
			return check_event();
		interval = (timeout_usec - time_usec + 999) / 1000;
		timeout_source = g_timeout_add(interval, timeout_handler, NULL);
	}

	return 0;
}


static gboolean event_handler(GIOChannel *source, GIOCondition condition,
				gpointer data)
{
	int res;

	if (timeout_source) {
		g_source_remove(timeout_source);
		timeout_source = 0;
	}

	res = check_event();
	if (res) {
		error("%s: %s", __func__, strerror(-res));
		return FALSE;
	}

	return TRUE;
}

static gboolean timeout_handler(gpointer user_data)
{
	int res;

	res = check_event();
	if (res)
		error("%s: %s", __func__, strerror(-res));

	return FALSE;
}

static int logind_init(void)
{
	struct logind_cb_context ctxt;
	GIOChannel *channel;
	int events;
	int fd;
	int res;

	monitor = NULL;

	DBG("");

	if (!monitoring_enabled)
		return 0;

	uid = getuid();

	res = sd_login_monitor_new("uid", &monitor);
	if (res < 0) {
		monitor = NULL;
		goto FAIL;
	}

	events = res = sd_login_monitor_get_events(monitor);
	if (res < 0)
		goto FAIL;

	fd = res = sd_login_monitor_get_fd(monitor);
	if (res < 0)
		goto FAIL;

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	event_source = g_io_add_watch(channel, events, event_handler, NULL);

	g_io_channel_unref(channel);

	return check_event();

FAIL:
	sd_login_monitor_unref(monitor);
	monitoring_enabled = FALSE;
	ctxt.state = "active";
	ctxt.seats = 1;
	ctxt.res = 0;
	g_slist_foreach(callbacks, call_cb, &ctxt);
	return res;
}

static void logind_exit(void)
{
	if (event_source) {
		g_source_remove(event_source);
		event_source = 0;
	}
	if (timeout_source) {
		g_source_remove(timeout_source);
		timeout_source = 0;
	}
	sd_login_monitor_unref(monitor);
}

int logind_register(logind_cb cb)
{
	struct logind_cb_context ctxt;

	logind_cb_context_init(&ctxt);
	if (ctxt.res) {
		free((char *)ctxt.state);
		return ctxt.res;
	}

	if (!monitoring_enabled)
		goto CALL_CB;
	if (callbacks == NULL) {
		int res;

		res = logind_init();
		if (res) {
			error("logind_init(): %s - login detection disabled",
				strerror(-res));
			goto CALL_CB;
		}
	}
	callbacks = g_slist_prepend(callbacks, cb);

CALL_CB:
	cb(&ctxt);
	free((char *)ctxt.state);
	return ctxt.res;
}
void logind_unregister(logind_cb cb)
{
	GSList *cb_node;

	if (!monitoring_enabled)
		return;
	cb_node = g_slist_find(callbacks, cb);
	if (cb_node != NULL)
		callbacks = g_slist_delete_link(callbacks, cb_node);
	if (callbacks == NULL)
		logind_exit();
}

int logind_set(gboolean enabled)
{
	monitoring_enabled = enabled;
	if (enabled) {
		struct logind_cb_context ctxt;

		logind_cb_context_init(&ctxt);
		if (ctxt.res)
			return ctxt.res;
		g_slist_foreach(callbacks, call_cb, &ctxt);
		free((char *)ctxt.state);
		return ctxt.res;
	}

	struct logind_cb_context ctxt = {
		.state = "active",
		.seats = 1,
		.res = 0
	};

	g_slist_foreach(callbacks, call_cb, &ctxt);
	return ctxt.res;
}

#endif
