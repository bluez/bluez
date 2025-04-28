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
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>

#include <systemd/sd-login.h>

#include "obexd/src/log.h"
#include "obexd/src/logind.h"

static sd_login_monitor * monitor;
static int uid;
static gboolean active = FALSE;
static gboolean monitoring_enabled = TRUE;
static guint source;

struct callback_pair {
	logind_init_cb init_cb;
	logind_exit_cb exit_cb;
};

GSList *callbacks;

static void call_init_cb(gpointer data, gpointer user_data)
{
	int res;

	res = ((struct callback_pair *)data)->init_cb();
	if (res)
		*(int *)user_data = res;
}
static void call_exit_cb(gpointer data, gpointer user_data)
{
	((struct callback_pair *)data)->exit_cb();
}

static int update(void)
{
	char *state = NULL;
	gboolean state_is_active;
	int res;

	res = sd_login_monitor_flush(monitor);
	if (res < 0)
		return res;
	res = sd_uid_get_state(uid, &state);
	state_is_active = g_strcmp0(state, "active");
	free(state);
	if (res < 0)
		return res;

	if (state_is_active) {
		if (!active)
			return 0;
	} else {
		res = sd_uid_get_seats(uid, 1, NULL);
		if (res < 0)
			return res;
		if (active == !!res)
			return 0;
	}
	active ^= TRUE;
	res = 0;
	g_slist_foreach(callbacks, active ? call_init_cb : call_exit_cb, &res);
	return res;
}

static gboolean event_handler(GIOChannel *source, GIOCondition condition,
				gpointer data)
{
	int res;

	res = sd_login_monitor_flush(monitor);
	if (res < 0) {
		error("sd_login_monitor_flush(): %s", strerror(-res));
		return FALSE;
	}
	if (!monitoring_enabled)
		return TRUE;
	res = update();
	if (res < 0) {
		error("update(): %s", strerror(-res));
		return FALSE;
	}
	return TRUE;
}

static gboolean timeout_handler(gpointer user_data)
{
	uint64_t timeout_usec;
	int res;

	if (!event_handler(NULL, 0, NULL))
		return FALSE;

	res = sd_login_monitor_get_timeout(monitor, &timeout_usec);
	if (res < 0) {
		error("sd_login_monitor_get_timeout(): %s", strerror(-res));
		return FALSE;
	}

	if (timeout_usec != (uint64_t)-1) {
		uint64_t time_usec;
		struct timespec ts;

		res = clock_gettime(CLOCK_MONOTONIC, &ts);
		if (res < 0)
			return -errno;
		time_usec = (uint64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
		if (time_usec > timeout_usec)
			return timeout_handler(user_data);
		g_timeout_add((timeout_usec - time_usec + 999) / 1000,
				timeout_handler, user_data);
	}

	return FALSE;
}

static int logind_init(void)
{
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

	// Check this after creating the monitor, in case of race conditions:
	res = update();
	if (res < 0)
		goto FAIL;

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

	source = g_io_add_watch(channel, events, event_handler, NULL);

	g_io_channel_unref(channel);

	timeout_handler(NULL);

	return 0;

FAIL:
	sd_login_monitor_unref(monitor);
	monitoring_enabled = FALSE;
	active = TRUE;
	return res;
}

static void logind_exit(void)
{
	if (source) {
		g_source_remove(source);
		source = 0;
	}
	sd_login_monitor_unref(monitor);
}

static gint find_cb(gconstpointer a, gconstpointer b)
{
	return ((struct callback_pair *)a)->init_cb - (logind_init_cb)b;
}

int logind_register(logind_init_cb init_cb, logind_exit_cb exit_cb)
{
	struct callback_pair *cbs;

	if (!monitoring_enabled)
		return init_cb();
	if (callbacks == NULL) {
		int res;

		res = logind_init();
		if (res) {
			error("logind_init(): %s - login detection disabled",
				strerror(-res));
			return init_cb();
		}
	}
	cbs = g_new(struct callback_pair, 1);
	cbs->init_cb = init_cb;
	cbs->exit_cb = exit_cb;
	callbacks = g_slist_prepend(callbacks, cbs);
	return active ? init_cb() : 0;
}
void logind_unregister(logind_init_cb init_cb, logind_exit_cb exit_cb)
{
	GSList *cb_node;

	if (!monitoring_enabled)
		return exit_cb();
	if (active)
		exit_cb();
	cb_node = g_slist_find_custom(callbacks, init_cb, find_cb);
	if (cb_node != NULL)
		callbacks = g_slist_delete_link(callbacks, cb_node);
	if (callbacks == NULL)
		logind_exit();
}

int logind_set(gboolean enabled)
{
	int res = 0;

	if (monitoring_enabled == enabled)
		return 0;

	monitoring_enabled = enabled;
	if (enabled) {
		active = FALSE;
		return update();
	}

	active = TRUE;
	g_slist_foreach(callbacks, call_exit_cb, &res);
	return res;
}

#endif
