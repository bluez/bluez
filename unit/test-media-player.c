// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Collabora Ltd.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus/gdbus.h"

#include "src/shared/tester.h"
#include "src/dbus-common.h"
#include "profiles/audio/player.h"

#define ERROR_INTERFACE	"org.bluez.Error"

#define SERVICE_NAME	"org.bluez.unit.test-media-player"
#define DEVICE_PATH	"/org/bluez/unit/dev_00_00_00_00_00_00"
#define PLAYER_PATH	DEVICE_PATH "/avrcp/player0"
#define NOWPLAYING_PATH	PLAYER_PATH "/NowPlaying/item2"
#define FILESYSTEM_PATH	PLAYER_PATH "/Filesystem/item2"

#define ITEM_UID	2
#define TOTAL_ITEMS	42

struct context {
	DBusConnection *dbus_conn;
	struct media_player *mp;
	DBusPendingCall *pending;
	DBusPendingCall *pending2;
	bool defer_completion;
	unsigned int play_item_calls;
	unsigned int list_items_calls;
	unsigned int expected_play_calls;
	char *play_item_name;
	uint64_t play_item_uid;
	const char *expected_name;
	bool change_scope_on_list;
	bool destroy_on_play;
	bool check_total_items;
	unsigned int total_items_calls;
};

static struct context *context;

static gboolean complete_play_item(gpointer user_data)
{
	if (context == NULL)
		return FALSE;

	/*
	 * Completion has to be deferred until media_item_play() has
	 * returned, since the pending message is only stored once the
	 * play_item callback has succeeded.
	 */
	media_player_play_item_complete(context->mp, 0);

	return FALSE;
}

static gboolean destroy_player(gpointer user_data)
{
	if (context == NULL || context->mp == NULL)
		return FALSE;

	/*
	 * Destroyed from the main loop rather than from the callback, so
	 * that the pending message has already been stored.
	 */
	media_player_destroy(context->mp);
	context->mp = NULL;

	return FALSE;
}

static int test_play_item(struct media_player *mp, const char *name,
					uint64_t uid, void *user_data)
{
	struct context *ctx = user_data;

	ctx->play_item_calls++;
	g_free(ctx->play_item_name);
	ctx->play_item_name = g_strdup(name);
	ctx->play_item_uid = uid;

	if (ctx->destroy_on_play)
		g_idle_add(destroy_player, NULL);
	else if (!ctx->defer_completion)
		g_idle_add(complete_play_item, NULL);

	return 0;
}

static gboolean complete_list_items(gpointer user_data)
{
	if (context == NULL)
		return FALSE;

	/*
	 * A browsed player can be re-addressed at any time, which makes
	 * avrcp call media_player_set_folder() and move the scope while
	 * the ListItems request is still pending.
	 */
	if (context->change_scope_on_list)
		media_player_set_folder(context->mp, "/Other", 1);

	media_player_list_complete(context->mp, NULL, 0);

	return FALSE;
}

static int test_list_items(struct media_player *mp, const char *name,
			uint32_t start, uint32_t end, void *user_data)
{
	struct context *ctx = user_data;

	ctx->list_items_calls++;

	if (!ctx->defer_completion)
		g_idle_add(complete_list_items, NULL);

	return 0;
}

static void call_get_number_of_items(DBusPendingCall **pending,
					DBusPendingCallNotifyFunction notify);
static void number_of_items_reply(DBusPendingCall *call, void *user_data);

static gboolean complete_total_items(gpointer user_data)
{
	if (context == NULL)
		return FALSE;

	media_player_total_items_complete(context->mp, TOTAL_ITEMS);

	call_get_number_of_items(&context->pending2, number_of_items_reply);

	return FALSE;
}

static int test_search(struct media_player *mp, const char *string,
							void *user_data)
{
	return 0;
}

static int test_total_items(struct media_player *mp, const char *name,
							void *user_data)
{
	struct context *ctx = user_data;

	ctx->total_items_calls++;

	if (ctx->check_total_items)
		g_idle_add(complete_total_items, NULL);

	return 0;
}

static const struct media_player_callback test_callbacks = {
	.play_item = test_play_item,
	.list_items = test_list_items,
	.total_items = test_total_items,
	.search = test_search,
};

static struct context *create_context(void)
{
	struct context *ctx = g_new0(struct context, 1);
	DBusError err;

	dbus_error_init(&err);

	ctx->dbus_conn = g_dbus_setup_private(DBUS_BUS_SESSION, SERVICE_NAME,
									&err);
	if (ctx->dbus_conn == NULL) {
		if (dbus_error_is_set(&err)) {
			tester_debug("D-Bus setup failed: %s", err.message);
			dbus_error_free(&err);
		}

		g_free(ctx);
		tester_test_abort();
		return NULL;
	}

	/* Avoid D-Bus library calling _exit() before next test finishes. */
	dbus_connection_set_exit_on_disconnect(ctx->dbus_conn, FALSE);

	g_dbus_attach_object_manager(ctx->dbus_conn);

	set_dbus_connection(ctx->dbus_conn);

	ctx->mp = media_player_controller_create(DEVICE_PATH, "avrcp", 0);
	g_assert(ctx->mp != NULL);

	media_player_set_callbacks(ctx->mp, &test_callbacks, ctx);

	return ctx;
}

static void destroy_context(void)
{
	if (context == NULL)
		return;

	if (context->pending) {
		dbus_pending_call_cancel(context->pending);
		dbus_pending_call_unref(context->pending);
	}

	if (context->pending2) {
		dbus_pending_call_cancel(context->pending2);
		dbus_pending_call_unref(context->pending2);
	}

	if (context->mp)
		media_player_destroy(context->mp);

	set_dbus_connection(NULL);

	g_dbus_detach_object_manager(context->dbus_conn);

	dbus_connection_flush(context->dbus_conn);
	dbus_connection_close(context->dbus_conn);
	dbus_connection_unref(context->dbus_conn);

	g_free(context->play_item_name);
	g_free(context);
	context = NULL;
}

static void play_reply(DBusPendingCall *call, void *user_data)
{
	struct context *ctx = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (reply == NULL) {
		tester_warn("Play() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("Play() returned error: %s",
					dbus_message_get_error_name(reply));
		goto failed;
	}

	if (ctx->play_item_calls != 1) {
		tester_warn("play_item called %u times, expected 1",
						ctx->play_item_calls);
		goto failed;
	}

	if (g_strcmp0(ctx->play_item_name, ctx->expected_name)) {
		tester_warn("play_item name is '%s', expected '%s'",
				ctx->play_item_name, ctx->expected_name);
		goto failed;
	}

	if (ctx->play_item_uid != ITEM_UID) {
		tester_warn("play_item uid is %" PRIu64 ", expected %u",
					ctx->play_item_uid, ITEM_UID);
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

/* The first Play() of the busy test is never completed on purpose. */
static void ignore_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (reply)
		dbus_message_unref(reply);
}

/* The second, overlapping Play() is the one under test here. */
static void busy_reply(DBusPendingCall *call, void *user_data)
{
	struct context *ctx = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (reply == NULL) {
		tester_warn("Play() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("overlapping Play() succeeded, expected an error");
		goto failed;
	}

	if (ctx->play_item_calls != ctx->expected_play_calls) {
		tester_warn("play_item called %u times, expected %u",
				ctx->play_item_calls, ctx->expected_play_calls);
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

/* ListItems must always be answered, even if the scope moved meanwhile. */
static void list_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (reply == NULL) {
		tester_warn("ListItems() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("ListItems() returned error: %s",
					dbus_message_get_error_name(reply));
		dbus_message_unref(reply);
		tester_test_failed();
		return;
	}

	dbus_message_unref(reply);
	tester_test_passed();
}

/* Without a scope org.bluez.MediaFolder1 must not be registered at all. */
static void no_folder_reply(DBusPendingCall *call, void *user_data)
{
	struct context *ctx = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (reply == NULL) {
		tester_warn("ListItems() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("ListItems() succeeded without a scope");
		goto failed;
	}

	if (ctx->list_items_calls != 0) {
		tester_warn("list_items called %u times, expected 0",
						ctx->list_items_calls);
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

/* Destroying the player must answer whatever request is in flight. */
static void destroyed_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *name;

	if (reply == NULL) {
		tester_warn("Play() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("Play() succeeded, expected an error");
		goto failed;
	}

	name = dbus_message_get_error_name(reply);
	if (g_strcmp0(name, ERROR_INTERFACE ".Failed")) {
		tester_warn("Play() failed with '%s', expected '%s'", name,
						ERROR_INTERFACE ".Failed");
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

/* NumberOfItems has to pick up the count reported by the player. */
static void number_of_items_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessageIter iter, var;
	dbus_uint32_t items;

	if (reply == NULL) {
		tester_warn("Get(NumberOfItems) got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("Get(NumberOfItems) returned error: %s",
					dbus_message_get_error_name(reply));
		goto failed;
	}

	if (!dbus_message_iter_init(reply, &iter) ||
			dbus_message_iter_get_arg_type(&iter) !=
							DBUS_TYPE_VARIANT) {
		tester_warn("Get(NumberOfItems) reply is malformed");
		goto failed;
	}

	dbus_message_iter_recurse(&iter, &var);
	if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_UINT32) {
		tester_warn("NumberOfItems is not a uint32");
		goto failed;
	}

	dbus_message_iter_get_basic(&var, &items);

	if (items != TOTAL_ITEMS) {
		tester_warn("NumberOfItems is %u, expected %u", items,
								TOTAL_ITEMS);
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

static void call_get_number_of_items(DBusPendingCall **pending,
					DBusPendingCallNotifyFunction notify)
{
	DBusMessage *msg;
	const char *iface = "org.bluez.MediaFolder1";
	const char *prop = "NumberOfItems";

	msg = dbus_message_new_method_call(SERVICE_NAME, PLAYER_PATH,
				"org.freedesktop.DBus.Properties", "Get");
	g_assert(msg != NULL);

	g_assert(dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
						DBUS_TYPE_STRING, &prop,
						DBUS_TYPE_INVALID));

	g_assert(dbus_connection_send_with_reply(context->dbus_conn, msg,
							pending, 2000));
	g_assert(*pending != NULL);

	g_assert(dbus_pending_call_set_notify(*pending, notify, context, NULL));

	dbus_message_unref(msg);
}

/* A busy Search() has to report the same error as its siblings. */
static void search_busy_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *desc;

	if (reply == NULL) {
		tester_warn("Search() got no reply");
		tester_test_failed();
		return;
	}

	if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR) {
		tester_warn("Search() succeeded, expected an error");
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &desc,
							DBUS_TYPE_INVALID)) {
		tester_warn("Search() error carries no description");
		goto failed;
	}

	if (g_strcmp0(desc, strerror(EBUSY))) {
		tester_warn("Search() failed with '%s', expected '%s'", desc,
							strerror(EBUSY));
		goto failed;
	}

	dbus_message_unref(reply);
	tester_test_passed();
	return;

failed:
	dbus_message_unref(reply);
	tester_test_failed();
}

static void call_search(DBusPendingCall **pending,
					DBusPendingCallNotifyFunction notify)
{
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	const char *string = "needle";

	msg = dbus_message_new_method_call(SERVICE_NAME, PLAYER_PATH,
					"org.bluez.MediaFolder1", "Search");
	g_assert(msg != NULL);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &string);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
	dbus_message_iter_close_container(&iter, &dict);

	g_assert(dbus_connection_send_with_reply(context->dbus_conn, msg,
							pending, 2000));
	g_assert(*pending != NULL);

	g_assert(dbus_pending_call_set_notify(*pending, notify, context, NULL));

	dbus_message_unref(msg);
}

static void call_list_items(DBusPendingCall **pending,
					DBusPendingCallNotifyFunction notify)
{
	DBusMessage *msg;
	DBusMessageIter iter, dict;

	msg = dbus_message_new_method_call(SERVICE_NAME, PLAYER_PATH,
					"org.bluez.MediaFolder1", "ListItems");
	g_assert(msg != NULL);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
	dbus_message_iter_close_container(&iter, &dict);

	g_assert(dbus_connection_send_with_reply(context->dbus_conn, msg,
							pending, 2000));
	g_assert(*pending != NULL);

	g_assert(dbus_pending_call_set_notify(*pending, notify, context, NULL));

	dbus_message_unref(msg);
}

static void call_play(const char *path, DBusPendingCall **pending,
					DBusPendingCallNotifyFunction notify)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(SERVICE_NAME, path,
						"org.bluez.MediaItem1", "Play");
	g_assert(msg != NULL);

	g_assert(dbus_connection_send_with_reply(context->dbus_conn, msg,
							pending, 2000));
	g_assert(*pending != NULL);

	g_assert(dbus_pending_call_set_notify(*pending, notify, context, NULL));

	dbus_message_unref(msg);
}

static struct media_item *create_nowplaying_item(void)
{
	g_assert(media_player_create_folder(context->mp, "/NowPlaying",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	media_player_set_playlist(context->mp, "/NowPlaying");

	return media_player_set_playlist_item(context->mp, ITEM_UID);
}

/*
 * A player advertising the NowPlaying feature bit but not the Browsing
 * feature bit gets a /NowPlaying folder holding playable items, while the
 * player scope stays unset because SetBrowsedPlayer is never issued.
 *
 * Playing such an item must not dereference the unset scope.
 */
static void test_play_item_without_scope(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->expected_name = NOWPLAYING_PATH;

	g_assert(create_nowplaying_item() != NULL);

	call_play(NOWPLAYING_PATH, &context->pending, play_reply);
}

static struct media_item *create_filesystem_item(void)
{
	struct media_item *item;

	g_assert(media_player_create_folder(context->mp, "/Filesystem",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	media_player_set_folder(context->mp, "/Filesystem", 1);

	item = media_player_create_item(context->mp, "track",
					PLAYER_ITEM_TYPE_AUDIO, ITEM_UID);
	g_assert(item != NULL);
	media_item_set_playable(item, true);

	return item;
}

/* A browsable player sets a scope, which must keep working. */
static void test_play_item_with_scope(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->expected_name = FILESYSTEM_PATH;

	g_assert(create_filesystem_item() != NULL);

	call_play(FILESYSTEM_PATH, &context->pending, play_reply);
}

/* A Play() issued while another one is still pending must be rejected. */
static void test_play_item_busy(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->expected_name = NOWPLAYING_PATH;
	context->defer_completion = true;
	context->expected_play_calls = 1;

	g_assert(create_nowplaying_item() != NULL);

	call_play(NOWPLAYING_PATH, &context->pending, ignore_reply);
	call_play(NOWPLAYING_PATH, &context->pending2, busy_reply);
}

/*
 * ListItems() and Play() share one pending-request slot per player, so a
 * Play() issued while a ListItems() is still outstanding must be rejected.
 */
static void test_play_item_busy_with_list_items(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->defer_completion = true;
	context->expected_play_calls = 0;

	g_assert(create_filesystem_item() != NULL);

	call_list_items(&context->pending, ignore_reply);
	call_play(FILESYSTEM_PATH, &context->pending2, busy_reply);
}

/*
 * The scope can move while a request is pending, which is what avrcp does
 * on SetBrowsedPlayer. The outstanding ListItems() must still be answered.
 */
static void test_list_items_scope_change(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->change_scope_on_list = true;

	g_assert(media_player_create_folder(context->mp, "/Filesystem",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	g_assert(media_player_create_folder(context->mp, "/Other",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	media_player_set_folder(context->mp, "/Filesystem", 1);

	call_list_items(&context->pending, list_reply);
}

/*
 * Without a scope MediaFolder1 is not registered at all, which is why
 * MediaItem1.Play() was the only entry point reachable with an unset scope.
 */
static void test_no_folder_without_scope(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	g_assert(create_nowplaying_item() != NULL);

	call_list_items(&context->pending, no_folder_reply);
}

/*
 * Destroying a player while a request is still in flight must answer it,
 * rather than leave the caller waiting for the D-Bus timeout.
 */
static void test_play_item_destroy_pending(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->defer_completion = true;
	context->destroy_on_play = true;

	g_assert(create_nowplaying_item() != NULL);

	call_play(NOWPLAYING_PATH, &context->pending, destroyed_reply);
}

/*
 * A player reporting the total number of items has to see it applied,
 * including when the scope moves without any D-Bus request in flight,
 * which is what avrcp does on SetBrowsedPlayer.
 */
static void test_total_items_scope_change(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->check_total_items = true;

	g_assert(media_player_create_folder(context->mp, "/Filesystem",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	g_assert(media_player_create_folder(context->mp, "/Other",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);

	media_player_set_folder(context->mp, "/Filesystem", 0);
	media_player_set_folder(context->mp, "/Other", 0);

	g_assert(context->total_items_calls == 1);
}

/*
 * Search() shares the pending request slot with the other browsing
 * requests, so a busy Search() must report EBUSY like they do.
 */
static void test_search_busy(const void *data)
{
	context = create_context();
	if (context == NULL)
		return;

	context->defer_completion = true;

	g_assert(media_player_create_folder(context->mp, "/Filesystem",
					PLAYER_FOLDER_TYPE_MIXED, 0) != NULL);
	media_player_set_folder(context->mp, "/Filesystem", 1);
	media_player_set_searchable(context->mp, true);

	call_list_items(&context->pending, ignore_reply);
	call_search(&context->pending2, search_busy_reply);
}

static void test_teardown(const void *data)
{
	destroy_context();

	tester_teardown_complete();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/media_player/play_item_without_scope", NULL, NULL,
					test_play_item_without_scope,
					test_teardown);

	tester_add("/media_player/play_item_with_scope", NULL, NULL,
					test_play_item_with_scope,
					test_teardown);

	tester_add("/media_player/play_item_busy", NULL, NULL,
					test_play_item_busy,
					test_teardown);

	tester_add("/media_player/play_item_busy_with_list_items", NULL, NULL,
					test_play_item_busy_with_list_items,
					test_teardown);

	tester_add("/media_player/list_items_scope_change", NULL, NULL,
					test_list_items_scope_change,
					test_teardown);

	tester_add("/media_player/no_folder_without_scope", NULL, NULL,
					test_no_folder_without_scope,
					test_teardown);

	tester_add("/media_player/play_item_destroy_pending", NULL, NULL,
					test_play_item_destroy_pending,
					test_teardown);

	tester_add("/media_player/total_items_scope_change", NULL, NULL,
					test_total_items_scope_change,
					test_teardown);

	tester_add("/media_player/search_busy", NULL, NULL,
					test_search_busy, test_teardown);

	return tester_run();
}
