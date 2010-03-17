/*
 *  Phonebook access through D-Bus vCard and call history service
 *
 *  Copyright (C) 2010  Nokia Corporation
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "phonebook.h"
#include "dbus.h"
#include "vcard.h"

#define TRACKER_SERVICE "org.freedesktop.Tracker1"
#define TRACKER_RESOURCES_PATH "/org/freedesktop/Tracker1/Resources"
#define TRACKER_RESOURCES_INTERFACE "org.freedesktop.Tracker1.Resources"

#define TRACKER_DEFAULT_CONTACT_ME "<urn:nco:default-contact-me>"

#define CONTACTS_QUERY_ALL \
	"SELECT ?phone ?family ?given ?additional ?prefix "		\
		"?suffix ?email "					\
	"WHERE { "							\
		"?contact a nco:PersonContact ; "			\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { ?contact nco:hasEmailAddress ?email } "		\
	"OPTIONAL { ?contact nco:nameAdditional ?additional } "		\
	"OPTIONAL { ?contact nco:nameHonorificPrefix ?prefix } "	\
	"OPTIONAL { ?contact nco:nameHonorificSuffix ?suffix } "	\
	"}"

#define CONTACTS_QUERY_ALL_LIST						\
	"SELECT ?contact ?family ?given ?additional ?prefix "		\
		"?suffix ?phone "					\
	"WHERE { "							\
		"?contact a nco:PersonContact ; "			\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { ?contact nco:nameAdditional ?additional } "		\
	"OPTIONAL { ?contact nco:nameHonorificPrefix ?prefix } "	\
	"OPTIONAL { ?contact nco:nameHonorificSuffix ?suffix } "	\
	"}"

#define MISSED_CALLS_QUERY						\
	"SELECT ?contact ?family ?given ?additional ?prefix "		\
		"?suffix ?phone ?email "				\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?contact ; "					\
		"nmo:to <nco:default-contact-me> ; "			\
		"nmo:isRead false ."					\
		"?contact a nco:PersonContact ; "			\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { ?contact nco:hasEmailAddress ?email } "		\
	"OPTIONAL { ?contact nco:nameAdditional ?additional } "		\
	"OPTIONAL { ?contact nco:nameHonorificPrefix ?prefix } "	\
	"OPTIONAL { ?contact nco:nameHonorificSuffix ?suffix } "	\
	"}"

#define INCOMING_CALLS_QUERY						\
	"SELECT ?contact ?family ?given ?additional ?prefix "		\
		"?suffix ?phone ?fullname ?email "			\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?contact ; "					\
		"nmo:to " TRACKER_DEFAULT_CONTACT_ME " . "		\
		"?contact a nco:PersonContact ; "			\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { ?contact nco:hasEmailAddress ?email } "		\
	"OPTIONAL { ?contact nco:nameAdditional ?additional } "		\
	"OPTIONAL { ?contact nco:nameHonorificPrefix ?prefix } "	\
	"OPTIONAL { ?contact nco:nameHonorificSuffix ?suffix } "	\
	"}"

#define OUTGOING_CALLS_QUERY						\
	"SELECT ?contact ?family ?given ?additional ?prefix "		\
		"?suffix ?phone ?fullname ?email "			\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:to ?contact ; "					\
		"nmo:from " TRACKER_DEFAULT_CONTACT_ME " . "		\
			"?contact a nco:PersonContact ; "		\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { ?contact nco:hasEmailAddress ?email } "		\
	"OPTIONAL { ?contact nco:nameAdditional ?additional } "		\
	"OPTIONAL { ?contact nco:nameHonorificPrefix ?prefix } "	\
	"OPTIONAL { ?contact nco:nameHonorificSuffix ?suffix } "	\
	"}"

/* FIXME: still not sure about how to implement this */
#define COMBINED_CALLS_QUERY						\
	"SELECT ?contact "						\
	"WHERE { "							\
		"?call a nmo:Call . "					\
	"}"

#define CONTACTS_QUERY_FROM_URI \
	"SELECT ?phone ?family ?given ?additional ?prefix "		\
	"	?suffix ?email "					\
	"WHERE { "							\
		"<%s> a nco:PersonContact ; "				\
		"nco:nameFamily ?family ; "				\
		"nco:nameGiven ?given ; "				\
		"nco:hasPhoneNumber ?phone ."				\
	"OPTIONAL { <%s> nco:hasEmailAddress ?email } "			\
	"OPTIONAL { <%s> nco:nameAdditional ?additional } "		\
	"OPTIONAL { <%s> nco:nameHonorificPrefix ?prefix } "		\
	"OPTIONAL { <%s> nco:nameHonorificSuffix ?suffix } "		\
	"}"

typedef void (*reply_list_foreach_t) (char **reply, int num_fields,
		void *user_data);

struct pending_reply {
	reply_list_foreach_t callback;
	void *user_data;
	int num_fields;
};

struct phonebook_data {
	GString *vcards;
	phonebook_cb cb;
	void *user_data;
	int index;
};

struct cache_data {
	phonebook_cache_ready_cb ready_cb;
	phonebook_entry_cb entry_cb;
	void *user_data;
	GString *listing;
	int index;
};

struct phonebook_index {
	GArray *phonebook;
	int index;
};

static DBusConnection *connection = NULL;

static char **string_array_from_iter(DBusMessageIter iter, int array_len)
{
	DBusMessageIter sub;
	char **result;
	int i;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return NULL;

	result = g_new0(char *, array_len);

	dbus_message_iter_recurse(&iter, &sub);

	i = 0;
	while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
		char *arg;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			goto error;

		dbus_message_iter_get_basic(&sub, &arg);

		result[i] = arg;

		i++;
		dbus_message_iter_next(&sub);
	}

	return result;

error:
	g_free(result);

	return NULL;
}

static void query_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_reply *pending = user_data;
	DBusMessageIter iter, element;
	DBusError derr;
	int err;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s", derr.name,
							derr.message);
		dbus_error_free(&derr);

		err = -1;
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("SparqlQuery reply is not an array");

		err = -1;
		goto done;
	}

	dbus_message_iter_recurse(&iter, &element);

	err = 0;

	while (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_INVALID) {
		char **node;

		if (dbus_message_iter_get_arg_type(&element) !=
						DBUS_TYPE_ARRAY) {
			error("element is not an array");
			goto done;
		}

		node = string_array_from_iter(element, pending->num_fields);
		pending->callback(node, pending->num_fields,
							pending->user_data);
		g_free(node);

		dbus_message_iter_next(&element);
	}

done:
	/* This is the last entry */
	pending->callback(NULL, err, pending->user_data);

	dbus_message_unref(reply);
	g_free(pending);
}

static int query_tracker(const char* query, int num_fields,
				reply_list_foreach_t callback, void *user_data)
{
	struct pending_reply *pending;
	DBusPendingCall *call;
	DBusMessage *msg;

	if (connection == NULL)
		connection = obex_dbus_get_connection();

	msg = dbus_message_new_method_call(TRACKER_SERVICE,
			TRACKER_RESOURCES_PATH, TRACKER_RESOURCES_INTERFACE,
								"SparqlQuery");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &query,
						DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, msg, &call,
							-1) == FALSE) {
		error("Could not send dbus message");
		dbus_message_unref(msg);
		return -EPERM;
	}

	pending = g_new0(struct pending_reply, 1);
	pending->callback = callback;
	pending->user_data = user_data;
	pending->num_fields = num_fields;

	dbus_pending_call_set_notify(call, query_reply, pending, NULL);
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return 0;
}

static void pull_contacts(char **reply, int num_fields, void *user_data)
{
	struct phonebook_data *data = user_data;
	GString *vcards = data->vcards;
	char *formatted;

	if (reply == NULL)
		goto done;

	formatted = g_strdup_printf("%s;%s;%s;%s;%s", reply[1], reply[2],
						reply[3], reply[4], reply[5]);

	phonebook_add_entry(vcards, reply[0], TEL_TYPE_HOME, formatted,
								reply[6]);

	g_free(formatted);

	data->index++;

	return;

done:
	if (num_fields == 0)
		data->cb(vcards->str, vcards->len, data->index, 0, data->user_data);

	g_string_free(vcards, TRUE);
}

static void add_to_cache(char **reply, int num_fields, void *user_data)
{
	struct cache_data *cache = user_data;
	char *formatted;

	if (reply == NULL)
		goto done;

	formatted = g_strdup_printf("%s;%s;%s;%s;%s", reply[1], reply[2],
						reply[3], reply[4], reply[5]);

	cache->entry_cb(reply[0], PHONEBOOK_INVALID_HANDLE, formatted, "",
						reply[6], cache->user_data);

	g_free(formatted);

	return;

done:
	if (num_fields == 0)
		cache->ready_cb(cache->user_data);
}

int phonebook_init(void)
{
	return 0;
}

void phonebook_exit(void)
{
}

char *phonebook_set_folder(const char *current_folder, const char *new_folder,
							uint8_t flags, int *err)
{
	char *folder;

	if (err)
		*err = 0;

	folder = g_build_path(current_folder, new_folder, NULL);

	return folder;
}

int phonebook_pull(const char *name, const struct apparam_field *params,
					phonebook_cb cb, void *user_data)
{
	struct phonebook_data *data;

	data = g_new0(struct phonebook_data, 1);
	data->vcards = g_string_new(NULL);
	data->user_data = user_data;
	data->cb = cb;

	return query_tracker(CONTACTS_QUERY_ALL, 7, pull_contacts, data);
}

int phonebook_get_entry(const char *folder, const char *id,
					const struct apparam_field *params,
					phonebook_cb cb, void *user_data)
{
	struct phonebook_data *data;
	char *query;
	int ret;

	data = g_new0(struct phonebook_data, 1);
	data->vcards = g_string_new(NULL);
	data->user_data = user_data;
	data->cb = cb;

	query = g_strdup_printf(CONTACTS_QUERY_FROM_URI, id, id, id, id, id);

	ret = query_tracker(query, 8, pull_contacts, data);;

	g_free(query);

	return ret;
}

int phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
			phonebook_cache_ready_cb ready_cb, void *user_data)
{
	struct cache_data *cache;

	cache = g_new0(struct cache_data, 1);
	cache->entry_cb = entry_cb;
	cache->ready_cb = ready_cb;
	cache->user_data = user_data;

	return query_tracker(CONTACTS_QUERY_ALL_LIST, 7, add_to_cache, cache);
}
