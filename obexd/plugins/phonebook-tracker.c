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

#define CONTACTS_QUERY_ALL						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:hasEmailAddress(?c) "		\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
	"} "								\
	"}"

#define CONTACTS_QUERY_ALL_LIST						\
	"SELECT nco:contactUID(?c) nco:nameFamily(?c) "			\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"}"

#define MISSED_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:hasEmailAddress(?c) "		\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false ."				\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
	"} "								\
	"}"

#define MISSED_CALLS_LIST						\
	"SELECT nco:contactUID(?c) nco:nameFamily(?c) "			\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false ."				\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"}"

#define INCOMING_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:hasEmailAddress(?c) "		\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
	"} "								\
	"}"

#define INCOMING_CALLS_LIST						\
	"SELECT nco:contactUID(?c) nco:nameFamily(?c) "			\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"}"

#define OUTGOING_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:hasEmailAddress(?c) "		\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
	"} "								\
	"}"

#define OUTGOING_CALLS_LIST						\
	"SELECT nco:contactUID(?c) nco:nameFamily(?c) "			\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"}"

#define COMBINED_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:hasEmailAddress(?c) "		\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
	"{ "								\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"?a nco:hasPhoneNumber ?w . "			\
		"} "							\
	"} UNION { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"?a nco:hasPhoneNumber ?w . "			\
		"} "							\
	"} } "

#define COMBINED_CALLS_LIST						\
	"SELECT nco:contactUID(?c) nco:nameFamily(?c) "			\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
	"{ "								\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"} UNION { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"} } "


#define CONTACTS_QUERY_FROM_URI						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) nco:nameAdditional(?c) "	\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c)  "	\
	"nco:hasEmailAddress(?c) "					\
	"nco:phoneNumber(?w) "						\
	"WHERE { "							\
		"?c a nco:PersonContact ; "				\
		"nco:contactUID <%s> ; "				\
		"nco:hasPhoneNumber ?h . "				\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
	"} "								\
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
	gboolean vcardentry;
	const struct apparam_field *params;
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

static const char *name2query(const char *name)
{
	if (g_str_equal(name, "telecom/pb.vcf"))
		return CONTACTS_QUERY_ALL;
	else if (g_str_equal(name, "telecom/ich.vcf"))
		return INCOMING_CALLS_QUERY;
	else if (g_str_equal(name, "telecom/och.vcf"))
		return OUTGOING_CALLS_QUERY;
	else if (g_str_equal(name, "telecom/mch.vcf"))
		return MISSED_CALLS_QUERY;
	else if (g_str_equal(name, "telecom/cch.vcf"))
		return COMBINED_CALLS_QUERY;

	return NULL;
}

static gboolean folder_is_valid(const char *folder)
{
	if (g_str_equal(folder, "/"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom/pb"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom/ich"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom/och"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom/mch"))
		return TRUE;
	else if (g_str_equal(folder, "/telecom/cch"))
		return TRUE;

	return FALSE;
}

static const char *folder2query(const char *folder)
{
	if (g_str_equal(folder, "/telecom/pb"))
		return CONTACTS_QUERY_ALL_LIST;
	else if (g_str_equal(folder, "/telecom/ich"))
		return INCOMING_CALLS_LIST;
	else if (g_str_equal(folder, "/telecom/och"))
		return OUTGOING_CALLS_LIST;
	else if (g_str_equal(folder, "/telecom/mch"))
		return MISSED_CALLS_LIST;
	else if (g_str_equal(folder, "/telecom/cch"))
		return COMBINED_CALLS_LIST;

	return NULL;
}

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

static int query_tracker(const char *query, int num_fields,
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
	const struct apparam_field *params = data->params;
	struct phonebook_contact *contact;
	struct phonebook_number *number;
	GString *vcards = data->vcards;
	int last_index;

	DBG("reply %p", reply);

	if (reply == NULL)
		goto done;

	/* We are doing a PullvCardEntry, no need for those checks */
	if (data->vcardentry)
		goto add_entry;

	data->index++;

	/* Just interested in knowing the phonebook size */
	if (!data->vcardentry && params->maxlistcount == 0)
		return;

	last_index = params->liststartoffset + params->maxlistcount;

	if (data->index < params->liststartoffset || data->index > last_index)
		return;

add_entry:
	contact = g_new0(struct phonebook_contact, 1);
	contact->fullname = g_strdup(reply[1]);
	contact->family = g_strdup(reply[2]);
	contact->given = g_strdup(reply[3]);
	contact->additional = g_strdup(reply[4]);
	contact->prefix = g_strdup(reply[5]);
	contact->suffix = g_strdup(reply[6]);
	contact->email = g_strdup(reply[7]);

	number = g_new0(struct phonebook_number, 1);
	number->tel = g_strdup(reply[0]);
	number->type = 0; /* HOME */

	contact->numbers = g_slist_append(contact->numbers, number);

	/* Has WORK Phonenumber */
	if (strlen(reply[8])) {
		number = g_new0(struct phonebook_number, 1);
		number->tel = g_strdup(reply[8]);
		number->type = 3; /* WORK */

		contact->numbers = g_slist_append(contact->numbers, number);
	}

	DBG("contact %p", contact);

	phonebook_add_contact(vcards, contact, params->filter, params->format);
	phonebook_contact_free(contact);

	return;

done:
	if (num_fields == 0)
		data->cb(vcards->str, vcards->len, data->index, 0,
							data->user_data);

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

	/* The owner vCard must have the 0 handle */
	if (strcmp(reply[0], TRACKER_DEFAULT_CONTACT_ME) == 0)
		cache->entry_cb(reply[0], 0, formatted, "",
						reply[6], cache->user_data);
	else
		cache->entry_cb(reply[0], PHONEBOOK_INVALID_HANDLE, formatted,
					"", reply[6], cache->user_data);

	g_free(formatted);

	return;

done:
	if (num_fields == 0)
		cache->ready_cb(cache->user_data);

	g_free(cache);
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
	char *tmp1, *tmp2, *base, *path = NULL;
	gboolean root, child;
	int ret, len;

	root = (g_strcmp0("/", current_folder) == 0);
	child = (new_folder && strlen(new_folder) != 0);

	switch (flags) {
	case 0x02:
		/* Go back to root */
		if (!child) {
			path = g_strdup("/");
			goto done;
		}

		path = g_build_filename(current_folder, new_folder, NULL);
		break;
	case 0x03:
		/* Go up 1 level */
		if (root) {
			/* Already root */
			path = g_strdup("/");
			goto done;
		}

		/*
		 * Removing one level of the current folder. Current folder
		 * contains AT LEAST one level since it is not at root folder.
		 * Use glib utility functions to handle invalid chars in the
		 * folder path properly.
		 */
		tmp1 = g_path_get_basename(current_folder);
		tmp2 = g_strrstr(current_folder, tmp1);
		len = tmp2 - (current_folder + 1);

		g_free(tmp1);
		g_free(tmp2);

		if (len == 0)
			base = g_strdup("/");
		else
			base = g_strndup(current_folder, len);

		/* Return: one level only */
		if (!child) {
			path = base;
			goto done;
		}

		path = g_build_filename(base, new_folder, NULL);
		g_free(base);

		break;
	default:
		ret = -EBADR;
		break;
	}

done:

	if (!folder_is_valid(path)) {
		g_free(path);
		path = NULL;
		ret = -ENOENT;
	} else
		ret = 0;

	if (err)
		*err = ret;

	return path;
}

int phonebook_pull(const char *name, const struct apparam_field *params,
					phonebook_cb cb, void *user_data)
{
	struct phonebook_data *data;
	const char *query;

	DBG("name %s", name);

	query = name2query(name);
	if (query == NULL)
		return -ENOENT;

	data = g_new0(struct phonebook_data, 1);
	data->vcards = g_string_new(NULL);
	data->params = params;
	data->user_data = user_data;
	data->cb = cb;

	return query_tracker(query, 9, pull_contacts, data);
}

int phonebook_get_entry(const char *folder, const char *id,
					const struct apparam_field *params,
					phonebook_cb cb, void *user_data)
{
	struct phonebook_data *data;
	char *query;
	int ret;

	DBG("folder %s id %s", folder, id);

	data = g_new0(struct phonebook_data, 1);
	data->vcards = g_string_new(NULL);
	data->user_data = user_data;
	data->params = params;
	data->cb = cb;
	data->vcardentry = TRUE;

	query = g_strdup_printf(CONTACTS_QUERY_FROM_URI, id);

	ret = query_tracker(query, 9, pull_contacts, data);

	g_free(query);

	return ret;
}

int phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
			phonebook_cache_ready_cb ready_cb, void *user_data)
{
	struct cache_data *cache;
	const char *query;

	DBG("name %s", name);

	query = folder2query(name);
	if (query == NULL)
		return -ENOENT;

	cache = g_new0(struct cache_data, 1);
	cache->entry_cb = entry_cb;
	cache->ready_cb = ready_cb;
	cache->user_data = user_data;

	return query_tracker(query, 7, add_to_cache, cache);
}
