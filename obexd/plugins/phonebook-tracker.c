// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Phonebook access through D-Bus vCard and call history service
 *
 *  Copyright (C) 2010  Nokia Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <libtracker-sparql/tracker-sparql.h>

#include "obexd/src/log.h"
#include "obexd/src/obex.h"
#include "obexd/src/service.h"
#include "obexd/src/mimetype.h"
#include "phonebook.h"
#include "vcard.h"

#define TRACKER_SERVICE "org.freedesktop.Tracker1"
#define TRACKER_RESOURCES_PATH "/org/freedesktop/Tracker1/Resources"
#define TRACKER_RESOURCES_INTERFACE "org.freedesktop.Tracker1.Resources"

#define TRACKER_DEFAULT_CONTACT_ME "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#default-contact-me"
#define AFFILIATION_HOME "Home"
#define AFFILIATION_WORK "Work"
#define ADDR_FIELD_AMOUNT 7
#define PULL_QUERY_COL_AMOUNT 23
#define COUNT_QUERY_COL_AMOUNT 1

#define COL_PHONE_AFF 0 /* work/home phone numbers */
#define COL_FULL_NAME 1
#define COL_FAMILY_NAME 2
#define COL_GIVEN_NAME 3
#define COL_ADDITIONAL_NAME 4
#define COL_NAME_PREFIX 5
#define COL_NAME_SUFFIX 6
#define COL_ADDR_AFF 7 /* addresses from affiliation */
#define COL_BIRTH_DATE 8
#define COL_NICKNAME 9
#define COL_URL 10
#define COL_PHOTO 11
#define COL_ORG_ROLE 12
#define COL_UID 13
#define COL_TITLE 14
#define COL_AFF_TYPE 15
#define COL_ORG_NAME 16
#define COL_ORG_DEPARTMENT 17
#define COL_EMAIL_AFF 18 /* email's from affiliation (work/home) */
#define COL_DATE 19
#define COL_SENT 20
#define COL_ANSWERED 21
#define CONTACTS_ID_COL 22
#define CONTACT_ID_PREFIX "urn:uuid:"
#define CALL_ID_PREFIX "message:"

#define FAX_NUM_TYPE "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#FaxNumber"
#define MOBILE_NUM_TYPE "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#CellPhoneNumber"

#define MAIN_DELIM "\30" /* Main delimiter between phones, addresses, emails*/
#define SUB_DELIM "\31" /* Delimiter used in telephone number strings*/
#define ADDR_DELIM "\37" /* Delimiter used for address data fields */
#define MAX_FIELDS 100 /* Max amount of fields to be concatenated at once*/
#define VCARDS_PART_COUNT 50 /* amount of vcards sent at once to PBAP core */
#define QUERY_OFFSET_FORMAT "%s OFFSET %d"

#define CONTACTS_QUERY_ALL						\
"SELECT "								\
"(SELECT GROUP_CONCAT(fn:concat(rdf:type(?aff_number),"			\
"\"\31\", nco:phoneNumber(?aff_number)), \"\30\")"			\
"WHERE {"								\
"	?_role nco:hasPhoneNumber ?aff_number"				\
"}) "									\
"nco:fullname(?_contact) "						\
"nco:nameFamily(?_contact) "						\
"nco:nameGiven(?_contact) "						\
"nco:nameAdditional(?_contact) "					\
"nco:nameHonorificPrefix(?_contact) "					\
"nco:nameHonorificSuffix(?_contact) "					\
"(SELECT GROUP_CONCAT(fn:concat("					\
"tracker:coalesce(nco:pobox(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:extendedAddress(?aff_addr), \"\"), \"\37\","	\
"tracker:coalesce(nco:streetAddress(?aff_addr), \"\"), \"\37\","	\
"tracker:coalesce(nco:locality(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:region(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:postalcode(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:country(?aff_addr), \"\"), "			\
"\"\31\", rdfs:label(?_role) ), "					\
"\"\30\") "								\
"WHERE {"								\
"?_role nco:hasPostalAddress ?aff_addr"					\
"}) "									\
"nco:birthDate(?_contact) "						\
"(SELECT "								\
"	?nick "								\
"	WHERE { "							\
"		{ "							\
"			?_contact nco:nickname ?nick "			\
"		} UNION { "						\
"			?_contact nco:hasAffiliation ?role . "		\
"			?role nco:hasIMAddress ?im . "			\
"			?im nco:imNickname ?nick "			\
"		} "							\
"	} "								\
") "									\
"(SELECT GROUP_CONCAT(fn:concat( "					\
	"?url_val, \"\31\", tracker:coalesce(rdfs:label(?_role), \"\") "\
	"), \"\30\") "							\
	"WHERE {"							\
		"?_role nco:url ?url_val . "				\
"})"									\
"nie:url(nco:photo(?_contact)) "					\
"nco:role(?_role) "							\
"nco:contactUID(?_contact) "						\
"nco:title(?_role) "							\
"rdfs:label(?_role) "							\
"nco:fullname(nco:org(?_role))"						\
"nco:department(?_role) "						\
"(SELECT GROUP_CONCAT(fn:concat(?emailaddress,\"\31\","			\
	"tracker:coalesce(rdfs:label(?_role), \"\")),"			\
	"\"\30\") "							\
	"WHERE { "							\
	"?_role nco:hasEmailAddress "					\
	"		[ nco:emailAddress ?emailaddress ] "		\
	"}) "								\
"\"NOTACALL\" \"false\" \"false\" "					\
"?_contact "								\
"WHERE {"								\
"	?_contact a nco:PersonContact ."				\
"	OPTIONAL {?_contact nco:hasAffiliation ?_role .}"		\
"}"									\
"ORDER BY tracker:id(?_contact)"

#define CONTACTS_QUERY_ALL_LIST						\
	"SELECT ?c nco:nameFamily(?c) "					\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"(SELECT "							\
		"?nick "						\
		"WHERE { "						\
			"{ "						\
				"?c nco:nickname ?nick "		\
			"} UNION { "					\
				"?c nco:hasAffiliation ?role . "	\
				"?role nco:hasIMAddress ?im . "		\
				"?im nco:imNickname ?nick "		\
			"} "						\
		"} "							\
	") "								\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?c a nco:PersonContact . "				\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "			\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?h . "				\
	"} "								\
	"} GROUP BY ?c"

#define CALLS_CONSTRAINTS(CONSTRAINT)					\
" WHERE { "								\
	"?_call a nmo:Call . "						\
	"?_unb_contact a nco:Contact . "				\
	"?_unb_contact nco:hasPhoneNumber ?_cpn . "			\
CONSTRAINT								\
	"OPTIONAL { "							\
		"{ SELECT ?_contact ?_no ?_role ?_number "		\
			"count(?_contact) as ?cnt "			\
		"WHERE { "						\
			"?_contact a nco:PersonContact . "		\
			"{ "						\
				"?_contact nco:hasAffiliation ?_role . "\
				"?_role nco:hasPhoneNumber ?_number . " \
			"} UNION { "					\
				"?_contact nco:hasPhoneNumber ?_number" \
			"} "						\
			"?_number maemo:localPhoneNumber ?_no . "	\
		"} GROUP BY ?_no } "					\
		"FILTER(?cnt = 1) "					\
		"?_cpn maemo:localPhoneNumber ?_no . "			\
	"} "								\
"} "

#define CALLS_LIST(CONSTRAINT)						\
"SELECT ?_call nco:nameFamily(?_contact) "				\
	"nco:nameGiven(?_contact) nco:nameAdditional(?_contact) "	\
	"nco:nameHonorificPrefix(?_contact) "				\
	"nco:nameHonorificSuffix(?_contact) "				\
	"(SELECT "							\
		"?nick "						\
		"WHERE { "						\
			"{ "						\
				"?_contact nco:nickname ?nick "		\
			"} UNION { "					\
				"?_contact nco:hasAffiliation ?role . "	\
				"?role nco:hasIMAddress ?im . "		\
				"?im nco:imNickname ?nick "		\
			"} "						\
		"} "							\
	") "								\
	"nco:phoneNumber(?_cpn) "					\
CALLS_CONSTRAINTS(CONSTRAINT)						\
"ORDER BY DESC(nmo:sentDate(?_call)) "

#define CALLS_QUERY(CONSTRAINT)						\
"SELECT "								\
"(SELECT fn:concat(rdf:type(?role_number),"				\
	"\"\31\", nco:phoneNumber(?role_number))"			\
	"WHERE {"							\
	"{"								\
	"	?_role nco:hasPhoneNumber ?role_number "		\
	"	FILTER (?role_number = ?_number)"			\
	"} UNION { "							\
		"?_unb_contact nco:hasPhoneNumber ?role_number . "	\
	"	FILTER (!bound(?_role)) "				\
	"}"								\
"} GROUP BY nco:phoneNumber(?role_number) ) "				\
	"nco:fullname(?_contact) "					\
	"nco:nameFamily(?_contact) "					\
	"nco:nameGiven(?_contact) "					\
	"nco:nameAdditional(?_contact) "				\
	"nco:nameHonorificPrefix(?_contact) "				\
	"nco:nameHonorificSuffix(?_contact) "				\
"(SELECT GROUP_CONCAT(fn:concat("					\
	"tracker:coalesce(nco:pobox(?aff_addr), \"\"), \"\37\","	\
	"tracker:coalesce(nco:extendedAddress(?aff_addr), \"\"), \"\37\","\
	"tracker:coalesce(nco:streetAddress(?aff_addr), \"\"), \"\37\","\
	"tracker:coalesce(nco:locality(?aff_addr), \"\"), \"\37\","	\
	"tracker:coalesce(nco:region(?aff_addr), \"\"), \"\37\","	\
	"tracker:coalesce(nco:postalcode(?aff_addr), \"\"), \"\37\","	\
	"tracker:coalesce(nco:country(?aff_addr), \"\"), "		\
	"\"\31\", rdfs:label(?c_role) ), "				\
	"\"\30\") "							\
	"WHERE {"							\
	"?_contact nco:hasAffiliation ?c_role . "			\
	"?c_role nco:hasPostalAddress ?aff_addr"			\
	"}) "								\
	"nco:birthDate(?_contact) "					\
"(SELECT "								\
	"?nick "							\
	"WHERE { "							\
	"	{ "							\
	"	?_contact nco:nickname ?nick "				\
	"		} UNION { "					\
	"			?_contact nco:hasAffiliation ?role . "	\
	"			?role nco:hasIMAddress ?im . "		\
	"			?im nco:imNickname ?nick "		\
	"		} "						\
	"	} "							\
	") "								\
"(SELECT GROUP_CONCAT(fn:concat(?url_value, \"\31\", "			\
	"tracker:coalesce(rdfs:label(?c_role), \"\")), \"\30\") "	\
	"WHERE {"							\
		"?_contact nco:hasAffiliation ?c_role . "		\
		"?c_role nco:url ?url_value . "				\
"})"									\
	"nie:url(nco:photo(?_contact)) "				\
	"nco:role(?_role) "						\
	"nco:contactUID(?_contact) "					\
	"nco:title(?_role) "						\
	"rdfs:label(?_role) "						\
	"nco:fullname(nco:org(?_role)) "				\
	"nco:department(?_role) "					\
"(SELECT GROUP_CONCAT(fn:concat(?emailaddress,\"\31\","			\
	"tracker:coalesce(rdfs:label(?c_role), \"\")),"			\
	"\"\30\") "							\
	"WHERE { "							\
	"?_contact nco:hasAffiliation ?c_role . "			\
	"?c_role nco:hasEmailAddress "					\
	"		[ nco:emailAddress ?emailaddress ] "		\
	"}) "								\
	"nmo:receivedDate(?_call) "					\
	"nmo:isSent(?_call) "						\
	"nmo:isAnswered(?_call) "					\
	"?_call "							\
CALLS_CONSTRAINTS(CONSTRAINT)						\
"ORDER BY DESC(nmo:sentDate(?_call)) "

#define MISSED_CONSTRAINT		\
"?_call nmo:from ?_unb_contact . "	\
"?_call nmo:isSent false . "		\
"?_call nmo:isAnswered false . "

#define INCOMING_CONSTRAINT		\
"?_call nmo:from ?_unb_contact . "	\
"?_call nmo:isSent false . "		\
"?_call nmo:isAnswered true . "

#define OUTGOING_CONSTRAINT		\
"?_call nmo:to ?_unb_contact . "	\
"?_call nmo:isSent true . "

#define COMBINED_CONSTRAINT			\
"{ "						\
"	?_call nmo:from ?_unb_contact .  "	\
"	?_call nmo:isSent false "		\
"} UNION { "					\
"	?_call nmo:to ?_unb_contact . "		\
"	?_call nmo:isSent true "		\
"} "

#define CALL_URI_CONSTRAINT	\
COMBINED_CONSTRAINT		\
"FILTER (?_call = <%s>) "

#define MISSED_CALLS_QUERY CALLS_QUERY(MISSED_CONSTRAINT)
#define MISSED_CALLS_LIST CALLS_LIST(MISSED_CONSTRAINT)
#define INCOMING_CALLS_QUERY CALLS_QUERY(INCOMING_CONSTRAINT)
#define INCOMING_CALLS_LIST CALLS_LIST(INCOMING_CONSTRAINT)
#define OUTGOING_CALLS_QUERY CALLS_QUERY(OUTGOING_CONSTRAINT)
#define OUTGOING_CALLS_LIST CALLS_LIST(OUTGOING_CONSTRAINT)
#define COMBINED_CALLS_QUERY CALLS_QUERY(COMBINED_CONSTRAINT)
#define COMBINED_CALLS_LIST CALLS_LIST(COMBINED_CONSTRAINT)
#define CONTACT_FROM_CALL_QUERY CALLS_QUERY(CALL_URI_CONSTRAINT)

#define CONTACTS_QUERY_FROM_URI						\
"SELECT "								\
"(SELECT GROUP_CONCAT(fn:concat(rdf:type(?aff_number),"			\
"\"\31\", nco:phoneNumber(?aff_number)), \"\30\")"			\
"WHERE {"								\
"	?_role nco:hasPhoneNumber ?aff_number"				\
"}) "									\
"nco:fullname(<%s>) "							\
"nco:nameFamily(<%s>) "							\
"nco:nameGiven(<%s>) "							\
"nco:nameAdditional(<%s>) "						\
"nco:nameHonorificPrefix(<%s>) "					\
"nco:nameHonorificSuffix(<%s>) "					\
"(SELECT GROUP_CONCAT(fn:concat("					\
"tracker:coalesce(nco:pobox(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:extendedAddress(?aff_addr), \"\"), \"\37\","	\
"tracker:coalesce(nco:streetAddress(?aff_addr), \"\"), \"\37\","	\
"tracker:coalesce(nco:locality(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:region(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:postalcode(?aff_addr), \"\"), \"\37\","		\
"tracker:coalesce(nco:country(?aff_addr), \"\"), "			\
"\"\31\", rdfs:label(?_role) ), "					\
"\"\30\") "								\
"WHERE {"								\
"?_role nco:hasPostalAddress ?aff_addr"					\
"}) "									\
"nco:birthDate(<%s>) "							\
"(SELECT "								\
"	?nick "								\
"	WHERE { "							\
"		{ "							\
"			?_contact nco:nickname ?nick "			\
"		} UNION { "						\
"			?_contact nco:hasAffiliation ?role . "		\
"			?role nco:hasIMAddress ?im . "			\
"			?im nco:imNickname ?nick "			\
"		} "							\
"		FILTER (?_contact = <%s>)"				\
"	} "								\
") "									\
"(SELECT GROUP_CONCAT(fn:concat( "					\
	"?url_val, \"\31\", tracker:coalesce(rdfs:label(?_role), \"\") "\
	"), \"\30\") "							\
	"WHERE {"							\
		"?_role nco:url ?url_val . "				\
"})"									\
"nie:url(nco:photo(<%s>)) "						\
"nco:role(?_role) "							\
"nco:contactUID(<%s>) "							\
"nco:title(?_role) "							\
"rdfs:label(?_role) "							\
"nco:fullname(nco:org(?_role))"						\
"nco:department(?_role) "						\
"(SELECT GROUP_CONCAT(fn:concat(?emailaddress,\"\31\","			\
	"tracker:coalesce(rdfs:label(?_role), \"\")),"			\
	"\"\30\") "							\
	"WHERE { "							\
	"?_role nco:hasEmailAddress "					\
	"		[ nco:emailAddress ?emailaddress ] "		\
	"}) "								\
"\"NOTACALL\" \"false\" \"false\" "					\
"<%s> "									\
"WHERE {"								\
"	<%s> a nco:PersonContact ."					\
"	OPTIONAL {<%s> nco:hasAffiliation ?_role .}"			\
"}"

#define CONTACTS_OTHER_QUERY_FROM_URI					\
	"SELECT fn:concat(\"TYPE_OTHER\", \"\31\", nco:phoneNumber(?t))"\
	"\"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" "			\
	"\"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" "		\
	" \"NOTACALL\" \"false\" \"false\" <%s> "			\
	"WHERE { "							\
		"<%s> a nco:Contact . "					\
		"OPTIONAL { <%s> nco:hasPhoneNumber ?t . } "		\
	"} "

#define CONTACTS_COUNT_QUERY						\
	"SELECT COUNT(?c) "						\
	"WHERE {"							\
		"?c a nco:PersonContact ."				\
	"}"

#define MISSED_CALLS_COUNT_QUERY					\
	"SELECT COUNT(?call) WHERE {"					\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:isSent false ;"					\
		"nmo:from ?c ;"						\
		"nmo:isAnswered false ."				\
	"}"

#define INCOMING_CALLS_COUNT_QUERY					\
	"SELECT COUNT(?call) WHERE {"					\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:isSent false ;"					\
		"nmo:from ?c ;"						\
		"nmo:isAnswered true ."					\
	"}"

#define OUTGOING_CALLS_COUNT_QUERY					\
	"SELECT COUNT(?call) WHERE {"					\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:isSent true ;"					\
		"nmo:to ?c ."						\
	"}"

#define COMBINED_CALLS_COUNT_QUERY					\
	"SELECT COUNT(?call) WHERE {"					\
	"{"								\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:isSent true ;"					\
		"nmo:to ?c ."						\
	"}UNION {"							\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:from ?c ."						\
	"}"								\
	"}"

#define NEW_MISSED_CALLS_COUNT_QUERY					\
	"SELECT COUNT(?call) WHERE {"					\
		"?c a nco:Contact ;"					\
		"nco:hasPhoneNumber ?h ."				\
		"?call a nmo:Call ;"					\
		"nmo:isSent false ;"					\
		"nmo:from ?c ;"						\
		"nmo:isAnswered false ;"				\
		"nmo:isRead false ."					\
	"}"

typedef int (*reply_list_foreach_t) (const char **reply, int num_fields,
							void *user_data);

typedef void (*add_field_t) (struct phonebook_contact *contact,
						const char *value, int type);

struct pending_reply {
	reply_list_foreach_t callback;
	void *user_data;
	int num_fields;
};

struct contact_data {
	char *id;
	struct phonebook_contact *contact;
};

struct phonebook_data {
	phonebook_cb cb;
	void *user_data;
	int index;
	gboolean vcardentry;
	const struct apparam_field *params;
	GSList *contacts;
	phonebook_cache_ready_cb ready_cb;
	phonebook_entry_cb entry_cb;
	int newmissedcalls;
	GCancellable *query_canc;
	char *req_name;
	int vcard_part_count;
	int tracker_index;
};

struct phonebook_index {
	GArray *phonebook;
	int index;
};

static TrackerSparqlConnection *connection = NULL;

static const char *name2query(const char *name)
{
	if (g_str_equal(name, PB_CONTACTS))
		return CONTACTS_QUERY_ALL;
	else if (g_str_equal(name, PB_CALLS_INCOMING))
		return INCOMING_CALLS_QUERY;
	else if (g_str_equal(name, PB_CALLS_OUTGOING))
		return OUTGOING_CALLS_QUERY;
	else if (g_str_equal(name, PB_CALLS_MISSED))
		return MISSED_CALLS_QUERY;
	else if (g_str_equal(name, PB_CALLS_COMBINED))
		return COMBINED_CALLS_QUERY;

	return NULL;
}

static const char *name2count_query(const char *name)
{
	if (g_str_equal(name, PB_CONTACTS))
		return CONTACTS_COUNT_QUERY;
	else if (g_str_equal(name, PB_CALLS_INCOMING))
		return INCOMING_CALLS_COUNT_QUERY;
	else if (g_str_equal(name, PB_CALLS_OUTGOING))
		return OUTGOING_CALLS_COUNT_QUERY;
	else if (g_str_equal(name, PB_CALLS_MISSED))
		return MISSED_CALLS_COUNT_QUERY;
	else if (g_str_equal(name, PB_CALLS_COMBINED))
		return COMBINED_CALLS_COUNT_QUERY;

	return NULL;
}

static gboolean folder_is_valid(const char *folder)
{
	if (folder == NULL)
		return FALSE;

	if (g_str_equal(folder, "/"))
		return TRUE;
	else if (g_str_equal(folder, PB_TELECOM_FOLDER))
		return TRUE;
	else if (g_str_equal(folder, PB_CONTACTS_FOLDER))
		return TRUE;
	else if (g_str_equal(folder, PB_CALLS_INCOMING_FOLDER))
		return TRUE;
	else if (g_str_equal(folder, PB_CALLS_OUTGOING_FOLDER))
		return TRUE;
	else if (g_str_equal(folder, PB_CALLS_MISSED_FOLDER))
		return TRUE;
	else if (g_str_equal(folder, PB_CALLS_COMBINED_FOLDER))
		return TRUE;

	return FALSE;
}

static const char *folder2query(const char *folder)
{
	if (g_str_equal(folder, PB_CONTACTS_FOLDER))
		return CONTACTS_QUERY_ALL_LIST;
	else if (g_str_equal(folder, PB_CALLS_INCOMING_FOLDER))
		return INCOMING_CALLS_LIST;
	else if (g_str_equal(folder, PB_CALLS_OUTGOING_FOLDER))
		return OUTGOING_CALLS_LIST;
	else if (g_str_equal(folder, PB_CALLS_MISSED_FOLDER))
		return MISSED_CALLS_LIST;
	else if (g_str_equal(folder, PB_CALLS_COMBINED_FOLDER))
		return COMBINED_CALLS_LIST;

	return NULL;
}

static const char **string_array_from_cursor(TrackerSparqlCursor *cursor,
								int array_len)
{
	const char **result;
	int i;

	result = g_new0(const char *, array_len);

	for (i = 0; i < array_len; ++i) {
		TrackerSparqlValueType type;

		type = tracker_sparql_cursor_get_value_type(cursor, i);

		if (type == TRACKER_SPARQL_VALUE_TYPE_BLANK_NODE ||
				type == TRACKER_SPARQL_VALUE_TYPE_UNBOUND)
			/* For null/unbound type filling result part with ""*/
			result[i] = "";
		else
			/* Filling with string representation of content*/
			result[i] = tracker_sparql_cursor_get_string(cursor, i,
									NULL);
	}

	return result;
}

static void update_cancellable(struct phonebook_data *pdata,
							GCancellable *canc)
{
	if (pdata->query_canc)
		g_object_unref(pdata->query_canc);

	pdata->query_canc = canc;
}

static void async_query_cursor_next_cb(GObject *source, GAsyncResult *result,
							gpointer user_data)
{
	struct pending_reply *pending = user_data;
	TrackerSparqlCursor *cursor = TRACKER_SPARQL_CURSOR(source);
	GCancellable *cancellable;
	GError *error = NULL;
	gboolean success;
	const char **node;
	int err;

	success = tracker_sparql_cursor_next_finish(
						TRACKER_SPARQL_CURSOR(source),
						result, &error);

	if (!success) {
		if (error) {
			DBG("cursor_next error: %s", error->message);
			g_error_free(error);
		} else
			/* When tracker_sparql_cursor_next_finish ends with
			 * failure and no error is set, that means end of
			 * results returned by query */
			pending->callback(NULL, 0, pending->user_data);

		goto failed;
	}

	node = string_array_from_cursor(cursor, pending->num_fields);
	err = pending->callback(node, pending->num_fields, pending->user_data);
	g_free(node);

	/* Fetch next result only if processing current chunk ended with
	 * success. Sometimes during processing data, we are able to determine
	 * if there is no need to get more data from tracker - by example
	 * stored amount of data parts is big enough for sending and we might
	 * want to suspend processing or just some error occurred. */
	if (!err) {
		cancellable = g_cancellable_new();
		update_cancellable(pending->user_data, cancellable);
		tracker_sparql_cursor_next_async(cursor, cancellable,
						async_query_cursor_next_cb,
						pending);
		return;
	}

failed:
	g_object_unref(cursor);
	g_free(pending);
}

static int query_tracker(const char *query, int num_fields,
				reply_list_foreach_t callback, void *user_data)
{
	struct pending_reply *pending;
	GCancellable *cancellable;
	TrackerSparqlCursor *cursor;
	GError *error = NULL;

	DBG("");

	if (connection == NULL)
		connection = tracker_sparql_connection_get_direct(
								NULL, &error);

	if (!connection) {
		if (error) {
			DBG("direct-connection error: %s", error->message);
			g_error_free(error);
		}

		return -EINTR;
	}

	cancellable = g_cancellable_new();
	update_cancellable(user_data, cancellable);
	cursor = tracker_sparql_connection_query(connection, query,
							cancellable, &error);

	if (cursor == NULL) {
		if (error) {
			DBG("connection_query error: %s", error->message);
			g_error_free(error);
		}

		g_object_unref(cancellable);

		return -EINTR;
	}

	pending = g_new0(struct pending_reply, 1);
	pending->callback = callback;
	pending->user_data = user_data;
	pending->num_fields = num_fields;

	/* Now asynchronously going through each row of results - callback
	 * async_query_cursor_next_cb will be called ALWAYS, even if async
	 * request was canceled */
	tracker_sparql_cursor_next_async(cursor, cancellable,
						async_query_cursor_next_cb,
						pending);

	return 0;
}

static char *iso8601_utc_to_localtime(const char *datetime)
{
	time_t time;
	struct tm tm, *local;
	char localdate[32];
	int nr;

	memset(&tm, 0, sizeof(tm));

	nr = sscanf(datetime, "%04u-%02u-%02uT%02u:%02u:%02u",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	if (nr < 6) {
		/* Invalid time format */
		error("sscanf(): %s (%d)", strerror(errno), errno);
		return g_strdup("");
	}

	/* Time already in localtime */
	if (!g_str_has_suffix(datetime, "Z")) {
		strftime(localdate, sizeof(localdate), "%Y%m%dT%H%M%S", &tm);
		return g_strdup(localdate);
	}

	tm.tm_year -= 1900;	/* Year since 1900 */
	tm.tm_mon--;		/* Months since January, values 0-11 */

	time = mktime(&tm);
	time -= timezone;

	local = localtime(&time);

	strftime(localdate, sizeof(localdate), "%Y%m%dT%H%M%S", local);

	return g_strdup(localdate);
}

static void set_call_type(struct phonebook_contact *contact,
				const char *datetime, const char *is_sent,
				const char *is_answered)
{
	gboolean sent, answered;

	if (g_strcmp0(datetime, "NOTACALL") == 0) {
		contact->calltype = CALL_TYPE_NOT_A_CALL;
		return;
	}

	sent = g_str_equal(is_sent, "true");
	answered = g_str_equal(is_answered, "true");

	if (sent == FALSE) {
		if (answered == FALSE)
			contact->calltype = CALL_TYPE_MISSED;
		else
			contact->calltype = CALL_TYPE_INCOMING;
	} else
		contact->calltype = CALL_TYPE_OUTGOING;

	/* Tracker gives time in the ISO 8601 format, UTC time */
	contact->datetime = iso8601_utc_to_localtime(datetime);
}

static gboolean contact_matches(struct contact_data *c_data, const char *id,
							const char *datetime)
{
	char *localtime;
	int cmp_ret;

	if (g_strcmp0(c_data->id, id) != 0)
		return FALSE;

	/* id is equal and not call history entry => contact matches */
	if (c_data->contact->calltype == CALL_TYPE_NOT_A_CALL)
		return TRUE;

	/* for call history entries have to compare also timestamps of calls */
	localtime = iso8601_utc_to_localtime(datetime);
	cmp_ret = g_strcmp0(c_data->contact->datetime, localtime);
	g_free(localtime);

	return (cmp_ret == 0) ? TRUE : FALSE;
}

static struct phonebook_contact *find_contact(GSList *contacts, const char *id,
							const char *datetime)
{
	GSList *l;

	for (l = contacts; l; l = l->next) {
		struct contact_data *c_data = l->data;

		if (contact_matches(c_data, id, datetime))
			return c_data->contact;
	}

	return NULL;
}

static struct phonebook_field *find_field(GSList *fields, const char *value,
								int type)
{
	GSList *l;

	for (l = fields; l; l = l->next) {
		struct phonebook_field *field = l->data;
		/* Returning phonebook number if phone values and type values
		 * are equal */
		if (g_strcmp0(field->text, value) == 0 && field->type == type)
			return field;
	}

	return NULL;
}

static void add_phone_number(struct phonebook_contact *contact,
						const char *phone, int type)
{
	struct phonebook_field *number;

	if (phone == NULL || strlen(phone) == 0)
		return;

	/* Not adding number if there is already added with the same value */
	if (find_field(contact->numbers, phone, type))
		return;

	number = g_new0(struct phonebook_field, 1);
	number->text = g_strdup(phone);
	number->type = type;

	contact->numbers = g_slist_append(contact->numbers, number);
}

static void add_email(struct phonebook_contact *contact, const char *address,
								int type)
{
	struct phonebook_field *email;

	if (address == NULL || strlen(address) == 0)
		return;

	/* Not adding email if there is already added with the same value */
	if (find_field(contact->emails, address, type))
		return;

	email = g_new0(struct phonebook_field, 1);
	email->text = g_strdup(address);
	email->type = type;

	contact->emails = g_slist_append(contact->emails, email);
}

static gboolean addr_matches(struct phonebook_addr *a, struct phonebook_addr *b)
{
	GSList *la, *lb;

	if (a->type != b->type)
		return FALSE;

	for (la = a->fields, lb = b->fields; la && lb;
						la = la->next, lb = lb->next) {
		char *field_a = la->data;
		char *field_b = lb->data;

		if (g_strcmp0(field_a, field_b) != 0)
			return FALSE;
	}

	return TRUE;
}

/* generates phonebook_addr struct from tracker address data string. */
static struct phonebook_addr *gen_addr(const char *address, int type)
{
	struct phonebook_addr *addr;
	GSList *fields = NULL;
	char **addr_parts;
	int i;

	/* This test handles cases when address points to empty string
	 * (or address is NULL pointer) or string containing only six
	 * separators. It indicates that none of address fields is present
	 * and there is no sense to create dummy phonebook_addr struct */
	if (address == NULL || strlen(address) < ADDR_FIELD_AMOUNT)
		return NULL;

	addr_parts = g_strsplit(address, ADDR_DELIM, ADDR_FIELD_AMOUNT);

	for (i = 0; i < ADDR_FIELD_AMOUNT; ++i)
		fields = g_slist_append(fields, g_strdup(addr_parts[i]));

	g_strfreev(addr_parts);

	addr = g_new0(struct phonebook_addr, 1);
	addr->fields = fields;
	addr->type = type;

	return addr;
}

static void add_address(struct phonebook_contact *contact,
					const char *address, int type)
{
	struct phonebook_addr *addr;
	GSList *l;

	addr = gen_addr(address, type);
	if (addr == NULL)
		return;

	/* Not adding address if there is already added with the same value.
	 * These type of checks have to be done because sometimes tracker
	 * returns results for contact data in more than 1 row - then the same
	 * address may be returned more than once in query results */
	for (l = contact->addresses; l; l = l->next) {
		struct phonebook_addr *tmp = l->data;

		if (addr_matches(tmp, addr)) {
			phonebook_addr_free(addr);
			return;
		}
	}

	contact->addresses = g_slist_append(contact->addresses, addr);
}

static void add_url(struct phonebook_contact *contact, const char *url_val,
								int type)
{
	struct phonebook_field *url;

	if (url_val == NULL || strlen(url_val) == 0)
		return;

	/* Not adding url if there is already added with the same value */
	if (find_field(contact->urls, url_val, type))
		return;

	url = g_new0(struct phonebook_field, 1);

	url->text = g_strdup(url_val);
	url->type = type;

	contact->urls = g_slist_append(contact->urls, url);
}

static GString *gen_vcards(GSList *contacts,
					const struct apparam_field *params)
{
	GSList *l;
	GString *vcards;

	vcards = g_string_new(NULL);

	/* Generating VCARD string from contacts and freeing used contacts */
	for (l = contacts; l; l = l->next) {
		struct contact_data *c_data = l->data;
		phonebook_add_contact(vcards, c_data->contact,
					params->filter, params->format);
	}

	return vcards;
}

static int pull_contacts_size(const char **reply, int num_fields,
							void *user_data)
{
	struct phonebook_data *data = user_data;

	if (num_fields < 0) {
		data->cb(NULL, 0, num_fields, 0, TRUE, data->user_data);
		return -EINTR;
	}

	if (reply != NULL) {
		data->index = atoi(reply[0]);
		return 0;
	}

	data->cb(NULL, 0, data->index, data->newmissedcalls, TRUE,
							data->user_data);

	return 0;
	/*
	 * phonebook_data is freed in phonebook_req_finalize. Useful in
	 * cases when call is terminated.
	 */
}

static void add_affiliation(char **field, const char *value)
{
	if (strlen(*field) > 0 || value == NULL || strlen(value) == 0)
		return;

	g_free(*field);

	*field = g_strdup(value);
}

static void contact_init(struct phonebook_contact *contact,
							const char **reply)
{
	if (reply[COL_FAMILY_NAME][0] == '\0' &&
			reply[COL_GIVEN_NAME][0] == '\0' &&
			reply[COL_ADDITIONAL_NAME][0] == '\0' &&
			reply[COL_NAME_PREFIX][0] == '\0' &&
			reply[COL_NAME_SUFFIX][0] == '\0') {
		if (reply[COL_FULL_NAME][0] != '\0')
			contact->family = g_strdup(reply[COL_FULL_NAME]);
		else
			contact->family = g_strdup(reply[COL_NICKNAME]);
	} else {
		contact->family = g_strdup(reply[COL_FAMILY_NAME]);
		contact->given = g_strdup(reply[COL_GIVEN_NAME]);
		contact->additional = g_strdup(reply[COL_ADDITIONAL_NAME]);
		contact->prefix = g_strdup(reply[COL_NAME_PREFIX]);
		contact->suffix = g_strdup(reply[COL_NAME_SUFFIX]);
	}
	contact->fullname = g_strdup(reply[COL_FULL_NAME]);
	contact->birthday = g_strdup(reply[COL_BIRTH_DATE]);
	contact->nickname = g_strdup(reply[COL_NICKNAME]);
	contact->photo = g_strdup(reply[COL_PHOTO]);
	contact->company = g_strdup(reply[COL_ORG_NAME]);
	contact->department = g_strdup(reply[COL_ORG_DEPARTMENT]);
	contact->role = g_strdup(reply[COL_ORG_ROLE]);
	contact->uid = g_strdup(reply[COL_UID]);
	contact->title = g_strdup(reply[COL_TITLE]);

	set_call_type(contact, reply[COL_DATE], reply[COL_SENT],
							reply[COL_ANSWERED]);
}

static enum phonebook_number_type get_phone_type(const char *affiliation)
{
	if (g_strcmp0(AFFILIATION_HOME, affiliation) == 0)
		return TEL_TYPE_HOME;
	else if (g_strcmp0(AFFILIATION_WORK, affiliation) == 0)
		return TEL_TYPE_WORK;

	return TEL_TYPE_OTHER;
}

static void add_aff_number(struct phonebook_contact *contact,
				const char *pnumber, const char *aff_type)
{
	char **num_parts;
	char *type, *number;

	/* For phone taken directly from contacts data, phone number string
	 * is represented as number type and number string - those strings are
	 * separated by SUB_DELIM string */
	num_parts = g_strsplit(pnumber, SUB_DELIM, 2);

	if (!num_parts)
		return;

	if (num_parts[0])
		type = num_parts[0];
	else
		goto failed;

	if (num_parts[1])
		number = num_parts[1];
	else
		goto failed;

	if (g_strrstr(type, FAX_NUM_TYPE))
		add_phone_number(contact, number, TEL_TYPE_FAX);
	else if (g_strrstr(type, MOBILE_NUM_TYPE))
		add_phone_number(contact, number, TEL_TYPE_MOBILE);
	else
		/* if this is no fax/mobile phone, then adding phone number
		 * type based on type of the affiliation field
		 */
		add_phone_number(contact, number, get_phone_type(aff_type));

failed:
	g_strfreev(num_parts);
}

static void contact_add_numbers(struct phonebook_contact *contact,
							const char **reply)
{
	char **aff_numbers;
	int i;

	/* Filling phone numbers from contact's affiliation */
	aff_numbers = g_strsplit(reply[COL_PHONE_AFF], MAIN_DELIM, MAX_FIELDS);

	if (aff_numbers)
		for (i = 0; aff_numbers[i]; ++i)
			add_aff_number(contact, aff_numbers[i],
							reply[COL_AFF_TYPE]);

	g_strfreev(aff_numbers);
}

static enum phonebook_field_type get_field_type(const char *affiliation)
{
	if (g_strcmp0(AFFILIATION_HOME, affiliation) == 0)
		return FIELD_TYPE_HOME;
	else if (g_strcmp0(AFFILIATION_WORK, affiliation) == 0)
		return FIELD_TYPE_WORK;

	return FIELD_TYPE_OTHER;
}

static void add_aff_field(struct phonebook_contact *contact,
			const char *aff_email, add_field_t add_field_cb)
{
	char **email_parts;
	char *type, *email;

	/* Emails from affiliation data, are represented as real email
	 * string and affiliation type - those strings are separated by
	 * SUB_DELIM string */
	email_parts = g_strsplit(aff_email, SUB_DELIM, 2);

	if (!email_parts)
		return;

	if (email_parts[0])
		email = email_parts[0];
	else
		goto failed;

	if (email_parts[1])
		type = email_parts[1];
	else
		goto failed;

	add_field_cb(contact, email, get_field_type(type));

failed:
	g_strfreev(email_parts);
}

static void contact_add_emails(struct phonebook_contact *contact,
							const char **reply)
{
	char **aff_emails;
	int i;

	/* Emails from affiliation */
	aff_emails = g_strsplit(reply[COL_EMAIL_AFF], MAIN_DELIM, MAX_FIELDS);

	if (aff_emails)
		for (i = 0; aff_emails[i] != NULL; ++i)
			add_aff_field(contact, aff_emails[i], add_email);

	g_strfreev(aff_emails);
}

static void contact_add_addresses(struct phonebook_contact *contact,
							const char **reply)
{
	char **aff_addr;
	int i;

	/* Addresses from affiliation */
	aff_addr = g_strsplit(reply[COL_ADDR_AFF], MAIN_DELIM, MAX_FIELDS);

	if (aff_addr)
		for (i = 0; aff_addr[i] != NULL; ++i)
			add_aff_field(contact, aff_addr[i], add_address);

	g_strfreev(aff_addr);
}

static void contact_add_urls(struct phonebook_contact *contact,
							const char **reply)
{
	char **aff_url;
	int i;

	/* Addresses from affiliation */
	aff_url = g_strsplit(reply[COL_URL], MAIN_DELIM, MAX_FIELDS);

	if (aff_url)
		for (i = 0; aff_url[i] != NULL; ++i)
			add_aff_field(contact, aff_url[i], add_url);

	g_strfreev(aff_url);
}

static void contact_add_organization(struct phonebook_contact *contact,
							const char **reply)
{
	/* Adding fields connected by nco:hasAffiliation - they may be in
	 * separate replies */
	add_affiliation(&contact->title, reply[COL_TITLE]);
	add_affiliation(&contact->company, reply[COL_ORG_NAME]);
	add_affiliation(&contact->department, reply[COL_ORG_DEPARTMENT]);
	add_affiliation(&contact->role, reply[COL_ORG_ROLE]);
}

static void free_data_contacts(struct phonebook_data *data)
{
	GSList *l;

	/* freeing contacts */
	for (l = data->contacts; l; l = l->next) {
		struct contact_data *c_data = l->data;

		g_free(c_data->id);
		phonebook_contact_free(c_data->contact);
		g_free(c_data);
	}

	g_slist_free(data->contacts);
	data->contacts = NULL;
}

static void send_pull_part(struct phonebook_data *data,
			const struct apparam_field *params, gboolean lastpart)
{
	GString *vcards;

	DBG("");
	vcards = gen_vcards(data->contacts, params);
	data->cb(vcards->str, vcards->len, g_slist_length(data->contacts),
			data->newmissedcalls, lastpart, data->user_data);

	if (!lastpart)
		free_data_contacts(data);
	g_string_free(vcards, TRUE);
}

static int pull_contacts(const char **reply, int num_fields, void *user_data)
{
	struct phonebook_data *data = user_data;
	const struct apparam_field *params = data->params;
	struct phonebook_contact *contact;
	struct contact_data *contact_data;
	int last_index, i;
	gboolean cdata_present = FALSE, part_sent = FALSE;
	static char *temp_id = NULL;

	if (num_fields < 0) {
		data->cb(NULL, 0, num_fields, 0, TRUE, data->user_data);
		goto fail;
	}

	DBG("reply %p", reply);
	data->tracker_index++;

	if (reply == NULL)
		goto done;

	/* Trying to find contact in recently added contacts. It is needed for
	 * contacts that have more than one telephone number filled */
	contact = find_contact(data->contacts, reply[CONTACTS_ID_COL],
							reply[COL_DATE]);

	/* If contact is already created then adding only new phone numbers */
	if (contact) {
		cdata_present = TRUE;
		goto add_numbers;
	}

	/* We are doing a PullvCardEntry, no need for those checks */
	if (data->vcardentry)
		goto add_entry;

	/* Last four fields are always present, ignoring them */
	for (i = 0; i < num_fields - 4; i++) {
		if (reply[i][0] != '\0')
			break;
	}

	if (i == num_fields - 4 && !g_str_equal(reply[CONTACTS_ID_COL],
						TRACKER_DEFAULT_CONTACT_ME))
		return 0;

	if (g_strcmp0(temp_id, reply[CONTACTS_ID_COL])) {
		data->index++;
		g_free(temp_id);
		temp_id = g_strdup(reply[CONTACTS_ID_COL]);

		/* Incrementing counter for vcards in current part of data,
		 * but only if liststartoffset has been already reached */
		if (data->index > params->liststartoffset)
			data->vcard_part_count++;
	}

	if (data->vcard_part_count > VCARDS_PART_COUNT) {
		DBG("Part of vcard data ready for sending...");
		data->vcard_part_count = 0;
		/* Sending part of data to PBAP core - more data can be still
		 * fetched, so marking lastpart as FALSE */
		send_pull_part(data, params, FALSE);

		/* Later, after adding contact data, need to return -EINTR to
		 * stop fetching more data for this request. Data will be
		 * downloaded again from this point, when phonebook_pull_read
		 * will be called again with current request as a parameter*/
		part_sent = TRUE;
	}

	last_index = params->liststartoffset + params->maxlistcount;

	if (data->index <= params->liststartoffset)
		return 0;

	/* max number of results achieved - need send vcards data that was
	 * already collected and stop further data processing (these operations
	 * will be invoked in "done" section) */
	if (data->index > last_index && params->maxlistcount > 0) {
		DBG("Maxlistcount achieved");
		goto done;
	}

add_entry:
	contact = g_new0(struct phonebook_contact, 1);
	contact_init(contact, reply);

add_numbers:
	contact_add_numbers(contact, reply);
	contact_add_emails(contact, reply);
	contact_add_addresses(contact, reply);
	contact_add_urls(contact, reply);
	contact_add_organization(contact, reply);

	DBG("contact %p", contact);

	/* Adding contacts data to wrapper struct - this data will be used to
	 * generate vcard list */
	if (!cdata_present) {
		contact_data = g_new0(struct contact_data, 1);
		contact_data->contact = contact;
		contact_data->id = g_strdup(reply[CONTACTS_ID_COL]);
		data->contacts = g_slist_append(data->contacts, contact_data);
	}

	if (part_sent)
		return -EINTR;

	return 0;

done:
	/* Processing is end, this is definitely last part of transmission
	 * (marking lastpart as TRUE) */
	send_pull_part(data, params, TRUE);

fail:
	g_free(temp_id);
	temp_id = NULL;

	return -EINTR;
	/*
	 * phonebook_data is freed in phonebook_req_finalize. Useful in
	 * cases when call is terminated.
	 */
}

static int add_to_cache(const char **reply, int num_fields, void *user_data)
{
	struct phonebook_data *data = user_data;
	char *formatted;
	int i;

	if (reply == NULL || num_fields < 0)
		goto done;

	/* the first element is the URI, always not empty */
	for (i = 1; i < num_fields; i++) {
		if (reply[i][0] != '\0')
			break;
	}

	if (i == num_fields &&
			!g_str_equal(reply[0], TRACKER_DEFAULT_CONTACT_ME))
		return 0;

	if (i == 7)
		formatted = g_strdup(reply[7]);
	else if (i == 6)
		formatted = g_strdup(reply[6]);
	else
		formatted = g_strdup_printf("%s;%s;%s;%s;%s",
					reply[1], reply[2], reply[3], reply[4],
					reply[5]);

	/* The owner vCard must have the 0 handle */
	if (strcmp(reply[0], TRACKER_DEFAULT_CONTACT_ME) == 0)
		data->entry_cb(reply[0], 0, formatted, "",
						reply[6], data->user_data);
	else
		data->entry_cb(reply[0], PHONEBOOK_INVALID_HANDLE, formatted,
					"", reply[6], data->user_data);

	g_free(formatted);

	return 0;

done:
	if (num_fields <= 0)
		data->ready_cb(data->user_data);

	return -EINTR;
	/*
	 * phonebook_data is freed in phonebook_req_finalize. Useful in
	 * cases when call is terminated.
	 */
}

int phonebook_init(void)
{
	g_type_init();

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
	int ret = 0;
	int len;

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
	if (path && !folder_is_valid(path))
		ret = -ENOENT;

	if (ret < 0) {
		g_free(path);
		path = NULL;
	}

	if (err)
		*err = ret;

	return path;
}

static int pull_newmissedcalls(const char **reply, int num_fields,
							void *user_data)
{
	struct phonebook_data *data = user_data;
	reply_list_foreach_t pull_cb;
	int col_amount, err;
	const char *query;
	int nmissed;

	if (num_fields < 0) {
		data->cb(NULL, 0, num_fields, 0, TRUE, data->user_data);

		return -EINTR;
	}

	if (reply != NULL) {
		nmissed = atoi(reply[0]);
		data->newmissedcalls =
			nmissed <= UINT8_MAX ? nmissed : UINT8_MAX;
		DBG("newmissedcalls %d", data->newmissedcalls);

		return 0;
	}

	if (data->params->maxlistcount == 0) {
		query = name2count_query(PB_CALLS_MISSED);
		col_amount = COUNT_QUERY_COL_AMOUNT;
		pull_cb = pull_contacts_size;
	} else {
		query = name2query(PB_CALLS_MISSED);
		col_amount = PULL_QUERY_COL_AMOUNT;
		pull_cb = pull_contacts;
	}

	err = query_tracker(query, col_amount, pull_cb, data);
	if (err < 0) {
		data->cb(NULL, 0, err, 0, TRUE, data->user_data);

		return -EINTR;
	}

	return 0;
}

void phonebook_req_finalize(void *request)
{
	struct phonebook_data *data = request;

	DBG("");

	if (!data)
		return;

	/* canceling asynchronous operation on tracker if any is active */
	if (data->query_canc) {
		g_cancellable_cancel(data->query_canc);
		g_object_unref(data->query_canc);
	}

	free_data_contacts(data);
	g_free(data->req_name);
	g_free(data);
}

void *phonebook_pull(const char *name, const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct phonebook_data *data;

	DBG("name %s", name);

	data = g_new0(struct phonebook_data, 1);
	data->params = params;
	data->user_data = user_data;
	data->cb = cb;
	data->req_name = g_strdup(name);

	if (err)
		*err = 0;

	return data;
}

int phonebook_pull_read(void *request)
{
	struct phonebook_data *data = request;
	reply_list_foreach_t pull_cb;
	const char *query;
	char *offset_query;
	int col_amount;
	int ret;

	if (!data)
		return -ENOENT;

	data->newmissedcalls = 0;

	if (g_strcmp0(data->req_name, PB_CALLS_MISSED) == 0 &&
						data->tracker_index == 0) {
		/* new missed calls amount should be counted only once - it
		 * will be done during generating first part of results of
		 * missed calls history */
		query = NEW_MISSED_CALLS_COUNT_QUERY;
		col_amount = COUNT_QUERY_COL_AMOUNT;
		pull_cb = pull_newmissedcalls;
	} else if (data->params->maxlistcount == 0) {
		query = name2count_query(data->req_name);
		col_amount = COUNT_QUERY_COL_AMOUNT;
		pull_cb = pull_contacts_size;
	} else {
		query = name2query(data->req_name);
		col_amount = PULL_QUERY_COL_AMOUNT;
		pull_cb = pull_contacts;
	}

	if (query == NULL)
		return -ENOENT;

	if (pull_cb == pull_contacts && data->tracker_index > 0) {
		/* Adding offset to pull query to download next parts of data
		 * from tracker (phonebook_pull_read may be called many times
		 * from PBAP core to fetch data partially) */
		offset_query = g_strdup_printf(QUERY_OFFSET_FORMAT, query,
							data->tracker_index);
		ret = query_tracker(offset_query, col_amount, pull_cb, data);

		g_free(offset_query);

		return ret;
	}

	return query_tracker(query, col_amount, pull_cb, data);
}

void *phonebook_get_entry(const char *folder, const char *id,
				const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct phonebook_data *data;
	char *query;
	int ret;

	DBG("folder %s id %s", folder, id);

	data = g_new0(struct phonebook_data, 1);
	data->user_data = user_data;
	data->params = params;
	data->cb = cb;
	data->vcardentry = TRUE;

	if (g_str_has_prefix(id, CONTACT_ID_PREFIX) == TRUE ||
				g_strcmp0(id, TRACKER_DEFAULT_CONTACT_ME) == 0)
		query = g_strdup_printf(CONTACTS_QUERY_FROM_URI, id, id, id, id,
					id, id, id, id, id, id, id, id, id);
	else if (g_str_has_prefix(id, CALL_ID_PREFIX) == TRUE)
		query = g_strdup_printf(CONTACT_FROM_CALL_QUERY, id);
	else
		query = g_strdup_printf(CONTACTS_OTHER_QUERY_FROM_URI,
								id, id, id);

	ret = query_tracker(query, PULL_QUERY_COL_AMOUNT, pull_contacts, data);
	if (err)
		*err = ret;

	g_free(query);

	return data;
}

void *phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, void *user_data, int *err)
{
	struct phonebook_data *data;
	const char *query;
	int ret;

	DBG("name %s", name);

	query = folder2query(name);
	if (query == NULL) {
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	data = g_new0(struct phonebook_data, 1);
	data->entry_cb = entry_cb;
	data->ready_cb = ready_cb;
	data->user_data = user_data;

	ret = query_tracker(query, 8, add_to_cache, data);
	if (err)
		*err = ret;

	return data;
}
