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
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "log.h"
#include "obex.h"
#include "service.h"
#include "mimetype.h"
#include "phonebook.h"
#include "dbus.h"
#include "vcard.h"

#define TRACKER_SERVICE "org.freedesktop.Tracker1"
#define TRACKER_RESOURCES_PATH "/org/freedesktop/Tracker1/Resources"
#define TRACKER_RESOURCES_INTERFACE "org.freedesktop.Tracker1.Resources"

#define TRACKER_DEFAULT_CONTACT_ME "http://www.semanticdesktop.org/ontologies/2007/03/22/nco#default-contact-me"
#define CONTACTS_ID_COL 38
#define PULL_QUERY_COL_AMOUNT 39
#define COL_HOME_NUMBER 0
#define COL_HOME_EMAIL 7
#define COL_WORK_NUMBER 8
#define COL_FAX_NUMBER 16
#define COL_WORK_EMAIL 17
#define COL_OTHER_NUMBER 34
#define COL_DATE 35
#define COL_SENT 36
#define COL_ANSWERED 37
#define ADDR_FIELD_AMOUNT 7

#define CONTACTS_QUERY_ALL						\
	"SELECT ?v nco:fullname(?c) "					\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) ?f nco:emailAddress(?ew) "	\
	"nco:birthDate(?c) nco:nickname(?c) nco:url(?c) "		\
	"nco:photo(?c) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(?c) "	\
	"nco:title(?a) nco:phoneNumber(?t) "				\
	"\"NOTACALL\" \"false\" \"false\" ?c "				\
	"WHERE { "							\
		"?c a nco:PersonContact . "				\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . 				\
		OPTIONAL {"						\
		"?h a nco:FaxNumber ; "					\
		"nco:phoneNumber ?f . "					\
		"}"							\
		"OPTIONAL {"						\
		"?h a nco:VoicePhoneNumber ; "				\
		"nco:phoneNumber ?v"					\
		"}"							\
	"}"								\
	"OPTIONAL { ?c nco:hasEmailAddress ?e . } "			\
	"OPTIONAL { ?c nco:hasPostalAddress ?p . } "			\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"OPTIONAL { ?a nco:hasPhoneNumber ?w . } " 		\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
	"} "								\
	"}"

#define CONTACTS_QUERY_ALL_LIST						\
	"SELECT ?c nco:nameFamily(?c) "					\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?c a nco:PersonContact . "				\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "			\
	"OPTIONAL { "							\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?h . "				\
	"} "								\
	"} GROUP BY ?c"

#define MISSED_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) \"\" nco:emailAddress(?ew) "\
	"nco:birthDate(?c) nco:nickname(?c) nco:url(?c) "		\
	"nco:photo(?c) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(?c) "	\
	"nco:title(?a) nco:phoneNumber(?t) nmo:receivedDate(?call) "	\
	"nmo:isSent(?call) nmo:isAnswered(?call) ?x "			\
	"WHERE { "							\
	"{ "								\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?h . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false . "				\
		"?c a nco:PersonContact . "				\
		"?c nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "	\
			"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "	\
			"OPTIONAL { ?a nco:org ?o . } "			\
		"} "							\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?w . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false . "				\
		"?c a nco:PersonContact . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?t . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false . "				\
	"} "								\
	"} ORDER BY DESC(nmo:receivedDate(?call)) "

#define MISSED_CALLS_LIST						\
	"SELECT ?c nco:nameFamily(?c) "					\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered false ."				\
		"?c a nco:Contact . "					\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "			\
	"} ORDER BY DESC(nmo:receivedDate(?call))"

#define INCOMING_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) \"\" nco:emailAddress(?ew) "\
	"nco:birthDate(?c) nco:nickname(?c) nco:url(?c) "		\
	"nco:photo(?c) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(?c) "	\
	"nco:title(?a) nco:phoneNumber(?t) nmo:receivedDate(?call) "	\
	"nmo:isSent(?call) nmo:isAnswered(?call) ?x "			\
	"WHERE { "							\
	"{ "								\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?h . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered true . "				\
		"?c a nco:PersonContact . "				\
		"?c nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "	\
			"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "	\
			"OPTIONAL { ?a nco:org ?o . } "			\
		"} "							\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?w . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered true . "				\
		"?c a nco:PersonContact . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?t . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered true . "				\
	"} "								\
	"} ORDER BY DESC(nmo:receivedDate(?call)) "

#define INCOMING_CALLS_LIST						\
	"SELECT ?c nco:nameFamily(?c) "					\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false ; "					\
		"nmo:isAnswered true ."					\
		"?c a nco:Contact . "					\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "			\
	"} ORDER BY DESC(nmo:receivedDate(?call))"

#define OUTGOING_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) \"\" nco:emailAddress(?ew)"	\
	"nco:birthDate(?c) nco:nickname(?c) nco:url(?c) "		\
	"nco:photo(?c) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(?c) "	\
	"nco:title(?a) nco:phoneNumber(?t) nmo:receivedDate(?call) "	\
	"nmo:isSent(?call) nmo:isAnswered(?call) ?x "			\
	"WHERE { "							\
	"{ "								\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?h . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact . "				\
		"?c nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "	\
			"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "	\
			"OPTIONAL { ?a nco:org ?o . } "			\
		"} "							\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?w . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
	"} UNION { "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?t . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
	"} "								\
	"} ORDER BY DESC(nmo:sentDate(?call)) "

#define OUTGOING_CALLS_LIST						\
	"SELECT ?c nco:nameFamily(?c) "					\
	"nco:nameGiven(?c) nco:nameAdditional(?c) "			\
	"nco:nameHonorificPrefix(?c) nco:nameHonorificSuffix(?c) "	\
	"nco:phoneNumber(?h) "						\
	"WHERE { "							\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:Contact . "					\
	"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "			\
	"} ORDER BY DESC(nmo:sentDate(?call))"

#define COMBINED_CALLS_QUERY						\
	"SELECT nco:phoneNumber(?h) nco:fullname(?c) "			\
	"nco:nameFamily(?c) nco:nameGiven(?c) "				\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) \"\" nco:emailAddress(?ew) "\
	"nco:birthDate(?c) nco:nickname(?c) nco:url(?c) "		\
	"nco:photo(?c) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(?c) "	\
	"nco:title(?a) nco:phoneNumber(?t) nmo:receivedDate(?call) "	\
	"nmo:isSent(?call) nmo:isAnswered(?call) ?x "			\
	"WHERE { "							\
	"{ "								\
		"{ "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?h . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact . "				\
		"?c nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "	\
			"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "	\
			"OPTIONAL { ?a nco:org ?o . } "			\
		"} "							\
		"} UNION { "						\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?w . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
		"?c a nco:PersonContact . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
		"} UNION { "						\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?t . "				\
		"?call a nmo:Call ; "					\
		"nmo:to ?x ; "						\
		"nmo:isSent true . "					\
		"} "							\
	"} UNION { "							\
		"{ "							\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?h . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact . "				\
		"?c nco:hasPhoneNumber ?h . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"OPTIONAL { "						\
			"?c nco:hasAffiliation ?a . "			\
			"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "	\
			"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "	\
			"OPTIONAL { ?a nco:org ?o . } "			\
		"} "							\
		"} UNION { "						\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?w . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false . "					\
		"?c a nco:PersonContact . "				\
		"OPTIONAL { ?c nco:hasEmailAddress ?e . } "		\
		"OPTIONAL { ?c nco:hasPostalAddress ?p . } "		\
		"?c nco:hasAffiliation ?a . "				\
		"?a nco:hasPhoneNumber ?w . "				\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . } "		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
		"} UNION { "						\
		"?x a nco:Contact . "					\
		"?x nco:hasPhoneNumber ?t . "				\
		"?call a nmo:Call ; "					\
		"nmo:from ?x ; "					\
		"nmo:isSent false . "					\
		"} "							\
	"} "								\
	"} ORDER BY DESC(nmo:receivedDate(?call)) "

#define COMBINED_CALLS_LIST						\
	"SELECT ?c nco:nameFamily(?c) nco:nameGiven(?c) "		\
	"nco:nameAdditional(?c) nco:nameHonorificPrefix(?c) "		\
	"nco:nameHonorificSuffix(?c) nco:phoneNumber(?h) "		\
	"WHERE { "							\
	"{ "								\
		"?call a nmo:Call ; "					\
		"nmo:to ?c ; "						\
		"nmo:isSent true . "					\
		"?c a nco:Contact . "					\
		"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "		\
	"} UNION { "							\
		"?call a nmo:Call ; "					\
		"nmo:from ?c ; "					\
		"nmo:isSent false . "					\
		"?c a nco:Contact . "					\
		"OPTIONAL { ?c nco:hasPhoneNumber ?h . } "		\
	"} } ORDER BY DESC(nmo:receivedDate(?call))"


#define CONTACTS_QUERY_FROM_URI						\
	"SELECT ?v nco:fullname(<%s>) "					\
	"nco:nameFamily(<%s>) nco:nameGiven(<%s>) "			\
	"nco:nameAdditional(<%s>) nco:nameHonorificPrefix(<%s>) "	\
	"nco:nameHonorificSuffix(<%s>) nco:emailAddress(?e) "		\
	"nco:phoneNumber(?w) nco:pobox(?p) nco:extendedAddress(?p) "	\
	"nco:streetAddress(?p) nco:locality(?p) nco:region(?p) "	\
	"nco:postalcode(?p) nco:country(?p) ?f  nco:emailAddress(?ew)"	\
	"nco:birthDate(<%s>) nco:nickname(<%s>) nco:url(<%s>) "		\
	"nco:photo(<%s>) nco:fullname(?o) nco:department(?a) "		\
	"nco:role(?a) nco:pobox(?pw) nco:extendedAddress(?pw) "		\
	"nco:streetAddress(?pw) nco:locality(?pw) nco:region(?pw) "	\
	"nco:postalcode(?pw) nco:country(?pw) nco:contactUID(<%s>) "	\
	"nco:title(?a) nco:phoneNumber(?t) "				\
	"\"NOTACALL\" \"false\" \"false\" <%s> "			\
	"WHERE { "							\
		"<%s> a nco:Contact . "					\
	"OPTIONAL { <%s> nco:hasPhoneNumber ?h . 			\
		OPTIONAL {"						\
		"?h a nco:FaxNumber ; "					\
		"nco:phoneNumber ?f . "					\
		"}"							\
		"OPTIONAL {"						\
		"?h a nco:VoicePhoneNumber ; "				\
		"nco:phoneNumber ?v"					\
		"}"							\
	"}"								\
	"OPTIONAL { <%s> nco:hasEmailAddress ?e . } "			\
	"OPTIONAL { <%s> nco:hasPostalAddress ?p . } "			\
	"OPTIONAL { "							\
		"<%s> nco:hasAffiliation ?a . "				\
		"OPTIONAL { ?a nco:hasPhoneNumber ?w . }" 		\
		"OPTIONAL { ?a nco:hasEmailAddress ?ew . }"		\
		"OPTIONAL { ?a nco:hasPostalAddress ?pw . } "		\
		"OPTIONAL { ?a nco:org ?o . } "				\
	"} "								\
	"}"

typedef void (*reply_list_foreach_t) (char **reply, int num_fields,
		void *user_data);

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
	if (folder == NULL)
		return FALSE;

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

static char *iso8601_utc_to_localtime(const char *datetime)
{
	time_t time;
	struct tm tm, *local;
	char localdate[32];
	char tz;
	int nr;

	memset(&tm, 0, sizeof(tm));

	nr = sscanf(datetime, "%04u-%02u-%02uT%02u:%02u:%02u%c",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec,
			&tz);
	if (nr < 6) {
		/* Invalid time format */
		error("sscanf(): %s (%d)", strerror(errno), errno);
		return g_strdup("");
	}

	/* Time already in localtime */
	if (nr == 6) {
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

static struct phonebook_contact *find_contact(GSList *contacts, const char *id)
{
	GSList *l;
	struct contact_data *c_data;

	for (l = contacts; l; l = l->next) {
		c_data = l->data;
		if (g_strcmp0(c_data->id, id) == 0)
			return c_data->contact;
	}

	return NULL;
}

static struct phonebook_number *find_phone(GSList *numbers, const char *phone,
								int type)
{
	GSList *l = numbers;
	struct phonebook_number *pb_num;

	if (g_slist_length(l) == 1 && (pb_num = l->data) &&
					g_strcmp0(pb_num->tel, phone) == 0) {

		if ((type == TEL_TYPE_HOME || type == TEL_TYPE_WORK) &&
					pb_num->type == TEL_TYPE_OTHER)	{
			pb_num->type = type;
			return pb_num;
		}

		if (type == TEL_TYPE_OTHER && (pb_num->type == TEL_TYPE_HOME ||
					pb_num->type == TEL_TYPE_WORK))
			return pb_num;
	}

	for (; l; l = l->next) {
		pb_num = l->data;
		/* Returning phonebook number if phone values and type values
		 * are equal */
		if (g_strcmp0(pb_num->tel, phone) == 0 && pb_num->type == type)
			return pb_num;
	}

	return NULL;
}

static void add_phone_number(struct phonebook_contact *contact,
						const char *phone, int type)
{
	struct phonebook_number *number;

	if (phone == NULL || strlen(phone) == 0)
		return;

	/* Not adding number if there is already added with the same value */
	if (find_phone(contact->numbers, phone, type))
		return;

	number = g_new0(struct phonebook_number, 1);
	number->tel = g_strdup(phone);
	number->type = type;

	contact->numbers = g_slist_append(contact->numbers, number);
}

static struct phonebook_email *find_email(GSList *emails, const char *address,
								int type)
{
	GSList *l;

	for (l = emails; l; l = l->next) {
		struct phonebook_email *email = l->data;
		if (g_strcmp0(email->address, address) == 0 &&
						email->type == type)
			return email;
	}

	return NULL;
}

static void add_email(struct phonebook_contact *contact, const char *address,
								int type)
{
	struct phonebook_email *email;

	if (address == NULL || strlen(address) == 0)
		return;

	/* Not adding email if there is already added with the same value */
	if (find_email(contact->emails, address, type))
		return;

	email = g_new0(struct phonebook_email, 1);
	email->address = g_strdup(address);
	email->type = type;

	contact->emails = g_slist_append(contact->emails, email);
}

static struct phonebook_address *find_address(GSList *addresses,
					const char *address, int type)
{
	GSList *l;

	for (l = addresses; l; l = l->next) {
		struct phonebook_address *addr = l->data;
		if (g_strcmp0(addr->addr, address) == 0 &&
						addr->type == type)
			return addr;
	}

	return NULL;
}

static void add_address(struct phonebook_contact *contact,
					const char *address, int type)
{
	struct phonebook_address *addr;

	if (address == NULL || address_fields_present(address) == FALSE)
		return;

	/* Not adding address if there is already added with the same value */
	if (find_address(contact->addresses, address, type))
		return;

	addr = g_new0(struct phonebook_address, 1);

	addr->addr = g_strdup(address);
	addr->type = type;

	contact->addresses = g_slist_append(contact->addresses, addr);
}

static GString *gen_vcards(GSList *contacts,
					const struct apparam_field *params)
{
	GSList *l;
	GString *vcards;
	struct contact_data *c_data;

	vcards = g_string_new(NULL);

	/* Generating VCARD string from contacts and freeing used contacts */
	for (l = contacts; l; l = l->next) {
		c_data = l->data;
		phonebook_add_contact(vcards, c_data->contact,
					params->filter, params->format);

		g_free(c_data->id);
		phonebook_contact_free(c_data->contact);
		g_free(c_data);
	}

	return vcards;
}

static void pull_contacts(char **reply, int num_fields, void *user_data)
{
	struct phonebook_data *data = user_data;
	const struct apparam_field *params = data->params;
	struct phonebook_contact *contact;
	struct contact_data *contact_data;
	GString *vcards;
	int last_index, i;
	gboolean cdata_present = FALSE;
	char *home_addr, *work_addr;

	if (num_fields < 0) {
		data->cb(NULL, 0, num_fields, 0, data->user_data);
		goto fail;
	}

	DBG("reply %p", reply);

	if (reply == NULL)
		goto done;

	/* Trying to find contact in recently added contacts. It is needed for
	 * contacts that have more than one telephone number filled */
	contact = find_contact(data->contacts, reply[CONTACTS_ID_COL]);

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

	if (i == num_fields - 4 &&
			!g_str_equal(reply[CONTACTS_ID_COL],
					TRACKER_DEFAULT_CONTACT_ME))
		return;

	data->index++;

	last_index = params->liststartoffset + params->maxlistcount;

	if ((data->index <= params->liststartoffset ||
			data->index > last_index) &&
			params->maxlistcount > 0)
		return;

add_entry:
	contact = g_new0(struct phonebook_contact, 1);
	contact->fullname = g_strdup(reply[1]);
	contact->family = g_strdup(reply[2]);
	contact->given = g_strdup(reply[3]);
	contact->additional = g_strdup(reply[4]);
	contact->prefix = g_strdup(reply[5]);
	contact->suffix = g_strdup(reply[6]);
	contact->birthday = g_strdup(reply[18]);
	contact->nickname = g_strdup(reply[19]);
	contact->website = g_strdup(reply[20]);
	contact->photo = g_strdup(reply[21]);
	contact->company = g_strdup(reply[22]);
	contact->department = g_strdup(reply[23]);
	contact->role = g_strdup(reply[24]);
	contact->uid = g_strdup(reply[32]);
	contact->title = g_strdup(reply[33]);

	set_call_type(contact, reply[COL_DATE], reply[COL_SENT],
			reply[COL_ANSWERED]);

add_numbers:
	/* Adding phone numbers to contact struct */
	add_phone_number(contact, reply[COL_HOME_NUMBER], TEL_TYPE_HOME);
	add_phone_number(contact, reply[COL_WORK_NUMBER], TEL_TYPE_WORK);
	add_phone_number(contact, reply[COL_FAX_NUMBER], TEL_TYPE_FAX);
	add_phone_number(contact, reply[COL_OTHER_NUMBER], TEL_TYPE_OTHER);

	/* Adding emails */
	add_email(contact, reply[COL_HOME_EMAIL], EMAIL_TYPE_HOME);
	add_email(contact, reply[COL_WORK_EMAIL], EMAIL_TYPE_WORK);

	/* Adding addresses */
	home_addr = g_strdup_printf("%s;%s;%s;%s;%s;%s;%s",
				reply[9], reply[10], reply[11], reply[12],
				reply[13], reply[14], reply[15]);

	work_addr = g_strdup_printf("%s;%s;%s;%s;%s;%s;%s",
				reply[25], reply[26], reply[27], reply[28],
				reply[29], reply[30], reply[31]);

	add_address(contact, home_addr, ADDR_TYPE_HOME);
	add_address(contact, work_addr, ADDR_TYPE_WORK);

	g_free(home_addr);
	g_free(work_addr);

	DBG("contact %p", contact);

	/* Adding contacts data to wrapper struct - this data will be used to
	 * generate vcard list */
	if (!cdata_present) {
		contact_data = g_new0(struct contact_data, 1);
		contact_data->contact = contact;
		contact_data->id = g_strdup(reply[CONTACTS_ID_COL]);
		data->contacts = g_slist_append(data->contacts, contact_data);
	}

	return;

done:
	vcards = gen_vcards(data->contacts, params);

	if (num_fields == 0)
		data->cb(vcards->str, vcards->len,
				g_slist_length(data->contacts), 0,
				data->user_data);

	g_string_free(vcards, TRUE);
fail:
	g_slist_free(data->contacts);
	g_free(data);
}

static void add_to_cache(char **reply, int num_fields, void *user_data)
{
	struct cache_data *cache = user_data;
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
		return;

	if (i == 6)
		formatted = g_strdup(reply[6]);
	else
		formatted = g_strdup_printf("%s;%s;%s;%s;%s",
					reply[1], reply[2], reply[3], reply[4],
					reply[5]);

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
	if (num_fields <= 0)
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
	if (ret || !folder_is_valid(path)) {
		g_free(path);
		path = NULL;
		ret = ret ? ret : -ENOENT;
	}

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
	data->params = params;
	data->user_data = user_data;
	data->cb = cb;

	return query_tracker(query, PULL_QUERY_COL_AMOUNT, pull_contacts, data);
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
	data->user_data = user_data;
	data->params = params;
	data->cb = cb;
	data->vcardentry = TRUE;

	query = g_strdup_printf(CONTACTS_QUERY_FROM_URI, id, id, id, id, id,
						id, id, id, id, id, id, id,
						id, id, id, id, id);

	ret = query_tracker(query, PULL_QUERY_COL_AMOUNT, pull_contacts, data);

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
