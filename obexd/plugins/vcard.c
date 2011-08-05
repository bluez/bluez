/*
 * OBEX Server
 *
 * Copyright (C) 2008-2010 Intel Corporation.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "vcard.h"
#include "glib-helper.h"

#define ADDR_FIELD_AMOUNT 7
#define LEN_MAX 128
#define TYPE_INTERNATIONAL 145

#define PHONEBOOK_FLAG_CACHED 0x1

#define FILTER_VERSION (1 << 0)
#define FILTER_FN (1 << 1)
#define FILTER_N (1 << 2)
#define FILTER_PHOTO (1 << 3)
#define FILTER_BDAY (1 << 4)
#define FILTER_ADR (1 << 5)
#define FILTER_LABEL (1 << 6)
#define FILTER_TEL (1 << 7)
#define FILTER_EMAIL (1 << 8)
#define FILTER_MAILER (1 << 9)
#define FILTER_TZ (1 << 10)
#define FILTER_GEO (1 << 11)
#define FILTER_TITLE (1 << 12)
#define FILTER_ROLE (1 << 13)
#define FILTER_LOGO (1 << 14)
#define FILTER_AGENT (1 << 15)
#define FILTER_ORG (1 << 16)
#define FILTER_NOTE (1 << 17)
#define FILTER_REV (1 << 18)
#define FILTER_SOUND (1 << 19)
#define FILTER_URL (1 << 20)
#define FILTER_UID (1 << 21)
#define FILTER_KEY (1 << 22)
#define FILTER_NICKNAME (1 << 23)
#define FILTER_CATEGORIES (1 << 24)
#define FILTER_PROID (1 << 25)
#define FILTER_CLASS (1 << 26)
#define FILTER_SORT_STRING (1 << 27)
#define FILTER_X_IRMC_CALL_DATETIME (1 << 28)

#define FORMAT_VCARD21 0x00
#define FORMAT_VCARD30 0x01

/* according to RFC 2425, the output string may need folding */
static void vcard_printf(GString *str, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int len_temp, line_number, i;
	unsigned int line_delimit = 75;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	line_number = strlen(buf) / line_delimit + 1;

	for (i = 0; i < line_number; i++) {
		len_temp = MIN(line_delimit, strlen(buf) - line_delimit * i);
		g_string_append_len(str,  buf + line_delimit * i, len_temp);
		if (i != line_number - 1)
			g_string_append(str, "\r\n ");
	}

	g_string_append(str, "\r\n");
}

/* According to RFC 2426, we need escape following characters:
 *  '\n', '\r', ';', ',', '\'.
 */
static void add_slash(char *dest, const char *src, int len_max, int len)
{
	int i, j;

	for (i = 0, j = 0; i < len && j + 1 < len_max; i++, j++) {
		/* filling dest buffer - last field need to be reserved
		 * for '\0'*/
		switch (src[i]) {
		case '\n':
			if (j + 2 >= len_max)
				/* not enough space in the buffer to put char
				 * preceded with escaping sequence (and '\0' in
				 * the end) */
				goto done;

			dest[j++] = '\\';
			dest[j] = 'n';
			break;
		case '\r':
			if (j + 2 >= len_max)
				goto done;

			dest[j++] = '\\';
			dest[j] = 'r';
			break;
		case '\\':
		case ';':
		case ',':
			if (j + 2 >= len_max)
				goto done;

			dest[j++] = '\\';
		default:
			dest[j] = src[i];
			break;
		}
	}

done:
	dest[j] = 0;
}

static void get_escaped_fields(char **fields, ...)
{
	va_list ap;
	GString *line;
	char *field;
	char escaped[LEN_MAX];

	va_start(ap, fields);
	line = g_string_new("");

	for (field = va_arg(ap, char *); field; ) {
		add_slash(escaped, field, LEN_MAX, strlen(field));
		g_string_append(line, escaped);

		field = va_arg(ap, char *);

		if (field)
			g_string_append(line, ";");
	}

	va_end(ap);

	*fields = g_string_free(line, FALSE);
}

static void vcard_printf_begin(GString *vcards, uint8_t format)
{
	vcard_printf(vcards, "BEGIN:VCARD");

	if (format == FORMAT_VCARD30)
		vcard_printf(vcards, "VERSION:3.0");
	else if (format == FORMAT_VCARD21)
		vcard_printf(vcards, "VERSION:2.1");
}

/* check if there is at least one contact field with personal data present */
static gboolean contact_fields_present(struct phonebook_contact * contact)
{
	if (contact->family && strlen(contact->family) > 0)
		return TRUE;

	if (contact->given && strlen(contact->given) > 0)
		return TRUE;

	if (contact->additional && strlen(contact->additional) > 0)
		return TRUE;

	if (contact->prefix && strlen(contact->prefix) > 0)
		return TRUE;

	if (contact->suffix && strlen(contact->suffix) > 0)
		return TRUE;

	/* none of the personal data fields are present*/
	return FALSE;
}

gboolean address_fields_present(const char *address)
{
	gchar **fields = g_strsplit(address, ";", ADDR_FIELD_AMOUNT);
	int i;

	for (i = 0; i < ADDR_FIELD_AMOUNT; ++i) {

		if (strlen(fields[i]) != 0) {
			g_strfreev(fields);
			return TRUE;
		}
	}

	g_strfreev(fields);

	return FALSE;
}

static void vcard_printf_name(GString *vcards,
					struct phonebook_contact *contact)
{
	char *fields;

	if (contact_fields_present(contact) == FALSE) {
		/* If fields are empty, add only 'N:' as parameter.
		 * This is crucial for some devices (Nokia BH-903) which
		 * have problems with history listings and can't determine
		 * that a parameter is really empty if there are unnecessary
		 * characters after 'N:' (e.g. 'N:;;;;').
		 * We need to add only'N:' param - without semicolons.
		 */
		vcard_printf(vcards, "N:");
		return;
	}


	get_escaped_fields(&fields, contact->family,
				contact->given, contact->additional,
				contact->prefix, contact->suffix,
				NULL);

	vcard_printf(vcards, "N:%s", fields);

	g_free(fields);
}

static void vcard_printf_fullname(GString *vcards, const char *text)
{
	char field[LEN_MAX];
	add_slash(field, text, LEN_MAX, strlen(text));
	vcard_printf(vcards, "FN:%s", field);
}

static void vcard_printf_number(GString *vcards, uint8_t format,
					const char *number, int type,
					enum phonebook_number_type category)
{
	const char *intl = "", *category_string = "";
	char buf[128];

	/* TEL is a mandatory field, include even if empty */
	if (!number || !strlen(number) || !type) {
		vcard_printf(vcards, "TEL:");
		return;
	}

	switch (category) {
	case TEL_TYPE_HOME:
		if (format == FORMAT_VCARD21)
			category_string = "HOME;VOICE";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=HOME;TYPE=VOICE";
		break;
	case TEL_TYPE_MOBILE:
		if (format == FORMAT_VCARD21)
			category_string = "CELL;VOICE";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=CELL;TYPE=VOICE";
		break;
	case TEL_TYPE_FAX:
		if (format == FORMAT_VCARD21)
			category_string = "FAX";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=FAX";
		break;
	case TEL_TYPE_WORK:
		if (format == FORMAT_VCARD21)
			category_string = "WORK;VOICE";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=WORK;TYPE=VOICE";
		break;
	case TEL_TYPE_OTHER:
		if (format == FORMAT_VCARD21)
			category_string = "OTHER;VOICE";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=OTHER;TYPE=VOICE";
		break;
	}

	if ((type == TYPE_INTERNATIONAL) && (number[0] != '+'))
		intl = "+";

	snprintf(buf, sizeof(buf), "TEL;%s:%s\%s", category_string,
								intl, number);

	vcard_printf(vcards, buf, number);
}

static void vcard_printf_tag(GString *vcards, uint8_t format,
					const char *tag, const char *category,
					const char *fld)
{
	int len;
	char *separator = "", *type = "";
	char buf[LEN_MAX], field[LEN_MAX];

	if (tag == NULL || strlen(tag) == 0)
		return;

	if (fld == NULL || (len = strlen(fld)) == 0) {
		vcard_printf(vcards, "%s:", tag);
		return;
	}

	if (category && strlen(category)) {
		separator = ";";
		if (format == FORMAT_VCARD30)
			type = "TYPE=";
	} else {
		category = "";
	}

	snprintf(buf, LEN_MAX, "%s%s%s%s", tag, separator, type, category);

	add_slash(field, fld, LEN_MAX, len);
	vcard_printf(vcards, "%s:%s", buf, field);
}

static void vcard_printf_email(GString *vcards, uint8_t format,
					const char *address,
					enum phonebook_field_type category)
{
	const char *category_string = "";
	char field[LEN_MAX];
	int len = 0;

	if (!address || !(len = strlen(address))) {
		vcard_printf(vcards, "EMAIL:");
		return;
	}
	switch (category) {
	case FIELD_TYPE_HOME:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET;HOME";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET;TYPE=HOME";
		break;
	case FIELD_TYPE_WORK:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET;WORK";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET;TYPE=WORK";
		break;
	default:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET;TYPE=OTHER";
	}

	add_slash(field, address, LEN_MAX, len);
	vcard_printf(vcards, "EMAIL;%s:%s", category_string, field);
}

static void vcard_printf_url(GString *vcards, uint8_t format,
					const char *url,
					enum phonebook_field_type category)
{
	const char *category_string = "";
	char field[LEN_MAX];

	if (!url || strlen(url) == 0) {
		vcard_printf(vcards, "URL:");
		return;
	}

	switch (category) {
	case FIELD_TYPE_HOME:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET;HOME";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET;TYPE=HOME";
		break;
	case FIELD_TYPE_WORK:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET;WORK";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET;TYPE=WORK";
		break;
	default:
		if (format == FORMAT_VCARD21)
			category_string = "INTERNET";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=INTERNET";
		break;
	}

	add_slash(field, url, LEN_MAX, strlen(url));
	vcard_printf(vcards, "URL;%s:%s", category_string, field);
}

static gboolean org_fields_present(struct phonebook_contact *contact)
{
	if (contact->company && strlen(contact->company))
		return TRUE;

	if (contact->department && strlen(contact->department))
		return TRUE;

	return FALSE;
}

static void vcard_printf_org(GString *vcards,
					struct phonebook_contact *contact)
{
	char *fields;

	if (org_fields_present(contact) == FALSE)
		return;

	get_escaped_fields(&fields, contact->company,
					contact->department, NULL);

	vcard_printf(vcards, "ORG:%s", fields);

	g_free(fields);
}

static void vcard_printf_address(GString *vcards, uint8_t format,
					const char *address,
					enum phonebook_field_type category)
{
	char buf[LEN_MAX];
	char field[ADDR_FIELD_AMOUNT][LEN_MAX];
	const char *category_string = "";
	int len, i;
	gchar **address_fields;

	if (!address || address_fields_present(address) == FALSE) {
		vcard_printf(vcards, "ADR:");
		return;
	}

	switch (category) {
	case FIELD_TYPE_HOME:
		if (format == FORMAT_VCARD21)
			category_string = "HOME";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=HOME";
		break;
	case FIELD_TYPE_WORK:
		if (format == FORMAT_VCARD21)
			category_string = "WORK";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=WORK";
		break;
	default:
		if (format == FORMAT_VCARD21)
			category_string = "OTHER";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=OTHER";
		break;
	}

	address_fields = g_strsplit(address, ";", ADDR_FIELD_AMOUNT);

	for (i = 0; i < ADDR_FIELD_AMOUNT; ++i) {
		len = strlen(address_fields[i]);
		add_slash(field[i], address_fields[i], LEN_MAX, len);
	}

	snprintf(buf, LEN_MAX, "%s;%s;%s;%s;%s;%s;%s",
	field[0], field[1], field[2], field[3], field[4], field[5], field[6]);
	g_strfreev(address_fields);

	vcard_printf(vcards,"ADR;%s:%s", category_string, buf);
}

static void vcard_printf_datetime(GString *vcards,
					struct phonebook_contact *contact)
{
	const char *type;

	switch (contact->calltype) {
	case CALL_TYPE_MISSED:
		type = "MISSED";
		break;

	case CALL_TYPE_INCOMING:
		type = "RECEIVED";
		break;

	case CALL_TYPE_OUTGOING:
		type = "DIALED";
		break;

	case CALL_TYPE_NOT_A_CALL:
	default:
		return;
	}

	vcard_printf(vcards, "X-IRMC-CALL-DATETIME;%s:%s", type,
							contact->datetime);
}

static void vcard_printf_end(GString *vcards)
{
	vcard_printf(vcards, "END:VCARD");
}

void phonebook_add_contact(GString *vcards, struct phonebook_contact *contact,
					uint64_t filter, uint8_t format)
{
	if (format == FORMAT_VCARD30 && filter)
		filter |= (FILTER_VERSION | FILTER_FN | FILTER_N | FILTER_TEL);
	else if (format == FORMAT_VCARD21 && filter)
		filter |= (FILTER_VERSION | FILTER_N | FILTER_TEL);
	else
		filter = (FILTER_VERSION | FILTER_UID | FILTER_N | FILTER_FN |
				FILTER_TEL | FILTER_EMAIL | FILTER_ADR |
				FILTER_BDAY | FILTER_NICKNAME | FILTER_URL |
				FILTER_PHOTO | FILTER_ORG | FILTER_ROLE |
				FILTER_TITLE | FILTER_X_IRMC_CALL_DATETIME);

	vcard_printf_begin(vcards, format);

	if (filter & FILTER_UID && *contact->uid)
		vcard_printf_tag(vcards, format, "UID", NULL, contact->uid);

	if (filter & FILTER_N)
		vcard_printf_name(vcards, contact);

	if (filter & FILTER_FN && (*contact->fullname ||
					format == FORMAT_VCARD30))
		vcard_printf_fullname(vcards, contact->fullname);

	if (filter & FILTER_TEL) {
		GSList *l = contact->numbers;

		if (g_slist_length(l) == 0)
			vcard_printf_number(vcards, format, NULL, 1,
							TEL_TYPE_OTHER);

		for (; l; l = l->next) {
			struct phonebook_field *number = l->data;

			vcard_printf_number(vcards, format, number->text, 1,
								number->type);
		}
	}

	if (filter & FILTER_EMAIL) {
		GSList *l = contact->emails;

		for (; l; l = l->next) {
			struct phonebook_field *email = l->data;
			vcard_printf_email(vcards, format, email->text,
								email->type);
		}
	}

	if (filter & FILTER_ADR) {
		GSList *l = contact->addresses;

		for (; l; l = l->next) {
			struct phonebook_field *addr = l->data;
			vcard_printf_address(vcards, format, addr->text,
								addr->type);
		}
	}

	if (filter & FILTER_BDAY && *contact->birthday)
		vcard_printf_tag(vcards, format, "BDAY", NULL,
						contact->birthday);

	if (filter & FILTER_NICKNAME && *contact->nickname)
		vcard_printf_tag(vcards, format, "NICKNAME", NULL,
							contact->nickname);

	if (filter & FILTER_URL) {
		GSList *l = contact->urls;

		for (; l; l = l->next) {
			struct phonebook_field *url = l->data;
			vcard_printf_url(vcards, format, url->text, url->type);
		}
	}

	if (filter & FILTER_PHOTO && *contact->photo)
		vcard_printf_tag(vcards, format, "PHOTO", NULL,
							contact->photo);

	if (filter & FILTER_ORG)
		vcard_printf_org(vcards, contact);

	if (filter & FILTER_ROLE && *contact->role)
		vcard_printf_tag(vcards, format, "ROLE", NULL, contact->role);

	if (filter & FILTER_TITLE && *contact->title)
		vcard_printf_tag(vcards, format, "TITLE", NULL, contact->title);

	if (filter & FILTER_X_IRMC_CALL_DATETIME)
		vcard_printf_datetime(vcards, contact);

	vcard_printf_end(vcards);
}


static void field_free(gpointer data)
{
	struct phonebook_field *field = data;

	g_free(field->text);
	g_free(field);
}

void phonebook_contact_free(struct phonebook_contact *contact)
{
	if (contact == NULL)
		return;

	g_slist_free_full(contact->numbers, field_free);
	g_slist_free_full(contact->emails, field_free);
	g_slist_free_full(contact->addresses, field_free);
	g_slist_free_full(contact->urls, field_free);

	g_free(contact->uid);
	g_free(contact->fullname);
	g_free(contact->given);
	g_free(contact->family);
	g_free(contact->additional);
	g_free(contact->prefix);
	g_free(contact->suffix);
	g_free(contact->birthday);
	g_free(contact->nickname);
	g_free(contact->photo);
	g_free(contact->company);
	g_free(contact->department);
	g_free(contact->role);
	g_free(contact->title);
	g_free(contact->datetime);
	g_free(contact);
}
