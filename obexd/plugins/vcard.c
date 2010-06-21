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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "vcard.h"

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

	for (i = 0, j = 0; i < len && j < len_max; i++, j++) {
		switch (src[i]) {
		case '\n':
			dest[j++] = '\\';
			dest[j] = 'n';
			break;
		case '\r':
			dest[j++] = '\\';
			dest[j] = 'r';
			break;
		case '\\':
		case ';':
		case ',':
			dest[j++] = '\\';
		default:
			dest[j] = src[i];
			break;
		}
	}
	dest[j] = 0;
	return;
}

static void vcard_printf_begin(GString *vcards, uint8_t format)
{
	vcard_printf(vcards, "BEGIN:VCARD");

	if (format == FORMAT_VCARD30)
		vcard_printf(vcards, "VERSION:3.0");
	else if (format == FORMAT_VCARD21)
		vcard_printf(vcards, "VERSION:2.1");
}

static void vcard_printf_name(GString *vcards,
					struct phonebook_contact *contact)
{
	vcard_printf(vcards, "N:%s;%s;%s;%s;%s", contact->family,
				contact->given, contact->additional,
				contact->prefix, contact->suffix);
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
			category_string = "VOICE";
		else if (format == FORMAT_VCARD30)
			category_string = "TYPE=VOICE";
		break;
	}

	if ((type == TYPE_INTERNATIONAL) && (number[0] != '+'))
		intl = "+";

	snprintf(buf, sizeof(buf), "TEL;%s:%s\%s", category_string, intl, number);

	vcard_printf(vcards, buf, number);
}

static void vcard_printf_email(GString *vcards, const char *email)
{
	int len = 0;

	if (email)
		len = strlen(email);

	if (len) {
		char field[LEN_MAX];
		add_slash(field, email, LEN_MAX, len);
		vcard_printf(vcards,
				"EMAIL;TYPE=INTERNET:%s", field);
	}
}

static void vcard_printf_adr(GString *vcards, struct phonebook_contact *contact)
{
	vcard_printf(vcards, "ADR:%s;%s;%s;%s;%s;%s;%s", contact->pobox,
					contact->extended, contact->street,
					contact->locality, contact->region,
					contact->postal, contact->country);
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
	vcard_printf(vcards, "");
}

void phonebook_add_contact(GString *vcards, struct phonebook_contact *contact,
					uint64_t filter, uint8_t format)
{
	/* There's really nothing to do */
	if ((contact->numbers == NULL && (contact->fullname == NULL ||
						contact->fullname[0] == '\0')))
		return;

	if (format == FORMAT_VCARD30)
		filter |= (FILTER_VERSION | FILTER_FN | FILTER_N | FILTER_TEL);
	else if (format == FORMAT_VCARD21)
		filter |= (FILTER_VERSION | FILTER_N | FILTER_TEL);

	vcard_printf_begin(vcards, format);

	if (filter & FILTER_TEL) {
		GSList *l;

		for (l = contact->numbers; l; l = l->next) {
			struct phonebook_number *number = l->data;

			vcard_printf_number(vcards, format, number->tel, 1,
								number->type);
		}
	}

	if (filter & FILTER_N)
		vcard_printf_name(vcards, contact);

	if (filter & FILTER_FN)
		vcard_printf_fullname(vcards, contact->fullname);

	if (filter & FILTER_EMAIL)
		vcard_printf_email(vcards, contact->email);

	if (filter & FILTER_ADR)
		vcard_printf_adr(vcards, contact);

	if (filter & FILTER_X_IRMC_CALL_DATETIME)
		vcard_printf_datetime(vcards, contact);

	vcard_printf_end(vcards);
}

static void number_free(gpointer data, gpointer user_data)
{
	struct phonebook_number *number = data;

	g_free(number->tel);
	g_free(number);
}

void phonebook_contact_free(struct phonebook_contact *contact)
{
	if (contact == NULL)
		return;

	g_slist_foreach(contact->numbers, number_free, NULL);
	g_slist_free(contact->numbers);

	g_free(contact->fullname);
	g_free(contact->given);
	g_free(contact->family);
	g_free(contact->additional);
	g_free(contact->email);
	g_free(contact->prefix);
	g_free(contact->suffix);
	g_free(contact->pobox);
	g_free(contact->extended);
	g_free(contact->street);
	g_free(contact->locality);
	g_free(contact->region);
	g_free(contact->postal);
	g_free(contact->country);
	g_free(contact->datetime);
	g_free(contact);
}
