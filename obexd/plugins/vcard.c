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
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "vcard.h"

#define LEN_MAX 128
#define TYPE_INTERNATIONAL 145

#define PHONEBOOK_FLAG_CACHED 0x1

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

static void vcard_printf_begin(GString *vcards)
{
	vcard_printf(vcards, "BEGIN:VCARD");
	vcard_printf(vcards, "VERSION:3.0");
}

static void vcard_printf_text(GString *vcards, const char *text)
{
	char field[LEN_MAX];
	add_slash(field, text, LEN_MAX, strlen(text));
	vcard_printf(vcards, "FN:%s", field);
}

static void vcard_printf_number(GString *vcards, const char *number, int type,
					enum phonebook_number_type category)
{
	char *pref = "", *intl = "", *category_string = "";
	char buf[128];

	if (!number || !strlen(number) || !type)
		return;

	switch (category) {
	case TEL_TYPE_HOME:
		category_string = "HOME,VOICE";
		break;
	case TEL_TYPE_MOBILE:
		category_string = "CELL,VOICE";
		break;
	case TEL_TYPE_FAX:
		category_string = "FAX";
		break;
	case TEL_TYPE_WORK:
		category_string = "WORK,VOICE";
		break;
	case TEL_TYPE_OTHER:
		category_string = "VOICE";
		break;
	}

	if ((type == TYPE_INTERNATIONAL) && (number[0] != '+'))
		intl = "+";

	snprintf(buf, sizeof(buf), "TEL;TYPE=\%s%s:\%s\%s", pref,
			category_string, intl, number);
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

static void vcard_printf_end(GString *vcards)
{
	vcard_printf(vcards, "END:VCARD");
	vcard_printf(vcards, "");
}

void phonebook_add_entry(GString *vcards, const char *number, int type,
					const char *text, const char *email)
{
	/* There's really nothing to do */
	if ((number == NULL || number[0] == '\0') &&
			(text == NULL || text[0] == '\0'))
		return;

	vcard_printf_begin(vcards);

	if (text == NULL || text[0] == '\0')
		vcard_printf_text(vcards, number);
	else
		vcard_printf_text(vcards, text);

	vcard_printf_email(vcards, email);
	vcard_printf_number(vcards, number, type, TEL_TYPE_OTHER);
	vcard_printf_end(vcards);
}
