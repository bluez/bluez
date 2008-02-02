/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <limits.h>

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "logging.h"
#include "sdp-xml.h"

static int compute_seq_size(sdp_data_t *data)
{
	int unit_size = data->unitSize;
	sdp_data_t *seq = data->val.dataseq;

	for (; seq; seq = seq->next)
		unit_size += seq->unitSize;

	return unit_size;
}

struct context_data {
	sdp_record_t *record;
	sdp_data_t attr_data;
	struct sdp_xml_data *stack_head;
	uint16_t attr_id;
};

static void element_start(GMarkupParseContext *context,
		const gchar *element_name, const gchar **attribute_names,
		const gchar **attribute_values, gpointer user_data, GError **err)
{
	struct context_data *ctx_data = user_data;

	if (!strcmp(element_name, "record"))
		return;

	if (!strcmp(element_name, "attribute")) {
		int i;
		for (i = 0; attribute_names[i]; i++) {
			if (!strcmp(attribute_names[i], "id")) {
				ctx_data->attr_id = strtol(attribute_values[i], 0, 0);
				break;
			}
		}
		debug("New attribute 0x%04x", ctx_data->attr_id);
		return;
	}

	if (ctx_data->stack_head) {
		struct sdp_xml_data *newelem = sdp_xml_data_alloc();
		newelem->next = ctx_data->stack_head;
		ctx_data->stack_head = newelem;
	} else {
		ctx_data->stack_head = sdp_xml_data_alloc();
		ctx_data->stack_head->next = NULL;
	}

	if (!strcmp(element_name, "sequence"))
		ctx_data->stack_head->data = sdp_data_alloc(SDP_SEQ8, NULL);
	else if (!strcmp(element_name, "alternate"))
		ctx_data->stack_head->data = sdp_data_alloc(SDP_ALT8, NULL);
	else {
		int i;
		/* Parse value, name, encoding */
		for (i = 0; attribute_names[i]; i++) {
			if (!strcmp(attribute_names[i], "value")) {
				int curlen = strlen(ctx_data->stack_head->text);
				int attrlen = strlen(attribute_values[i]);

				/* Ensure we're big enough */
				while ((curlen + 1 + attrlen) > ctx_data->stack_head->size) {
					sdp_xml_data_expand(ctx_data->stack_head);
				}

				memcpy(ctx_data->stack_head->text + curlen,
						attribute_values[i], attrlen);
				ctx_data->stack_head->text[curlen + attrlen] = '\0';
			}

			if (!strcmp(attribute_names[i], "encoding")) {
				if (!strcmp(attribute_values[i], "hex"))
					ctx_data->stack_head->type = 1;
			}

			if (!strcmp(attribute_names[i], "name")) {
				ctx_data->stack_head->name = strdup(attribute_values[i]);
			}
		}

		ctx_data->stack_head->data = sdp_xml_parse_datatype(element_name,
				ctx_data->stack_head, ctx_data->record);

		if (ctx_data->stack_head->data == NULL)
			error("Can't parse element %s", element_name);
	}
}

static void element_end(GMarkupParseContext *context,
		const gchar *element_name, gpointer user_data, GError **err)
{
	struct context_data *ctx_data = user_data;
	struct sdp_xml_data *elem;

	if (!strcmp(element_name, "record"))
		return;

	if (!strcmp(element_name, "attribute")) {
		if (ctx_data->stack_head && ctx_data->stack_head->data) {
			int ret = sdp_attr_add(ctx_data->record, ctx_data->attr_id,
							ctx_data->stack_head->data);
			if (ret == -1)
				debug("Trouble adding attribute\n");

			ctx_data->stack_head->data = NULL;
			sdp_xml_data_free(ctx_data->stack_head);
			ctx_data->stack_head = NULL;
		} else {
			debug("No data for attribute 0x%04x\n", ctx_data->attr_id);
		}
		return;
	}

	if (!strcmp(element_name, "sequence")) {
		ctx_data->stack_head->data->unitSize = compute_seq_size(ctx_data->stack_head->data);

		if (ctx_data->stack_head->data->unitSize > USHRT_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint32_t);
			ctx_data->stack_head->data->dtd = SDP_SEQ32;
		} else if (ctx_data->stack_head->data->unitSize > UCHAR_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint16_t);
			ctx_data->stack_head->data->dtd = SDP_SEQ16;
		} else {
			ctx_data->stack_head->data->unitSize += sizeof(uint8_t);
		}
	} else if (!strcmp(element_name, "alternate")) {
		ctx_data->stack_head->data->unitSize = compute_seq_size(ctx_data->stack_head->data);

		if (ctx_data->stack_head->data->unitSize > USHRT_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint32_t);
			ctx_data->stack_head->data->dtd = SDP_ALT32;
		} else if (ctx_data->stack_head->data->unitSize > UCHAR_MAX) {
			ctx_data->stack_head->data->unitSize += sizeof(uint16_t);
			ctx_data->stack_head->data->dtd = SDP_ALT16;
		} else {
			ctx_data->stack_head->data->unitSize += sizeof(uint8_t);
		}
	}

	if (ctx_data->stack_head->next && ctx_data->stack_head->data &&
					ctx_data->stack_head->next->data) {
		switch (ctx_data->stack_head->next->data->dtd) {
		case SDP_SEQ8:
		case SDP_SEQ16:
		case SDP_SEQ32:
		case SDP_ALT8:
		case SDP_ALT16:
		case SDP_ALT32:
			ctx_data->stack_head->next->data->val.dataseq =
				sdp_seq_append(ctx_data->stack_head->next->data->val.dataseq,
								ctx_data->stack_head->data);
			ctx_data->stack_head->data = NULL;
			break;
		}

		elem = ctx_data->stack_head;
		ctx_data->stack_head = ctx_data->stack_head->next;

		sdp_xml_data_free(elem);
	}
}

static GMarkupParser parser = {
	element_start, element_end, NULL, NULL, NULL
};

sdp_record_t *sdp_xml_parse_record(const char *data, int size)
{
	GMarkupParseContext *ctx;
	struct context_data *ctx_data;
	sdp_record_t *record;

	ctx_data = malloc(sizeof(*ctx_data));
	if (!ctx_data)
		return NULL;

	record = sdp_record_alloc();
	if (!record) {
		free(ctx_data);
		return NULL;
	}

	memset(ctx_data, 0, sizeof(*ctx_data));
	ctx_data->record = record;

	ctx = g_markup_parse_context_new(&parser, 0, ctx_data, NULL);

	if (g_markup_parse_context_parse(ctx, data, size, NULL) == FALSE) {
		error("XML parsing error");
		g_markup_parse_context_free(ctx);
		sdp_record_free(record);
		free(ctx_data);
		return NULL;
	}

	g_markup_parse_context_free(ctx);

	free(ctx_data);

	return record;
}
