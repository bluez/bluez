/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <expat.h>

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

/* Expat specific implementation of the context struct */

struct sdp_xml_context {
	XML_Parser parser;			/* Parser object being used */
	sdp_record_t *sdprec;			/* SDP Record being built */
	struct sdp_xml_data *stack_head;	/* Top of the stack of attributes */
	int attrId;				/* Id of the most recently processed attribute */
};

static void convert_xml_to_sdp_start(void *data, const char *el, const char **attr)
{
	struct sdp_xml_context *context = data;
	int i;

	if (!strcmp(el, "record"))
		return;

	if (!strcmp(el, "attribute")) {
		/* Get the ID */
		for (i = 0; attr[i]; i += 1) {
			if (!strcmp(attr[i], "id")) {
				context->attrId = strtol(attr[i + 1], 0, 0);
				break;
			}
		}

		return;
	}

	/* Assume every other tag is an element of some sort */
	if (context->stack_head) {
		struct sdp_xml_data *newelem = sdp_xml_data_alloc();
		newelem->next = context->stack_head;
		context->stack_head = newelem;
	} else {
		context->stack_head = sdp_xml_data_alloc();
		context->stack_head->next = NULL;
	}

	if (!strcmp(el, "sequence"))
		context->stack_head->data = sdp_data_alloc(SDP_SEQ8, NULL);
	else if (!strcmp(el, "alternate"))
		context->stack_head->data = sdp_data_alloc(SDP_ALT8, NULL);
	else {
		/* Parse value, name, encoding */
		for (i = 0; attr[i]; i += 2) {
			if (!strcmp(attr[i], "value")) {
				int curlen = strlen(context->stack_head->text);
				int attrlen = strlen(attr[i + 1]);

				/* Ensure we're big enough */
				while ((curlen + 1 + attrlen) > context->stack_head->size) {
					sdp_xml_data_expand(context->stack_head);
				}

				memcpy(&context->stack_head->text[curlen],
							attr[i + 1], attrlen);
				context->stack_head->text[curlen + attrlen] = '\0';
			}

			if (!strcmp(attr[i], "encoding")) {
				if (!strcmp(attr[i + 1], "hex"))
					context->stack_head->type = 1;
			}

			if (!strcmp(attr[i], "name")) {
				context->stack_head->name = strdup(attr[i + 1]);
			}
		}

		context->stack_head->data = sdp_xml_parse_datatype(el,
					context->stack_head, context->sdprec);

		/* Could not parse an entry */
		if (context->stack_head->data == NULL)
			XML_StopParser(context->parser, 0);
	}
}

static void convert_xml_to_sdp_end(void *data, const char *el)
{
	struct sdp_xml_context *context = data;
	struct sdp_xml_data *elem;

	if (!strcmp(el, "record"))
		return;

	if (!strcmp(el, "attribute")) {
		if (context->stack_head && context->stack_head->data) {
			int ret = sdp_attr_add(context->sdprec, context->attrId,
							context->stack_head->data);
			if (ret == -1)
				debug("Trouble adding attribute\n");

			context->stack_head->data = NULL;
			sdp_xml_data_free(context->stack_head);
			context->stack_head = NULL;
		} else {
			debug("No Data for attribute: %d\n", context->attrId);
		}

		return;
	} else if (!strcmp(el, "sequence")) {
		context->stack_head->data->unitSize = compute_seq_size(context->stack_head->data);

		if (context->stack_head->data->unitSize > USHRT_MAX) {
			context->stack_head->data->unitSize += sizeof(uint32_t);
			context->stack_head->data->dtd = SDP_SEQ32;
		} else if (context->stack_head->data->unitSize > UCHAR_MAX) {
			context->stack_head->data->unitSize += sizeof(uint16_t);
			context->stack_head->data->dtd = SDP_SEQ16;
		} else {
			context->stack_head->data->unitSize += sizeof(uint8_t);
		}
	} else if (!strcmp(el, "alternate")) {
		context->stack_head->data->unitSize = compute_seq_size(context->stack_head->data);

		if (context->stack_head->data->unitSize > USHRT_MAX) {
			context->stack_head->data->unitSize += sizeof(uint32_t);
			context->stack_head->data->dtd = SDP_ALT32;
		} else if (context->stack_head->data->unitSize > UCHAR_MAX) {
			context->stack_head->data->unitSize += sizeof(uint16_t);
			context->stack_head->data->dtd = SDP_ALT16;
		} else {
			context->stack_head->data->unitSize += sizeof(uint8_t);
		}
	}

	/* If we're not inside a seq or alt, then we're inside an attribute
	   which will be taken care of later
	 */
	if (context->stack_head->next && context->stack_head->data &&
					context->stack_head->next->data) {
		switch (context->stack_head->next->data->dtd) {
		case SDP_SEQ8:
		case SDP_SEQ16:
		case SDP_SEQ32:
		case SDP_ALT8:
		case SDP_ALT16:
		case SDP_ALT32:
			context->stack_head->next->data->val.dataseq =
				sdp_seq_append(context->stack_head->next->data->val.dataseq,
								context->stack_head->data);
			context->stack_head->data = NULL;
			break;
		}

		elem = context->stack_head;
		context->stack_head = context->stack_head->next;

		sdp_xml_data_free(elem);
	}
}

static struct sdp_xml_context *sdp_xml_init_context()
{
	struct sdp_xml_context *context;

	context = malloc(sizeof(struct sdp_xml_context));

	if (!context)
		return NULL;

	context->parser = 0;
	context->sdprec = 0;
	context->stack_head = 0;

	context->parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(context->parser, convert_xml_to_sdp_start,
						convert_xml_to_sdp_end);
	XML_SetUserData(context->parser, context);

	if (!context->parser)
		goto fail;

	context->sdprec = sdp_record_alloc();

	if (!context->sdprec)
		goto fail;

	return context;

fail:
	if (context->parser)
		free(context->parser);

	if (context->sdprec)
		sdp_record_free(context->sdprec);

	if (context)
		free(context);

	return NULL;
}

static void sdp_xml_free_context(struct sdp_xml_context *context)
{
	struct sdp_xml_data *elem;

	/* Free the stack */
	while (context->stack_head) {
		elem = context->stack_head;
		context->stack_head = elem->next;
		sdp_xml_data_free(elem);
	}

	XML_ParserFree(context->parser);

	free(context);
}

static int sdp_xml_parse_chunk(struct sdp_xml_context *context,
					const char *data, int size, int final)
{
	if (!XML_Parse(context->parser, data, size, final)) {
		error("Parse error at line %d: %s\n",
			XML_GetCurrentLineNumber(context->parser),
			XML_ErrorString(XML_GetErrorCode(context->parser)));
		return -1;
	}

	return 0;
}

sdp_record_t *sdp_xml_parse_record(const char *data, int size)
{
	struct sdp_xml_context *context;
	sdp_record_t *record;

	context = sdp_xml_init_context();

	if (sdp_xml_parse_chunk(context, data, size, 1) < 0) {
		sdp_record_free(context->sdprec);
		sdp_xml_free_context(context);
		return NULL;
	}

	record = context->sdprec;

	sdp_xml_free_context(context);

	return record;
}
