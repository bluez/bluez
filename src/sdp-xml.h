/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2010  Marcel Holtmann <marcel@holtmann.org>
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


#ifndef __SDP_XML_H
#define __SDP_XML_H

#include <bluetooth/sdp.h>

#define SDP_XML_ENCODING_NORMAL	0
#define SDP_XML_ENCODING_HEX	1

void convert_sdp_record_to_xml(sdp_record_t *rec,
		void *user_data, void (*append_func) (void *, const char *));

sdp_data_t *sdp_xml_parse_nil(const char *data);
sdp_data_t *sdp_xml_parse_text(const char *data, char encoding);
sdp_data_t *sdp_xml_parse_url(const char *data);
sdp_data_t *sdp_xml_parse_int(const char *data, uint8_t dtd);
sdp_data_t *sdp_xml_parse_uuid(const char *data, sdp_record_t *record);

struct sdp_xml_data {
	char *text;			/* Pointer to the current buffer */
	int size;			/* Size of the current buffer */
	sdp_data_t *data;		/* The current item being built */
	struct sdp_xml_data *next;	/* Next item on the stack */
	char type;			/* 0 = Text or Hexadecimal */
	char *name;			/* Name, optional in the dtd */
	/* TODO: What is it used for? */
};

struct sdp_xml_data *sdp_xml_data_alloc(void);
void sdp_xml_data_free(struct sdp_xml_data *elem);
struct sdp_xml_data *sdp_xml_data_expand(struct sdp_xml_data *elem);

sdp_data_t *sdp_xml_parse_datatype(const char *el, struct sdp_xml_data *elem,
							sdp_record_t *record);

#endif /* __SDP_XML_H */
