/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hidp.h>

#include "hidd.h"

static void epox_endian_quirk(unsigned char *data, int size)
{
	/* USAGE_PAGE (Keyboard)	05 07
	 * USAGE_MINIMUM (0)		19 00
	 * USAGE_MAXIMUM (65280)	2A 00 FF   <= must be FF 00
	 * LOGICAL_MINIMUM (0)		15 00
	 * LOGICAL_MAXIMUM (65280)	26 00 FF   <= must be FF 00
	 */
	unsigned char pattern[] = { 0x05, 0x07, 0x19, 0x00, 0x2a, 0x00, 0xff,
						0x15, 0x00, 0x26, 0x00, 0xff };
	int i;

	if (!data)
		return;

	for (i = 0; i < size - sizeof(pattern); i++) {
		if (!memcmp(data + i, pattern, sizeof(pattern))) {
			data[i + 5] = 0xff;
			data[i + 6] = 0x00;
			data[i + 10] = 0xff;
			data[i + 11] = 0x00;
		}
	}
}

int get_hid_device_info(bdaddr_t *src, bdaddr_t *dst, struct hidp_connadd_req *req)
{
	uint32_t range = 0x0000ffff;
	sdp_session_t *s;
	sdp_list_t *search, *attrid, *pnp_rsp, *hid_rsp;
	sdp_record_t *rec;
	sdp_data_t *pdlist, *pdlist2;
	uuid_t svclass;
	int err;

	s = sdp_connect(src, dst, 0);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, PNP_INFO_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &range);

	err = sdp_service_search_attr_req(s, search, SDP_ATTR_REQ_RANGE, attrid, &pnp_rsp);

	sdp_list_free(search, 0);
	sdp_list_free(attrid, 0);

	sdp_uuid16_create(&svclass, HID_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &range);

	err = sdp_service_search_attr_req(s, search, SDP_ATTR_REQ_RANGE, attrid, &hid_rsp);

	sdp_list_free(search, 0);
	sdp_list_free(attrid, 0);

	sdp_close(s);

	if (err || !hid_rsp)
		return -1;

	if (pnp_rsp) {
		rec = (sdp_record_t *) pnp_rsp->data;

		pdlist = sdp_data_get(rec, 0x0201);
		req->vendor = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0202);
		req->product = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, 0x0203);
		req->version = pdlist ? pdlist->val.uint16 : 0x0000;

		sdp_record_free(rec);
	}

	rec = (sdp_record_t *) hid_rsp->data;

	pdlist = sdp_data_get(rec, 0x0101);
	pdlist2 = sdp_data_get(rec, 0x0102);
	if (pdlist) {
		if (pdlist2) {
			if (strncmp(pdlist->val.str, pdlist2->val.str, 5)) {
				strncpy(req->name, pdlist2->val.str, sizeof(req->name) - 1);
				strcat(req->name, " ");
			}
			strncat(req->name, pdlist->val.str,
					sizeof(req->name) - strlen(req->name));
		} else
			strncpy(req->name, pdlist->val.str, sizeof(req->name));
	} else {
		pdlist2 = sdp_data_get(rec, 0x0100);
		if (pdlist2)
			strncpy(req->name, pdlist2->val.str, sizeof(req->name));
	}

	pdlist = sdp_data_get(rec, 0x0201);
	req->parser = pdlist ? pdlist->val.uint16 : 0x0100;

	pdlist = sdp_data_get(rec, 0x0202);
	req->subclass = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, 0x0203);
	req->country = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, 0x0206);
	if (pdlist) {
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->next;

		req->rd_data = malloc(pdlist->unitSize);
		if (req->rd_data) {
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str, pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
			epox_endian_quirk(req->rd_data, req->rd_size);
		}
	}

	sdp_record_free(rec);

	return 0;
}
