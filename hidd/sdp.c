/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hidp.h>

#include "textfile.h"
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

static int store_device_info(const bdaddr_t *src, const bdaddr_t *dst, struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], addr[18], *str, *desc;
	int i, size;

	ba2str(src, addr);
	snprintf(filename, PATH_MAX, "%s/%s/hidd", STORAGEDIR, addr);

	size = 15 + 3 + 3 + 5 + (req->rd_size * 2) + 1 + 9 + strlen(req->name) + 2;
	str = malloc(size);
	if (!str)
		return -ENOMEM;

	desc = malloc((req->rd_size * 2) + 1);
	if (!desc) {
		free(str);
		return -ENOMEM;
	}

	memset(desc, 0, (req->rd_size * 2) + 1);
	for (i = 0; i < req->rd_size; i++)
		sprintf(desc + (i * 2), "%2.2X", req->rd_data[i]);

	snprintf(str, size - 1, "%04X:%04X:%04X %02X %02X %04X %s %08X %s",
			req->vendor, req->product, req->version,
			req->subclass, req->country, req->parser, desc,
			req->flags, req->name);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dst, addr);
	return textfile_put(filename, addr, str);
}

int get_stored_device_info(const bdaddr_t *src, const bdaddr_t *dst, struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], addr[18], tmp[3], *str, *desc;
	unsigned int vendor, product, version, subclass, country, parser, pos;
	int i;

	desc = malloc(4096);
	if (!desc)
		return -ENOMEM;

	memset(desc, 0, 4096);

	ba2str(src, addr);
	snprintf(filename, PATH_MAX, "%s/%s/hidd", STORAGEDIR, addr);

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str) {
		free(desc);
		return -EIO;
	}

	sscanf(str, "%04X:%04X:%04X %02X %02X %04X %4095s %08X %n",
			&vendor, &product, &version, &subclass, &country,
			&parser, desc, &req->flags, &pos);

	free(str);

	req->vendor   = vendor;
	req->product  = product;
	req->version  = version;
	req->subclass = subclass;
	req->country  = country;
	req->parser   = parser;

	snprintf(req->name, 128, str + pos);

	req->rd_size = strlen(desc) / 2;
	req->rd_data = malloc(req->rd_size);
	if (!req->rd_data)
		return -ENOMEM;

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < req->rd_size; i++) {
		memcpy(tmp, desc + (i * 2), 2);
		req->rd_data[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	return 0;
}

int get_sdp_device_info(const bdaddr_t *src, const bdaddr_t *dst, struct hidp_connadd_req *req)
{
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	bdaddr_t bdaddr;
	uint32_t range = 0x0000ffff;
	sdp_session_t *s;
	sdp_list_t *search, *attrid, *pnp_rsp, *hid_rsp;
	sdp_record_t *rec;
	sdp_data_t *pdlist, *pdlist2;
	uuid_t svclass;
	int err;

	s = sdp_connect(src, dst, SDP_RETRY_IF_BUSY | SDP_WAIT_ON_CLOSE);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, PNP_INFO_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &range);

	err = sdp_service_search_attr_req(s, search,
					SDP_ATTR_REQ_RANGE, attrid, &pnp_rsp);

	sdp_list_free(search, NULL);
	sdp_list_free(attrid, NULL);

	sdp_uuid16_create(&svclass, HID_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &range);

	err = sdp_service_search_attr_req(s, search,
					SDP_ATTR_REQ_RANGE, attrid, &hid_rsp);

	sdp_list_free(search, NULL);
	sdp_list_free(attrid, NULL);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getsockname(s->sock, (struct sockaddr *) &addr, &addrlen) < 0)
		bacpy(&bdaddr, src);
	else
		bacpy(&bdaddr, &addr.l2_bdaddr);

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

	if (bacmp(&bdaddr, BDADDR_ANY))
		store_device_info(&bdaddr, dst, req);

	return 0;
}

int get_alternate_device_info(const bdaddr_t *src, const bdaddr_t *dst, uint16_t *uuid, uint8_t *channel)
{
	uint16_t attr = SDP_ATTR_PROTO_DESC_LIST;
	sdp_session_t *s;
	sdp_list_t *search, *attrid, *rsp;
	uuid_t svclass;
	int err;

	s = sdp_connect(src, dst, SDP_RETRY_IF_BUSY | SDP_WAIT_ON_CLOSE);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, HEADSET_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &attr);

	err = sdp_service_search_attr_req(s, search,
					SDP_ATTR_REQ_INDIVIDUAL, attrid, &rsp);

	sdp_list_free(search, NULL);
	sdp_list_free(attrid, NULL);

	if (err <= 0) {
		sdp_uuid16_create(&svclass, SERIAL_PORT_SVCLASS_ID);
		search = sdp_list_append(NULL, &svclass);
		attrid = sdp_list_append(NULL, &attr);

		err = sdp_service_search_attr_req(s, search,
					SDP_ATTR_REQ_INDIVIDUAL, attrid, &rsp);

		sdp_list_free(search, NULL);
		sdp_list_free(attrid, NULL);

		if (err < 0) {
			sdp_close(s);
			return err;
		}

		if (uuid)
			*uuid = SERIAL_PORT_SVCLASS_ID;
	} else {
		if (uuid)
			*uuid = HEADSET_SVCLASS_ID;
	}

	sdp_close(s);

	for (; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			uint8_t ch = sdp_get_proto_port(protos, RFCOMM_UUID);
			if (ch > 0) {
				if (channel)
					*channel = ch;
				return 0;
			}
		}

		sdp_record_free(rec);
	}

	return -EIO;
}
