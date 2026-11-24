// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"

#include "cups.h"

#define ATTRID_1284ID 0x0300

int sdp_search_hcrp(sdp_session_t *sdp, unsigned short *ctrl_psm, unsigned short *data_psm)
{
	sdp_list_t *srch, *attrs, *rsp;
	uuid_t svclass;
	uint16_t attr1, attr2;
	int err;

	if (!sdp)
		return -1;

	sdp_uuid16_create(&svclass, HCR_PRINT_SVCLASS_ID);
	srch = sdp_list_append(NULL, &svclass);

	attr1 = SDP_ATTR_PROTO_DESC_LIST;
	attrs = sdp_list_append(NULL, &attr1);
	attr2 = SDP_ATTR_ADD_PROTO_DESC_LIST;
	attrs = sdp_list_append(attrs, &attr2);

	err = sdp_service_search_attr_req(sdp, srch, SDP_ATTR_REQ_INDIVIDUAL, attrs, &rsp);
	if (err)
		return -1;

	for (; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			unsigned short psm = sdp_get_proto_port(protos, L2CAP_UUID);
			if (psm > 0) {
				*ctrl_psm = psm;
			}
		}

		if (!sdp_get_add_access_protos(rec, &protos)) {
			unsigned short psm = sdp_get_proto_port(protos, L2CAP_UUID);
			if (psm > 0 && *ctrl_psm > 0) {
				*data_psm = psm;
				return 0;
			}
		}
	}

	return -1;
}

int sdp_search_spp(sdp_session_t *sdp, uint8_t *channel)
{
	sdp_list_t *srch, *attrs, *rsp;
	uuid_t svclass;
	uint16_t attr;
	int err;

	if (!sdp)
		return -1;

	sdp_uuid16_create(&svclass, SERIAL_PORT_SVCLASS_ID);
	srch = sdp_list_append(NULL, &svclass);

	attr = SDP_ATTR_PROTO_DESC_LIST;
	attrs = sdp_list_append(NULL, &attr);

	err = sdp_service_search_attr_req(sdp, srch, SDP_ATTR_REQ_INDIVIDUAL, attrs, &rsp);
	if (err)
		return -1;

	for (; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			uint8_t ch = sdp_get_proto_port(protos, RFCOMM_UUID);
			if (ch > 0) {
				*channel = ch;
				return 0;
			}
		}
	}

	return -1;
}

static char *record_get_ieee1284_id(sdp_record_t *rec)
{
	sdp_data_t *data = sdp_data_get(rec, ATTRID_1284ID);
	int len;

	if (!data || !SDP_IS_TEXT_STR(data->dtd))
		return NULL;

	/* The device ID is preceded by its two length bytes */
	len = data->unitSize - sizeof(uint8_t);
	if (len <= 2)
		return NULL;

	return strndup(data->val.str + 2, len - 2);
}

static int search_ieee1284_id(sdp_session_t *sdp, sdp_list_t **rsp)
{
	sdp_list_t *srch, *attrs;
	uuid_t svclass;
	uint16_t attr;
	int err;

	if (!sdp)
		return -1;

	sdp_uuid16_create(&svclass, HCR_PRINT_SVCLASS_ID);
	srch = sdp_list_append(NULL, &svclass);

	attr = ATTRID_1284ID;
	attrs = sdp_list_append(NULL, &attr);

	if (rsp)
		err = sdp_service_search_attr_req(sdp, srch,
					SDP_ATTR_REQ_INDIVIDUAL, attrs, rsp);
	else
		err = sdp_service_search_attr_async(sdp, srch,
					SDP_ATTR_REQ_INDIVIDUAL, attrs);

	sdp_list_free(srch, NULL);
	sdp_list_free(attrs, NULL);

	return err;
}

char *sdp_search_ieee1284_id(sdp_session_t *sdp)
{
	sdp_list_t *rsp, *l;
	char *id = NULL;

	if (search_ieee1284_id(sdp, &rsp))
		return NULL;

	for (l = rsp; l; l = l->next) {
		if (!id)
			id = record_get_ieee1284_id(l->data);

		sdp_record_free(l->data);
	}

	sdp_list_free(rsp, NULL);

	return id;
}

int sdp_search_ieee1284_id_async(sdp_session_t *sdp)
{
	return search_ieee1284_id(sdp, NULL);
}

char *sdp_parse_ieee1284_id(uint8_t *rsp, size_t size)
{
	int scanned, seqlen = 0, bytesleft = size;
	uint8_t dtd;
	char *id = NULL;

	scanned = sdp_extract_seqtype(rsp, bytesleft, &dtd, &seqlen);
	if (!scanned || !seqlen)
		return NULL;

	rsp += scanned;
	bytesleft -= scanned;

	while (!id && bytesleft > 0) {
		sdp_record_t *rec;
		int recsize = 0;

		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (recsize)
			id = record_get_ieee1284_id(rec);

		sdp_record_free(rec);

		if (!recsize)
			break;

		rsp += recsize;
		bytesleft -= recsize;
	}

	return id;
}
