/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "dund.h"

static unsigned char async_uuid[] = {	0x03, 0x50, 0x27, 0x8F, 0x3D, 0xCA, 0x4E, 0x62,
					0x83, 0x1D, 0xA4, 0x11, 0x65, 0xFF, 0x90, 0x6C };

static sdp_record_t  *record;
static sdp_session_t *session;

void dun_sdp_unregister(void) 
{
	if (record && sdp_record_unregister(session, record))
		syslog(LOG_ERR, "Service record unregistration failed.");
	sdp_close(session);
}

int dun_sdp_register(bdaddr_t *device, uint8_t channel, int type)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, l2cap, rfcomm, dun;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];
	int status;

	session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!session) {
		syslog(LOG_ERR, "Failed to connect to the local SDP server. %s(%d)", 
				strerror(errno), errno);
		return -1;
	}

	record = sdp_record_alloc();
	if (!record) {
		syslog(LOG_ERR, "Failed to alloc service record");
		return -1;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq    = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	proto[1] = sdp_list_append(proto[1], sdp_data_alloc(SDP_UINT8, &channel));
	apseq    = sdp_list_append(apseq, proto[1]);

	aproto   = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	switch (type) {
	case MROUTER:
		sdp_uuid16_create(&dun, SERIAL_PORT_SVCLASS_ID);
		break;
	case ACTIVESYNC:
		sdp_uuid128_create(&dun, (void *) async_uuid);
		break;
	case DIALUP:
		sdp_uuid16_create(&dun, DIALUP_NET_SVCLASS_ID);
		break;
	default:
		sdp_uuid16_create(&dun, LAN_ACCESS_SVCLASS_ID);
		break;
	}

	svclass = sdp_list_append(NULL, &dun);
	sdp_set_service_classes(record, svclass);

	if (type == LANACCESS || type == DIALUP) {
		sdp_uuid16_create(&profile[0].uuid, LAN_ACCESS_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);
	}

	switch (type) {
	case MROUTER:
		sdp_set_info_attr(record, "mRouter", NULL, NULL);
		break;
	case ACTIVESYNC:
		sdp_set_info_attr(record, "ActiveSync", NULL, NULL);
		break;
	case DIALUP:
		sdp_set_info_attr(record, "Dialup Networking", NULL, NULL);
		break;
	default:
		sdp_set_info_attr(record, "LAN Access Point", NULL, NULL);
		break;
	}

	status = sdp_device_record_register(session, device, record, 0);
	if (status) {
		syslog(LOG_ERR, "SDP registration failed.");
		sdp_record_free(record);
		record = NULL;
		return -1;
	}
	return 0;
}

int dun_sdp_search(bdaddr_t *src, bdaddr_t *dst, int *channel, int type)
{
	sdp_session_t *s;
	sdp_list_t *srch, *attrs, *rsp;
	uuid_t svclass;
	uint16_t attr;
	int err;

	s = sdp_connect(src, dst, 0);
	if (!s) {
		syslog(LOG_ERR, "Failed to connect to the SDP server. %s(%d)", 
				strerror(errno), errno);
		return -1;
	}

	switch (type) {
	case MROUTER:
		sdp_uuid16_create(&svclass, SERIAL_PORT_SVCLASS_ID);
		break;
	case ACTIVESYNC:
		sdp_uuid128_create(&svclass, (void *) async_uuid);
		break;
	default:
		sdp_uuid16_create(&svclass, LAN_ACCESS_SVCLASS_ID);
		break;
	}

	srch  = sdp_list_append(NULL, &svclass);

	attr  = SDP_ATTR_PROTO_DESC_LIST;
	attrs = sdp_list_append(NULL, &attr);

	err = sdp_service_search_attr_req(s, srch, SDP_ATTR_REQ_INDIVIDUAL, attrs, &rsp);

	sdp_close(s);

	if (err)
		return 0;

	for(; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			int ch = sdp_get_proto_port(protos, RFCOMM_UUID);
			if (ch > 0) {
				*channel = ch;
				return 1;
			}
		}
	}

	return 0;
}
