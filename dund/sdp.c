/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "dund.h"

static sdp_record_t  *record;
static sdp_session_t *session;

void dun_sdp_unregister(void) 
{
	if (record && sdp_record_unregister(session, record))
		syslog(LOG_ERR, "Service record unregistration failed.");
	sdp_close(session);
}

int dun_sdp_register(uint8_t channel, int mrouter)
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

	sdp_uuid16_create(&dun, mrouter ? SERIAL_PORT_SVCLASS_ID : LAN_ACCESS_SVCLASS_ID);
	svclass = sdp_list_append(NULL, &dun);
	sdp_set_service_classes(record, svclass);

	sdp_uuid16_create(&profile[0].uuid, mrouter ? SERIAL_PORT_PROFILE_ID : LAN_ACCESS_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(record, pfseq);
		
	sdp_set_info_attr(record, mrouter ? "mRouter" : "LAN Access Point", NULL, NULL);

	status = sdp_record_register(session, record, 0);
	if (status) {
		syslog(LOG_ERR, "SDP registration failed.");
		sdp_record_free(record); record = NULL;
		return -1;
	}
	return 0;
}

int dun_sdp_search(bdaddr_t *src, bdaddr_t *dst, int *channel, int mrouter)
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

	sdp_uuid16_create(&svclass, mrouter ? SERIAL_PORT_SVCLASS_ID : LAN_ACCESS_SVCLASS_ID);
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
