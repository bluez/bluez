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
#include <bluetooth/bnep.h>

#include "pand.h"

static sdp_record_t  *record;
static sdp_session_t *session;

void bnep_sdp_unregister(void) 
{
	if (record && sdp_record_unregister(session, record))
		syslog(LOG_ERR, "Service record unregistration failed.");

	sdp_close(session);
}

int bnep_sdp_register(bdaddr_t *device, uint16_t role)
{
	sdp_list_t *svclass, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, pan, l2cap, bnep;
	sdp_profile_desc_t profile[1];
	sdp_list_t *proto[2];
	sdp_data_t *v, *p;
	uint16_t psm = 15, version = 0x0100;
	int status;

	session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!session) {
		syslog(LOG_ERR, "Failed to connect to the local SDP server. %s(%d)", 
				strerror(errno), errno);
		return -1;
	}

	record = sdp_record_alloc();
	if (!record) {
		syslog(LOG_ERR, "Failed to allocate service record %s(%d)", 
				strerror(errno), errno);
		sdp_close(session);
		return -1;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, 0);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	p = sdp_data_alloc(SDP_UINT16, &psm);
	proto[0] = sdp_list_append(proto[0], p);
	apseq    = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&bnep, BNEP_UUID);
	proto[1] = sdp_list_append(NULL, &bnep);
	v = sdp_data_alloc(SDP_UINT16, &version);
	proto[1] = sdp_list_append(proto[1], v);

	/* Supported protocols */
	{
		uint16_t ptype[4] = { 
			0x0800,  /* IPv4 */
			0x0806,  /* ARP */
		};
		sdp_data_t *head, *pseq;
		int p;

		for (p = 0, head = NULL; p < 2; p++) {
			sdp_data_t *data = sdp_data_alloc(SDP_UINT16, &ptype[p]);
			if (head)
				sdp_seq_append(head, data);
			else
				head = data;
		}
		pseq = sdp_data_alloc(SDP_SEQ16, head);
		proto[1] = sdp_list_append(proto[1], pseq);
	}

	apseq    = sdp_list_append(apseq, proto[1]);
	
	aproto   = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_data_free(p);
	sdp_data_free(v);

	switch (role) {
	case BNEP_SVC_NAP:
		sdp_uuid16_create(&pan, NAP_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, NAP_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, "Network Access Point", NULL, NULL);
		break;

	case BNEP_SVC_GN:
		sdp_uuid16_create(&pan, GN_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, GN_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);
		
		sdp_set_info_attr(record, "Group Network Service", NULL, NULL);
		break;

	case BNEP_SVC_PANU:
		sdp_uuid16_create(&pan, PANU_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);
		sdp_list_free(svclass, 0);

		sdp_uuid16_create(&profile[0].uuid, PANU_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);
		sdp_list_free(pfseq, 0);

		sdp_set_info_attr(record, "PAN User", NULL, NULL);
		break;
	}

	status = sdp_device_record_register(session, device, record, 0);
	if (status) {
		syslog(LOG_ERR, "SDP registration failed.");
		sdp_record_free(record); record = NULL;
		sdp_close(session);
		return -1;
	}
	return 0;
}

/* Search for PAN service.
 * Returns 1 if service is found and 0 otherwise. */
int bnep_sdp_search(bdaddr_t *src, bdaddr_t *dst, uint16_t service)
{
	sdp_list_t *srch, *rsp = NULL;
	sdp_session_t *s;
	uuid_t svclass;
	int err;

	switch (service) {
	case BNEP_SVC_PANU:
		sdp_uuid16_create(&svclass, PANU_SVCLASS_ID);
		break;
	case BNEP_SVC_NAP:
		sdp_uuid16_create(&svclass, NAP_SVCLASS_ID);
		break;
	case BNEP_SVC_GN:
		sdp_uuid16_create(&svclass, GN_SVCLASS_ID);
		break;
	}
		
	srch = sdp_list_append(NULL, &svclass);

	s = sdp_connect(src, dst, 0);
	if (!s) {
		syslog(LOG_ERR, "Failed to connect to the SDP server. %s(%d)",
				strerror(errno), errno);
		return 0;
	}

	err = sdp_service_search_req(s, srch, 1, &rsp);
	sdp_close(s);

	/* Assume that search is successeful
	 * if at least one record is found */
	if (!err && sdp_list_len(rsp))
		return 1;

	return 0;
}
