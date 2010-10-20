/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hidp.h>
#include <bluetooth/bnep.h>

#include "textfile.h"
#include "sdp.h"

static sdp_record_t *record = NULL;
static sdp_session_t *session = NULL;

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

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
	unsigned int i;

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
	int i, err, size;

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "hidd");

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

	free(desc);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dst, addr);
	err = textfile_put(filename, addr, str);

	free(str);

	return err;
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
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "hidd");

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str) {
		free(desc);
		return -EIO;
	}

	sscanf(str, "%04X:%04X:%04X %02X %02X %04X %4095s %08X %n",
			&vendor, &product, &version, &subclass, &country,
			&parser, desc, &req->flags, &pos);


	req->vendor   = vendor;
	req->product  = product;
	req->version  = version;
	req->subclass = subclass;
	req->country  = country;
	req->parser   = parser;

	snprintf(req->name, 128, "%s", str + pos);

	free(str);
	req->rd_size = strlen(desc) / 2;
	req->rd_data = malloc(req->rd_size);
	if (!req->rd_data) {
		free(desc);
		return -ENOMEM;
	}

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < req->rd_size; i++) {
		memcpy(tmp, desc + (i * 2), 2);
		req->rd_data[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	free(desc);

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

	pdlist2 = sdp_data_get(rec, 0x0100);
	if (pdlist2)
		strncpy(req->name, pdlist2->val.str, sizeof(req->name) - 1);
	else {
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
				strncpy(req->name, pdlist->val.str, sizeof(req->name) - 1);
		}
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

int get_alternate_device_info(const bdaddr_t *src, const bdaddr_t *dst, uint16_t *uuid, uint8_t *channel, char *name, size_t len)
{
	uint16_t attr1 = SDP_ATTR_PROTO_DESC_LIST;
	uint16_t attr2 = SDP_ATTR_SVCNAME_PRIMARY;
	sdp_session_t *s;
	sdp_list_t *search, *attrid, *rsp;
	uuid_t svclass;
	int err;

	s = sdp_connect(src, dst, SDP_RETRY_IF_BUSY | SDP_WAIT_ON_CLOSE);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, HEADSET_SVCLASS_ID);
	search = sdp_list_append(NULL, &svclass);
	attrid = sdp_list_append(NULL, &attr1);
	attrid = sdp_list_append(attrid, &attr2);

	err = sdp_service_search_attr_req(s, search,
					SDP_ATTR_REQ_INDIVIDUAL, attrid, &rsp);

	sdp_list_free(search, NULL);
	sdp_list_free(attrid, NULL);

	if (err <= 0) {
		sdp_uuid16_create(&svclass, SERIAL_PORT_SVCLASS_ID);
		search = sdp_list_append(NULL, &svclass);
		attrid = sdp_list_append(NULL, &attr1);
		attrid = sdp_list_append(attrid, &attr2);

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

		sdp_get_service_name(rec, name, len);

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
	uint16_t security_desc = 0;
	uint16_t net_access_type = 0xfffe;
	uint32_t max_net_access_rate = 0;
	char *name = "BlueZ PAN";
	char *desc = "BlueZ PAN Service";
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

	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	add_lang_attr(record);

	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_data_free(p);
	sdp_data_free(v);
	sdp_attr_add_new(record, SDP_ATTR_SECURITY_DESC, SDP_UINT16, &security_desc);

	switch (role) {
	case BNEP_SVC_NAP:
		sdp_uuid16_create(&pan, NAP_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, NAP_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, "Network Access Point", name, desc);

		sdp_attr_add_new(record, SDP_ATTR_NET_ACCESS_TYPE, SDP_UINT16, &net_access_type);
		sdp_attr_add_new(record, SDP_ATTR_MAX_NET_ACCESSRATE, SDP_UINT32, &max_net_access_rate);
		break;

	case BNEP_SVC_GN:
		sdp_uuid16_create(&pan, GN_SVCLASS_ID);
		svclass = sdp_list_append(NULL, &pan);
		sdp_set_service_classes(record, svclass);

		sdp_uuid16_create(&profile[0].uuid, GN_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);

		sdp_set_info_attr(record, "Group Network Service", name, desc);
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

		sdp_set_info_attr(record, "PAN User", name, desc);
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

static unsigned char async_uuid[] = {	0x03, 0x50, 0x27, 0x8F, 0x3D, 0xCA, 0x4E, 0x62,
					0x83, 0x1D, 0xA4, 0x11, 0x65, 0xFF, 0x90, 0x6C };

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

	switch (type) {
	case LANACCESS:
		sdp_uuid16_create(&profile[0].uuid, LAN_ACCESS_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);
		break;
	case DIALUP:
		sdp_uuid16_create(&profile[0].uuid, DIALUP_NET_PROFILE_ID);
		profile[0].version = 0x0100;
		pfseq = sdp_list_append(NULL, &profile[0]);
		sdp_set_profile_descs(record, pfseq);
		break;
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
	case DIALUP:
		sdp_uuid16_create(&svclass, DIALUP_NET_SVCLASS_ID);
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
