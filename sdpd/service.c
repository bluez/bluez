/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2007  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include "sdpd.h"
#include "logging.h"

static sdp_record_t *server;

/*
 * List of version numbers supported by the SDP server.
 * Add to this list when newer versions are supported.
 */
static sdp_version_t sdpVnumArray[1] = {
	{ 1, 0 }
};
static const int sdpServerVnumEntries = 1;

/*
 * The service database state is an attribute of the service record
 * of the SDP server itself. This attribute is guaranteed to
 * change if any of the contents of the service repository
 * changes. This function updates the timestamp of value of
 * the svcDBState attribute
 * Set the SDP server DB. Simply a timestamp which is the marker
 * when the DB was modified.
 */
static void update_db_timestamp(void)
{
	uint32_t dbts = sdp_get_time();
	sdp_data_t *d = sdp_data_alloc(SDP_UINT32, &dbts);
	sdp_attr_replace(server, SDP_ATTR_SVCDB_STATE, d);
}

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	// UTF-8 MIBenum (http://www.iana.org/assignments/character-sets)
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

void register_public_browse_group(int public)
{
	sdp_list_t *browselist;
	uuid_t bgscid, pbgid;
	sdp_data_t *sdpdata;
	sdp_record_t *browse = sdp_record_alloc();

	if (public) {
		browse->handle = sdp_next_handle();
		if (browse->handle < 0x10000)
			return;
	} else
		browse->handle = SDP_SERVER_RECORD_HANDLE + 1;

	sdp_record_add(BDADDR_ANY, browse);
	sdpdata = sdp_data_alloc(SDP_UINT32, &browse->handle);
	sdp_attr_add(browse, SDP_ATTR_RECORD_HANDLE, sdpdata);

	add_lang_attr(browse);
	sdp_set_info_attr(browse, "Public Browse Group Root", "BlueZ", "Root of public browse hierarchy");

	sdp_uuid16_create(&bgscid, BROWSE_GRP_DESC_SVCLASS_ID);
	browselist = sdp_list_append(0, &bgscid);
	sdp_set_service_classes(browse, browselist);
	sdp_list_free(browselist, 0);

	if (public) {
		sdp_uuid16_create(&pbgid, PUBLIC_BROWSE_GROUP);
		sdp_set_group_id(browse, pbgid);
	}
}

/*
 * The SDP server must present its own service record to
 * the service repository. This can be accessed by service
 * discovery clients. This method constructs a service record
 * and stores it in the repository
 */
void register_server_service(int public)
{
	int i;
	sdp_list_t *classIDList, *browseList;
	sdp_list_t *access_proto = 0;
	uuid_t l2cap, classID, browseGroupId, sdpSrvUUID;
	void **versions, **versionDTDs;
	uint8_t dtd;
	uint16_t version, port;
	sdp_data_t *pData, *port_data, *version_data;
	sdp_list_t *pd, *seq;

	server = sdp_record_alloc();
	server->pattern = NULL;

	/* Force the record to be SDP_SERVER_RECORD_HANDLE */
	server->handle = SDP_SERVER_RECORD_HANDLE;

	sdp_record_add(BDADDR_ANY, server);
	sdp_attr_add(server, SDP_ATTR_RECORD_HANDLE, sdp_data_alloc(SDP_UINT32, &server->handle));

	/*
	 * Add all attributes to service record. (No need to commit since we 
	 * are the server and this record is already in the database.)
	 */
	add_lang_attr(server);
	sdp_set_info_attr(server, "SDP Server", "BlueZ", "Bluetooth service discovery server");

	sdp_uuid16_create(&classID, SDP_SERVER_SVCLASS_ID);
	classIDList = sdp_list_append(0, &classID);
	sdp_set_service_classes(server, classIDList);
	sdp_list_free(classIDList, 0);

	/*
	 * Set the version numbers supported, these are passed as arguments
	 * to the server on command line. Now defaults to 1.0
	 * Build the version number sequence first
	 */
	versions = (void **)malloc(sdpServerVnumEntries * sizeof(void *));
	versionDTDs = (void **)malloc(sdpServerVnumEntries * sizeof(void *));
	dtd = SDP_UINT16;
	for (i = 0; i < sdpServerVnumEntries; i++) {
		uint16_t *version = malloc(sizeof(uint16_t));
		*version = sdpVnumArray[i].major;
		*version = (*version << 8);
		*version |= sdpVnumArray[i].minor;
		versions[i] = version;
		versionDTDs[i] = &dtd;
	}
	pData = sdp_seq_alloc(versionDTDs, versions, sdpServerVnumEntries);
	for (i = 0; i < sdpServerVnumEntries; i++)
		free(versions[i]);
	free(versions);
	free(versionDTDs);
	sdp_attr_add(server, SDP_ATTR_VERSION_NUM_LIST, pData);

	sdp_uuid16_create(&sdpSrvUUID, SDP_UUID);
	sdp_set_service_id(server, sdpSrvUUID);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	pd = sdp_list_append(0, &l2cap);
	port = SDP_PSM;
	port_data = sdp_data_alloc(SDP_UINT16, &port);
	pd = sdp_list_append(pd, port_data);
	version = 1;
	version_data = sdp_data_alloc(SDP_UINT16, &version);
	pd = sdp_list_append(pd, version_data);
	seq = sdp_list_append(0, pd);

	access_proto = sdp_list_append(0, seq);
	sdp_set_access_protos(server, access_proto);
	sdp_list_free(access_proto, free);
	sdp_data_free(port_data);
	sdp_data_free(version_data);
	sdp_list_free(pd, 0);

	if (public) {
		sdp_uuid16_create(&browseGroupId, PUBLIC_BROWSE_GROUP);
		browseList = sdp_list_append(0, &browseGroupId);
		sdp_set_browse_groups(server, browseList);
		sdp_list_free(browseList, 0);
	}

	update_db_timestamp();
}

// FIXME: refactor for server-side
static sdp_record_t *extract_pdu_server(bdaddr_t *device, uint8_t *p, uint32_t handleExpected, int *scanned)
{
	int extractStatus = -1, localExtractedLength = 0;
	uint8_t dtd;
	int seqlen = 0;
	sdp_record_t *rec = NULL;
	uint16_t attrId, lookAheadAttrId;
	sdp_data_t *pAttr = NULL;
	uint32_t handle = 0xffffffff;

	*scanned = sdp_extract_seqtype(p, &dtd, &seqlen);
	p += *scanned;
	lookAheadAttrId = ntohs(bt_get_unaligned((uint16_t *) (p + sizeof(uint8_t))));

	debug("Look ahead attr id : %d", lookAheadAttrId);

	if (lookAheadAttrId == SDP_ATTR_RECORD_HANDLE) {
		handle = ntohl(bt_get_unaligned((uint32_t *) (p +
				sizeof(uint8_t) + sizeof(uint16_t) +
				sizeof(uint8_t))));
		debug("SvcRecHandle : 0x%x", handle);
		rec = sdp_record_find(handle);
	} else if (handleExpected != 0xffffffff)
		rec = sdp_record_find(handleExpected);

	if (!rec) {
		rec = sdp_record_alloc();
		rec->attrlist = NULL;
		if (lookAheadAttrId == SDP_ATTR_RECORD_HANDLE) {
			rec->handle = handle;
			sdp_record_add(device, rec);
		} else if (handleExpected != 0xffffffff) {
			rec->handle = handleExpected;
			sdp_record_add(device, rec);
		}
	}

	while (localExtractedLength < seqlen) {
		int attrSize = sizeof(uint8_t);
		int attrValueLength = 0;

		debug("Extract PDU, sequenceLength: %d localExtractedLength: %d", seqlen, localExtractedLength);
		dtd = *(uint8_t *) p;

		attrId = ntohs(bt_get_unaligned((uint16_t *) (p + attrSize)));
		attrSize += sizeof(uint16_t);
		
		debug("DTD of attrId : %d Attr id : 0x%x", dtd, attrId);

		pAttr = sdp_extract_attr(p + attrSize, &attrValueLength, rec);

		debug("Attr id : 0x%x attrValueLength : %d", attrId, attrValueLength);

		attrSize += attrValueLength;
		if (pAttr == NULL) {
			debug("Terminating extraction of attributes");
			break;
		}
		localExtractedLength += attrSize;
		p += attrSize;
		sdp_attr_replace(rec, attrId, pAttr);
		extractStatus = 0;
		debug("Extract PDU, seqLength: %d localExtractedLength: %d",
					seqlen, localExtractedLength);
	}

	if (extractStatus == 0) {
		debug("Successful extracting of Svc Rec attributes");
#ifdef SDP_DEBUG
		sdp_print_service_attr(rec->attrlist);
#endif
		*scanned += seqlen;
	}
	return rec;
}

/*
 * Add the newly created service record to the service repository
 */
int service_register_req(sdp_req_t *req, sdp_buf_t *rsp)
{
	int scanned = 0;
	sdp_data_t *handle;
	uint8_t *p = req->buf + sizeof(sdp_pdu_hdr_t);
	sdp_record_t *rec;

	req->flags = *p++;
	if (req->flags & SDP_DEVICE_RECORD) {
		bacpy(&req->device, (bdaddr_t *) p);
		p += sizeof(bdaddr_t);
	}

	// save image of PDU: we need it when clients request this attribute
	rec = extract_pdu_server(&req->device, p, 0xffffffff, &scanned);
	if (!rec)
		goto invalid;

	if (rec->handle == 0xffffffff) {
		rec->handle = sdp_next_handle();
		if (rec->handle < 0x10000)
			goto invalid;
	} else {
		if (sdp_record_find(rec->handle))
			goto invalid;
	}

	sdp_record_add(&req->device, rec);
	if (!(req->flags & SDP_RECORD_PERSIST))
		sdp_svcdb_set_collectable(rec, req->sock);

	handle = sdp_data_alloc(SDP_UINT32, &rec->handle);
	sdp_attr_replace(rec, SDP_ATTR_RECORD_HANDLE, handle);

	/*
	 * if the browse group descriptor is NULL,
	 * ensure that the record belongs to the ROOT group
	 */
	if (sdp_data_get(rec, SDP_ATTR_BROWSE_GRP_LIST) == NULL) {
		 uuid_t uuid;
		 sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
		 sdp_pattern_add_uuid(rec, &uuid);
	}

	update_db_timestamp();

	/* Build a rsp buffer */
	bt_put_unaligned(htonl(rec->handle), (uint32_t *) rsp->data);
	rsp->data_size = sizeof(uint32_t);

	return 0;

invalid:
	bt_put_unaligned(htons(SDP_INVALID_SYNTAX), (uint16_t *) rsp->data);
	rsp->data_size = sizeof(uint16_t);

	return -1;
}

/*
 * Update a service record
 */
int service_update_req(sdp_req_t *req, sdp_buf_t *rsp)
{
	sdp_record_t *orec;
	int status = 0, scanned = 0;
	uint8_t *p = req->buf + sizeof(sdp_pdu_hdr_t);
	uint32_t handle = ntohl(bt_get_unaligned((uint32_t *) p));

	debug("Svc Rec Handle: 0x%x", handle);

	p += sizeof(uint32_t);

	orec = sdp_record_find(handle);

	debug("SvcRecOld: %p", orec);

	if (orec) {
		sdp_record_t *nrec = extract_pdu_server(BDADDR_ANY, p, handle, &scanned);
		if (nrec && handle == nrec->handle)
			update_db_timestamp();
		else {
			debug("SvcRecHandle : 0x%x", handle);
			debug("SvcRecHandleNew : 0x%x", nrec->handle);
			debug("SvcRecNew : %p", nrec);
			debug("SvcRecOld : %p", orec);
			debug("Failure to update, restore old value");

			if (nrec)
				sdp_record_free(nrec);
			status = SDP_INVALID_SYNTAX;
		}
	} else
		status = SDP_INVALID_RECORD_HANDLE;

	p = rsp->data;
	bt_put_unaligned(htons(status), (uint16_t *) p);
	rsp->data_size = sizeof(uint16_t);
	return status;
}

/*
 * Remove a registered service record
 */
int service_remove_req(sdp_req_t *req, sdp_buf_t *rsp)
{
	uint8_t *p = req->buf + sizeof(sdp_pdu_hdr_t);
	uint32_t handle = ntohl(bt_get_unaligned((uint32_t *) p));
	sdp_record_t *rec;
	int status = 0;

	/* extract service record handle */
	p += sizeof(uint32_t);

	rec = sdp_record_find(handle);
	if (rec) {
		sdp_svcdb_collect(rec);
		status = sdp_record_remove(handle);
		sdp_record_free(rec);
		if (status == 0)
			update_db_timestamp();
	} else {
		status = SDP_INVALID_RECORD_HANDLE;
		debug("Could not find record : 0x%x", handle);
	}

	p = rsp->data;
	bt_put_unaligned(htons(status), (uint16_t *) p);
	rsp->data_size = sizeof(uint16_t);

	return status;
}
