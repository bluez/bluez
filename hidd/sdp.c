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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hidp.h>

#include "hidd.h"

int get_hid_device_info(bdaddr_t *src, bdaddr_t *dst, struct hidp_connadd_req *req)
{
	sdp_session_t *s;
	sdp_list_t *srch, *attrs, *rsp;
	sdp_record_t *rec;
	sdp_data_t *pdlist;
	uuid_t svclass;
	uint16_t attr;
	int err;

	s = sdp_connect(src, dst, 0);
	if (!s)
		return -1;

	sdp_uuid16_create(&svclass, HID_SVCLASS_ID);
	srch  = sdp_list_append(NULL, &svclass);

	attr  = 0x0206;
	attrs = sdp_list_append(NULL, &attr);

	err = sdp_service_search_attr_req(s, srch, SDP_ATTR_REQ_INDIVIDUAL, attrs, &rsp);

	sdp_close(s);

	if (err || !rsp)
		return -1;

	rec = (sdp_record_t *) rsp->data;

	pdlist = sdp_data_get(rec, 0x0206);
	pdlist = pdlist->val.dataseq;
	pdlist = pdlist->val.dataseq;
	pdlist = pdlist->next;

	req->rd_data = malloc(pdlist->unitSize);
	if (req->rd_data) {
		memcpy(req->rd_data, (unsigned char *) pdlist->val.str, pdlist->unitSize);
		req->rd_size = pdlist->unitSize;
	}

	return 0;
}
