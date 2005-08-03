/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
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

#ifndef SDPD_H
#define SDPD_H

#define sdp_get_unaligned bt_get_unaligned
#define sdp_put_unaligned bt_put_unaligned

#define SDPINF(fmt, arg...) syslog(LOG_INFO, fmt "\n", ## arg)
#define SDPERR(fmt, arg...) syslog(LOG_ERR, "%s: " fmt "\n", __func__ , ## arg)

#ifdef SDP_DEBUG
#define SDPDBG(fmt, arg...) syslog(LOG_DEBUG, "%s: " fmt "\n", __func__ , ## arg)
#else
#define SDPDBG(fmt...)
#endif

typedef struct request {
	bdaddr_t device;
	bdaddr_t bdaddr;
	int      local;
	int      sock;
	int      mtu;
	int      flags;
	uint8_t  *buf;
	int      len;
} sdp_req_t;

void process_request(sdp_req_t *req);

int service_register_req(sdp_req_t *req, sdp_buf_t *rsp);
int service_update_req(sdp_req_t *req, sdp_buf_t *rsp);
int service_remove_req(sdp_req_t *req, sdp_buf_t *rsp);

typedef struct {
	uint32_t timestamp;
	union {
		uint16_t maxBytesSent;
		uint16_t lastIndexSent;
	} cStateValue;
} sdp_cont_state_t;

#define SDP_CONT_STATE_SIZE (sizeof(uint8_t) + sizeof(sdp_cont_state_t))

sdp_buf_t *sdp_get_cached_rsp(sdp_cont_state_t *cstate);
void sdp_cstate_cache_init(void);
void sdp_cstate_clean_buf(void);
uint32_t sdp_cstate_alloc_buf(sdp_buf_t *buf);

void sdp_svcdb_reset(void);
void sdp_svcdb_collect_all(int sock);
void sdp_svcdb_set_collectable(sdp_record_t *rec, int sock);
void sdp_svcdb_collect(sdp_record_t *rec);
sdp_record_t *sdp_record_find(uint32_t handle);
void sdp_record_add(bdaddr_t *device, sdp_record_t *rec);
int sdp_record_remove(uint32_t handle);
sdp_list_t *sdp_get_record_list();
uint32_t sdp_next_handle(void);

uint32_t sdp_get_time();

#endif
