/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <malloc.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "sdpd.h"

typedef struct _sdp_cstate_list sdp_cstate_list_t;

struct _sdp_cstate_list {
	sdp_cstate_list_t *next;
	uint32_t timestamp;
	sdp_buf_t buf;
};

static sdp_cstate_list_t *cstates;

// FIXME: should probably remove it when it's found
sdp_buf_t *sdp_get_cached_rsp(sdp_cont_state_t *cstate)
{
	sdp_cstate_list_t *p;

	for (p = cstates; p; p = p->next)
		if (p->timestamp == cstate->timestamp)
			return &p->buf;
	return 0;
}

uint32_t sdp_cstate_alloc_buf(sdp_buf_t *buf)
{
	sdp_cstate_list_t *cstate = (sdp_cstate_list_t *)malloc(sizeof(sdp_cstate_list_t));
	uint8_t *data = malloc(buf->data_size);

	memcpy(data, buf->data, buf->data_size);
	memset((char *)cstate, 0, sizeof(sdp_cstate_list_t));
	cstate->buf.data = data;
	cstate->buf.data_size = buf->data_size;
	cstate->buf.buf_size = buf->data_size;
	cstate->timestamp = sdp_get_time();
	cstate->next = cstates;
	cstates = cstate;
	return cstate->timestamp;
}

/*
 * A simple function which returns the time of day in
 * seconds. Used for updating the service db state
 * attribute of the service record of the SDP server
 */
uint32_t sdp_get_time()
{
	/*
	 * To handle failure in gettimeofday, so an old
	 * value is returned and service does not fail
	 */
	static struct timeval tm;

	gettimeofday(&tm, NULL);
	return (uint32_t) tm.tv_sec;
}
