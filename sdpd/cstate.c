/*
   Service Discovery Protocol (SDP)
   Copyright (C) 2002 Maxim Krasnyansky <maxk@qualcomm.com>, Stephen Crane <steve.crane@rococosoft.com>
   
   Based on original SDP implementation by Nokia Corporation.
   Copyright (C) 2001,2002 Nokia Corporation.
   Original author Guruprasad Krishnamurthy <guruprasad.krishnamurthy@nokia.com>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
   OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
   RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
   NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
   USE OR PERFORMANCE OF THIS SOFTWARE.
   
   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
   TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/

/*
   Fixes:
	Guruprasad Krishnamurthy <guruprasad.krishnamurthy@nokia.com>
*/

/*
 * $Id$
 */

#include <malloc.h>
#include <sys/time.h>

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "sdpd.h"

typedef struct _sdp_cstate_list sdp_cstate_list_t;

struct _sdp_cstate_list {
	sdp_cstate_list_t *next;
        long timestamp;
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

long sdp_cstate_alloc_buf(sdp_buf_t *buf)
{
	sdp_cstate_list_t *cstate = (sdp_cstate_list_t *)malloc(sizeof(sdp_cstate_list_t));
	char *data = (char *)malloc(buf->data_size);

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
long sdp_get_time()
{
	/*
	 * To handle failure in gettimeofday, so an old
	 * value is returned and service does not fail
	 */
	static struct timeval tm;

	gettimeofday(&tm, NULL);
	return tm.tv_sec;
}
