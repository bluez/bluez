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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <malloc.h>
#include <syslog.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "sdpd.h"

static sdp_list_t *service_db;

/*
 * Ordering function called when inserting a service record.
 * The service repository is a linked list in sorted order
 * and the service record handle is the sort key
 */
static int record_sort(const void *r1, const void *r2)
{
	const sdp_record_t *rec1 = (const sdp_record_t *)r1;
	const sdp_record_t *rec2 = (const sdp_record_t *)r2;

	if (!rec1 || !rec2) {
		SDPERR("NULL RECORD LIST FATAL\n");
		return -1;
	}
	return rec1->handle - rec2->handle;
}

/*
 * Reset the service repository by deleting its contents
 */
void sdp_svcdb_reset()
{
	sdp_list_free(service_db, (sdp_free_func_t)sdp_record_free);
}

typedef struct _indexed {
	int sock;
	sdp_record_t *record;
} sdp_indexed_t;

static sdp_list_t *socket_index;

/*
 * collect all services registered over this socket
 */
void sdp_svcdb_collect_all(int sock)
{
	sdp_list_t *p, *q;

	for (p=socket_index, q=0; p; ) {
		sdp_indexed_t *item = (sdp_indexed_t *)p->data;
		if (item->sock == sock) {
			sdp_list_t *next = p->next;
			sdp_record_remove(item->record->handle);
			free(item);
			if (q)
				q->next = next;
			else
				socket_index = next;
			free(p);
			p = next;
		} else if (item->sock > sock)
			return;
		else {
			q = p;
			p = p->next;
		}
	}
}

void sdp_svcdb_collect(sdp_record_t *rec)
{
	sdp_list_t *p, *q;

	for (p=socket_index, q=0; p; q=p, p=p->next) {
		sdp_indexed_t *item = (sdp_indexed_t *)p->data;
		if (rec == item->record) {
			free(item);
			if (q)
				q->next = p->next;
			else
				socket_index = p->next;
			free(p);
			return;
		}
	}
}

static int compare_indices(const void *i1, const void *i2)
{
	const sdp_indexed_t *s1 = (const sdp_indexed_t *)i1;
	const sdp_indexed_t *s2 = (const sdp_indexed_t *)i2;
	return s1->sock - s2->sock;
}

void sdp_svcdb_set_collectable(sdp_record_t *record, int sock)
{
	sdp_indexed_t *item = (sdp_indexed_t *)malloc(sizeof(sdp_indexed_t));
	item->sock = sock;
	item->record = record;
	socket_index = sdp_list_insert_sorted(socket_index, item, compare_indices);
}

/*
 * Add a service record to the repository
 */
void sdp_record_add(sdp_record_t *rec)
{
#ifdef SDP_DEBUG
	SDPDBG("Adding rec : 0x%lx\n", (long) rec);
	SDPDBG("with handle : 0x%x\n", rec->handle);
#endif
	service_db = sdp_list_insert_sorted(service_db, rec, record_sort);
}

static sdp_list_t *record_locate(uint32_t handle)
{
	if (service_db) {
		sdp_list_t *p;
		sdp_record_t r;

		r.handle = handle;
		p = sdp_list_find(service_db, &r, record_sort);
		return p;
	}
	SDPDBG("Could not find svcRec for : 0x%x\n", handle);
	return 0;
}

/*
 * Given a service record handle, find the record associated with it.
 */
sdp_record_t *sdp_record_find(uint32_t handle)
{
        sdp_list_t *p = record_locate(handle);

        if (p)
                return (sdp_record_t *)p->data;
	SDPDBG("Couldn't find record for : 0x%x\n", handle);
        return 0;
}

/*
 * Given a service record handle, remove its record from the repository
 */
int sdp_record_remove(uint32_t handle)
{
	sdp_list_t *p = record_locate(handle);

	if (p) {
		sdp_record_t *r = (sdp_record_t *)p->data;
		if (r) {
			service_db = sdp_list_remove(service_db, r);
			return 0;
		}
	}
	SDPERR("Remove : Couldn't find record for : 0x%x\n", handle);
	return -1;
}

/*
 * Return a pointer to the linked list containing the records in sorted order
 */
sdp_list_t *sdp_get_record_list()
{
	return service_db;
}

uint32_t sdp_next_handle(void)
{
	uint32_t handle = 0x10000;

	while (sdp_record_find(handle))
		handle++;

	return handle;
}
