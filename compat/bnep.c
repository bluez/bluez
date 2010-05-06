/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include <netinet/in.h>

#include "pand.h"

static int ctl;

/* Compatibility with old ioctls */
#define OLD_BNEPCONADD      1
#define OLD_BNEPCONDEL      2
#define OLD_BNEPGETCONLIST  3
#define OLD_BNEPGETCONINFO  4

static unsigned long bnepconnadd;
static unsigned long bnepconndel;
static unsigned long bnepgetconnlist;
static unsigned long bnepgetconninfo;

static struct {
	char     *str;
	uint16_t uuid;
} __svc[] = {
	{ "PANU", BNEP_SVC_PANU },
	{ "NAP",  BNEP_SVC_NAP  },
	{ "GN",   BNEP_SVC_GN   },
	{ NULL }
};

int bnep_str2svc(char *svc, uint16_t *uuid)
{
	int i;
	for (i = 0; __svc[i].str; i++)
		if (!strcasecmp(svc, __svc[i].str)) {
			*uuid = __svc[i].uuid;
			return 0;
		}
	return -1;
}

char *bnep_svc2str(uint16_t uuid)
{
	int i;
	for (i = 0; __svc[i].str; i++)
		if (__svc[i].uuid == uuid)
			return __svc[i].str;
	return NULL;
}

int bnep_init(void)
{
	ctl = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_BNEP);
	if (ctl < 0) {
		perror("Failed to open control socket");
		return 1;
	}

	/* Temporary ioctl compatibility hack */
	{
		struct bnep_connlist_req req;
		struct bnep_conninfo ci[1];

		req.cnum = 1;
		req.ci   = ci;

		if (!ioctl(ctl, BNEPGETCONNLIST, &req)) {
			/* New ioctls */
			bnepconnadd     = BNEPCONNADD;
			bnepconndel     = BNEPCONNDEL;
			bnepgetconnlist = BNEPGETCONNLIST;
			bnepgetconninfo = BNEPGETCONNINFO;
		} else {
			/* Old ioctls */
			bnepconnadd     = OLD_BNEPCONADD;
			bnepconndel     = OLD_BNEPCONDEL;
			bnepgetconnlist = OLD_BNEPGETCONLIST;
			bnepgetconninfo = OLD_BNEPGETCONINFO;
		}
	}

	return 0;
}

int bnep_cleanup(void)
{
	close(ctl);
	return 0;
}

int bnep_show_connections(void)
{
	struct bnep_connlist_req req;
	struct bnep_conninfo ci[48];
	unsigned int i;

	req.cnum = 48;
	req.ci   = ci;
	if (ioctl(ctl, bnepgetconnlist, &req)) {
		perror("Failed to get connection list");
		return -1;
	}

	for (i = 0; i < req.cnum; i++) {
		printf("%s %s %s\n", ci[i].device,
			batostr((bdaddr_t *) ci[i].dst),
			bnep_svc2str(ci[i].role));
	}
	return 0;
}

int bnep_kill_connection(uint8_t *dst)
{
	struct bnep_conndel_req req;

	memcpy(req.dst, dst, ETH_ALEN);
	req.flags = 0;
	if (ioctl(ctl, bnepconndel, &req)) {
		perror("Failed to kill connection");
		return -1;
	}
	return 0;
}

int bnep_kill_all_connections(void)
{
	struct bnep_connlist_req req;
	struct bnep_conninfo ci[48];
	unsigned int i;

	req.cnum = 48;
	req.ci   = ci;
	if (ioctl(ctl, bnepgetconnlist, &req)) {
		perror("Failed to get connection list");
		return -1;
	}

	for (i = 0; i < req.cnum; i++) {
		struct bnep_conndel_req req;
		memcpy(req.dst, ci[i].dst, ETH_ALEN);
		req.flags = 0;
		ioctl(ctl, bnepconndel, &req);
	}
	return 0;
}

static int bnep_connadd(int sk, uint16_t role, char *dev)
{
	struct bnep_connadd_req req;

	strncpy(req.device, dev, 16);
	req.device[15] = '\0';
	req.sock = sk;
	req.role = role;
	if (ioctl(ctl, bnepconnadd, &req))
		return -1;
	strncpy(dev, req.device, 16);
	return 0;
}

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

struct __service_32 {
	uint16_t unused1;
	uint16_t dst;
	uint16_t unused2;
	uint16_t src;
} __attribute__ ((packed));

struct __service_128 {
	uint16_t unused1;
	uint16_t dst;
	uint16_t unused2[8];
	uint16_t src;
	uint16_t unused3[7];
} __attribute__ ((packed));

int bnep_accept_connection(int sk, uint16_t role, char *dev)
{
	struct bnep_setup_conn_req *req;
	struct bnep_control_rsp *rsp;
	unsigned char pkt[BNEP_MTU];
	ssize_t r;

	r = recv(sk, pkt, BNEP_MTU, 0);
	if (r <= 0)
		return -1;

	errno = EPROTO;

	if ((size_t) r < sizeof(*req))
		return -1;

	req = (void *) pkt;
	if (req->type != BNEP_CONTROL || req->ctrl != BNEP_SETUP_CONN_REQ)
		return -1;

	/* FIXME: Check role UUIDs */

	rsp = (void *) pkt;
	rsp->type = BNEP_CONTROL;
	rsp->ctrl = BNEP_SETUP_CONN_RSP;
	rsp->resp = htons(BNEP_SUCCESS);
	if (send(sk, rsp, sizeof(*rsp), 0) < 0)
		return -1;

	return bnep_connadd(sk, role, dev);
}

/* Create BNEP connection
 * sk      - Connect L2CAP socket
 * role    - Local role
 * service - Remote service
 * dev     - Network device (contains actual dev name on return)
 */
int bnep_create_connection(int sk, uint16_t role, uint16_t svc, char *dev)
{
	struct bnep_setup_conn_req *req;
	struct bnep_control_rsp *rsp;
	struct __service_16 *s;
	struct timeval timeo;
	unsigned char pkt[BNEP_MTU];
	ssize_t r;

	/* Send request */
	req = (void *) pkt;
	req->type = BNEP_CONTROL;
	req->ctrl = BNEP_SETUP_CONN_REQ;
	req->uuid_size = 2;	/* 16bit UUID */

	s = (void *) req->service;
	s->dst = htons(svc);
	s->src = htons(role);

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 30;

	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

	if (send(sk, pkt, sizeof(*req) + sizeof(*s), 0) < 0)
		return -1;

receive:
	/* Get response */
	r = recv(sk, pkt, BNEP_MTU, 0);
	if (r <= 0)
		return -1;

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 0;

	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

	errno = EPROTO;

	if ((size_t) r < sizeof(*rsp))
		return -1;

	rsp = (void *) pkt;
	if (rsp->type != BNEP_CONTROL)
		return -1;

	if (rsp->ctrl != BNEP_SETUP_CONN_RSP)
		goto receive;

	r = ntohs(rsp->resp);

	switch (r) {
	case BNEP_SUCCESS:
		break;

	case BNEP_CONN_INVALID_DST:
	case BNEP_CONN_INVALID_SRC:
	case BNEP_CONN_INVALID_SVC:
		errno = EPROTO;
		return -1;

	case BNEP_CONN_NOT_ALLOWED:
		errno = EACCES;
		return -1;
	}

	return bnep_connadd(sk, role, dev);
}
