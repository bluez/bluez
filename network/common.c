/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include "logging.h"
#include "common.h"

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
		error("Failed to open control socket");
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

int bnep_kill_connection(const char *addr)
{
	struct bnep_conndel_req req;
	uint8_t *dst = (void *) strtoba(addr);

	memcpy(req.dst, dst, ETH_ALEN);
	req.flags = 0;
	if (ioctl(ctl, bnepconndel, &req)) {
		error("Failed to kill connection");
		return -1;
	}
	return 0;
}

int bnep_kill_all_connections(void)
{
	struct bnep_connlist_req req;
	struct bnep_conninfo ci[48];
	int i;

	req.cnum = 48;
	req.ci   = ci;
	if (ioctl(ctl, bnepgetconnlist, &req)) {
		error("Failed to get connection list");
		return -1;
	}

	for (i=0; i < req.cnum; i++) {
		struct bnep_conndel_req req;
		memcpy(req.dst, ci[i].dst, ETH_ALEN);
		req.flags = 0;
		ioctl(ctl, bnepconndel, &req);
	}
	return 0;
}

int bnep_connadd(int sk, uint16_t role, char *dev)
{
	struct bnep_connadd_req req;

	strncpy(req.device, dev, 16);
	req.device[15] = '\0';
	req.sock = sk;
	req.role = role;
	if (ioctl(ctl, bnepconnadd, &req)) {
		error("Failed to add device %s", dev);
		return -1;
	}
	strncpy(dev, req.device, 16);
	return 0;
}
