/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <linux/sockios.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include <glib.h>

#include "log.h"
#include "common.h"

static int ctl;

static struct {
	const char	*name;		/* Friendly name */
	const char	*uuid128;	/* UUID 128 */
	uint16_t	id;		/* Service class identifier */
} __svc[] = {
	{ "panu",	PANU_UUID,	BNEP_SVC_PANU	},
	{ "gn",		GN_UUID,	BNEP_SVC_GN	},
	{ "nap",	NAP_UUID,	BNEP_SVC_NAP	},
	{ NULL }
};

uint16_t bnep_service_id(const char *svc)
{
	int i;
	uint16_t id;

	/* Friendly service name */
	for (i = 0; __svc[i].name; i++)
		if (!strcasecmp(svc, __svc[i].name)) {
			return __svc[i].id;
		}

	/* UUID 128 string */
	for (i = 0; __svc[i].uuid128; i++)
		if (!strcasecmp(svc, __svc[i].uuid128)) {
			return __svc[i].id;
		}

	/* Try convert to HEX */
	id = strtol(svc, NULL, 16);
	if ((id < BNEP_SVC_PANU) || (id > BNEP_SVC_GN))
		return 0;

	return id;
}

const char *bnep_uuid(uint16_t id)
{
	int i;

	for (i = 0; __svc[i].uuid128; i++)
		if (__svc[i].id == id)
			return __svc[i].uuid128;
	return NULL;
}

const char *bnep_name(uint16_t id)
{
	int i;

	for (i = 0; __svc[i].name; i++)
		if (__svc[i].id == id)
			return __svc[i].name;
	return NULL;
}

int bnep_init(void)
{
	ctl = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_BNEP);

	if (ctl < 0) {
		int err = -errno;
		error("Failed to open control socket: %s (%d)",
						strerror(-err), -err);
		return err;
	}

	return 0;
}

int bnep_cleanup(void)
{
	close(ctl);
	return 0;
}

int bnep_kill_connection(bdaddr_t *dst)
{
	struct bnep_conndel_req req;

	memset(&req, 0, sizeof(req));
	baswap((bdaddr_t *)&req.dst, dst);
	req.flags = 0;
	if (ioctl(ctl, BNEPCONNDEL, &req)) {
		int err = -errno;
		error("Failed to kill connection: %s (%d)",
						strerror(-err), -err);
		return err;
	}
	return 0;
}

int bnep_kill_all_connections(void)
{
	struct bnep_connlist_req req;
	struct bnep_conninfo ci[7];
	unsigned int i;
	int err;

	memset(&req, 0, sizeof(req));
	req.cnum = 7;
	req.ci   = ci;
	if (ioctl(ctl, BNEPGETCONNLIST, &req)) {
		err = -errno;
		error("Failed to get connection list: %s (%d)",
						strerror(-err), -err);
		return err;
	}

	for (i = 0; i < req.cnum; i++) {
		struct bnep_conndel_req del;

		memset(&del, 0, sizeof(del));
		memcpy(del.dst, ci[i].dst, ETH_ALEN);
		del.flags = 0;
		ioctl(ctl, BNEPCONNDEL, &del);
	}
	return 0;
}

int bnep_connadd(int sk, uint16_t role, char *dev)
{
	struct bnep_connadd_req req;

	memset(&req, 0, sizeof(req));
	strncpy(req.device, dev, 16);
	req.device[15] = '\0';
	req.sock = sk;
	req.role = role;
	if (ioctl(ctl, BNEPCONNADD, &req) < 0) {
		int err = -errno;
		error("Failed to add device %s: %s(%d)",
				dev, strerror(-err), -err);
		return err;
	}

	strncpy(dev, req.device, 16);
	return 0;
}

int bnep_if_up(const char *devname)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, IF_NAMESIZE - 1);

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_MULTICAST;

	err = ioctl(sk, SIOCSIFFLAGS, (caddr_t) &ifr);

	close(sk);

	if (err < 0) {
		error("Could not bring up %s", devname);
		return err;
	}

	return 0;
}

int bnep_if_down(const char *devname)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, IF_NAMESIZE - 1);

	ifr.ifr_flags &= ~IFF_UP;

	/* Bring down the interface */
	err = ioctl(sk, SIOCSIFFLAGS, (caddr_t) &ifr);

	close(sk);

	if (err < 0) {
		error("Could not bring down %s", devname);
		return err;
	}

	return 0;
}

int bnep_add_to_bridge(const char *devname, const char *bridge)
{
	int ifindex = if_nametoindex(devname);
	struct ifreq ifr;
	int sk, err;

	if (!devname || !bridge)
		return -EINVAL;

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
	ifr.ifr_ifindex = ifindex;

	err = ioctl(sk, SIOCBRADDIF, &ifr);

	close(sk);

	if (err < 0)
		return err;

	info("bridge %s: interface %s added", bridge, devname);

	return 0;
}
