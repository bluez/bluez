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

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/sockios.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include "bridge.h"

static int bridge_socket = -1;
static const char *gn_bridge;
static const char *nap_bridge;

int bridge_init(const char *gn_iface, const char *nap_iface)
{
#if 0
	struct stat st;

	if (stat("/sys/module/bridge", &st) < 0)
		return -EOPNOTSUPP;
#endif

	bridge_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (bridge_socket < 0)
		return -errno;

	gn_bridge = gn_iface;
	nap_bridge = nap_iface;
	return 0;
}

void bridge_cleanup(void)
{
	close(bridge_socket);

	bridge_socket = -1;
}

int bridge_create(int id)
{
	int err;
	const char *name = bridge_get_name(id);

	err = ioctl(bridge_socket, SIOCBRADDBR, name);
	if (err < 0)
		return -errno;

	return 0;
}

int bridge_remove(int id)
{
	int err;
	const char *name = bridge_get_name(id);

	err = ioctl(bridge_socket, SIOCBRDELBR, name);
	if (err < 0)
		return -errno;

	return 0;
}

int bridge_add_interface(int id, const char *dev)
{
	struct ifreq ifr;
	int ifindex = if_nametoindex(dev);
	const char *name = bridge_get_name(id);

	if (ifindex == 0)
		return -ENODEV;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_ifindex = ifindex;

	if (ioctl(bridge_socket, SIOCBRADDIF, &ifr) < 0)
		return -errno;

	return 0;
}

const char *bridge_get_name(int id)
{
	if (id == BNEP_SVC_GN)
		return gn_bridge;

	if (id == BNEP_SVC_NAP)
		return nap_bridge;

	return NULL;
}
