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
#include "bnep.h"
#include "lib/uuid.h"

#define CON_SETUP_RETRIES      3
#define CON_SETUP_TO           9

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

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

struct bnep_conn {
	GIOChannel	*io;
	uint16_t	src;
	uint16_t	dst;
	guint	attempts;
	guint	setup_to;
	void	*data;
	bnep_connect_cb	conn_cb;
};

static void free_bnep_connect(struct bnep_conn *bc)
{
	if (!bc)
		return;

	if (bc->io) {
		g_io_channel_unref(bc->io);
		bc->io = NULL;
	}

	g_free(bc);
	bc = NULL;
}

uint16_t bnep_service_id(const char *svc)
{
	int i;
	uint16_t id;

	/* Friendly service name */
	for (i = 0; __svc[i].name; i++) {
		if (!strcasecmp(svc, __svc[i].name))
			return __svc[i].id;
	}

	/* UUID 128 string */
	for (i = 0; __svc[i].uuid128; i++) {
		if (!strcasecmp(svc, __svc[i].uuid128))
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

		if (err == -EPROTONOSUPPORT)
			warn("kernel lacks bnep-protocol support");
		else
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

int bnep_kill_connection(const bdaddr_t *dst)
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

int bnep_connadd(int sk, uint16_t role, char *dev)
{
	struct bnep_connadd_req req;

	memset(dev, 0, 16);
	memset(&req, 0, sizeof(req));
	strcpy(req.device, "bnep%d");
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

static gboolean bnep_setup_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct bnep_conn *bc = data;
	struct bnep_control_rsp *rsp;
	struct timeval timeo;
	char pkt[BNEP_MTU];
	char iface[16];
	ssize_t r;
	int sk;

	if (cond & G_IO_NVAL)
		goto failed;

	if (bc->setup_to > 0) {
		g_source_remove(bc->setup_to);
		bc->setup_to = 0;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on l2cap server socket");
		goto failed;
	}

	sk = g_io_channel_unix_get_fd(chan);
	memset(pkt, 0, BNEP_MTU);
	r = read(sk, pkt, sizeof(pkt) - 1);
	if (r < 0) {
		error("IO Channel read error");
		goto failed;
	}

	if (r == 0) {
		error("No packet received on l2cap socket");
		goto failed;
	}

	errno = EPROTO;

	if ((size_t) r < sizeof(*rsp)) {
		error("Packet received is not bnep type");
		goto failed;
	}

	rsp = (void *) pkt;
	if (rsp->type != BNEP_CONTROL) {
		error("Packet received is not bnep type");
		goto failed;
	}

	if (rsp->ctrl != BNEP_SETUP_CONN_RSP)
		return TRUE;

	r = ntohs(rsp->resp);
	if (r != BNEP_SUCCESS) {
		error("bnep failed");
		goto failed;
	}

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 0;
	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

	sk = g_io_channel_unix_get_fd(bc->io);
	if (bnep_connadd(sk, bc->src, iface)) {
		error("bnep conn could not be added");
		goto failed;
	}

	if (bnep_if_up(iface)) {
		error("could not up %s", iface);
		goto failed;
	}

	bc->conn_cb(chan, iface, 0, bc->data);
	free_bnep_connect(bc);

	return FALSE;

failed:
	bc->conn_cb(NULL, NULL, -EIO, bc->data);
	free_bnep_connect(bc);

	return FALSE;
}

static int bnep_setup_conn_req(struct bnep_conn *bc)
{
	struct bnep_setup_conn_req *req;
	struct __service_16 *s;
	unsigned char pkt[BNEP_MTU];
	int fd;

	/* Send request */
	req = (void *) pkt;
	req->type = BNEP_CONTROL;
	req->ctrl = BNEP_SETUP_CONN_REQ;
	req->uuid_size = 2;     /* 16bit UUID */
	s = (void *) req->service;
	s->src = htons(bc->src);
	s->dst = htons(bc->dst);

	fd = g_io_channel_unix_get_fd(bc->io);
	if (write(fd, pkt, sizeof(*req) + sizeof(*s)) < 0) {
		error("bnep connection req send failed: %s", strerror(errno));
		return -errno;
	}

	bc->attempts++;

	return 0;
}

static gboolean bnep_conn_req_to(gpointer user_data)
{
	struct bnep_conn *bc = user_data;

	if (bc->attempts == CON_SETUP_RETRIES) {
		error("Too many bnep connection attempts");
	} else {
		error("bnep connection setup TO, retrying...");
		if (bnep_setup_conn_req(bc) == 0)
			return TRUE;
	}

	bc->conn_cb(NULL, NULL, -ETIMEDOUT, bc->data);
	free_bnep_connect(bc);

	return FALSE;
}

int bnep_connect(int sk, uint16_t src, uint16_t dst, bnep_connect_cb conn_cb,
								void *data)
{
	struct bnep_conn *bc;
	int err;

	if (!conn_cb)
		return -EINVAL;

	bc = g_new0(struct bnep_conn, 1);
	bc->io = g_io_channel_unix_new(sk);
	bc->attempts = 0;
	bc->src = src;
	bc->dst = dst;
	bc->conn_cb = conn_cb;
	bc->data = data;

	err = bnep_setup_conn_req(bc);
	if (err < 0)
		return err;

	bc->setup_to = g_timeout_add_seconds(CON_SETUP_TO,
							bnep_conn_req_to, bc);
	g_io_add_watch(bc->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							bnep_setup_cb, bc);
	return 0;
}

int bnep_add_to_bridge(const char *devname, const char *bridge)
{
	int ifindex;
	struct ifreq ifr;
	int sk, err;

	if (!devname || !bridge)
		return -EINVAL;

	ifindex = if_nametoindex(devname);

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

int bnep_del_from_bridge(const char *devname, const char *bridge)
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

	err = ioctl(sk, SIOCBRDELIF, &ifr);

	close(sk);

	if (err < 0)
		return err;

	info("bridge %s: interface %s removed", bridge, devname);

	return 0;
}
