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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <net/if.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include <glib.h>

#include "logging.h"
#include "common.h"
#include "textfile.h"

static int ctl;
static GSList *pids;

#define PANU_UUID	"00001115-0000-1000-8000-00805f9b34fb"
#define NAP_UUID	"00001116-0000-1000-8000-00805f9b34fb"
#define GN_UUID		"00001117-0000-1000-8000-00805f9b34fb"

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

static const char *panu = NULL;
static const char *gn = NULL;
static const char *nap = NULL;

struct bnep_data {
	char *devname;
	int pid;
};

static void script_exited(GPid pid, gint status, gpointer data)
{
	struct bnep_data *bnep = data;

	if (WIFEXITED(status))
		debug("%d exited with status %d", pid, WEXITSTATUS(status));
	else
		debug("%d was killed by signal %d", pid, WTERMSIG(status));

	g_spawn_close_pid(pid);
	pid = 0;

	g_free(bnep->devname);
	pids = g_slist_remove(pids, bnep);
}

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

int bnep_init(const char *panu_script, const char *gn_script,
		const char *nap_script)
{
	ctl = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_BNEP);

	if (ctl < 0) {
		int err = errno;
		error("Failed to open control socket: %s (%d)",
						strerror(err), err);
		return -err;
	}

	panu = panu_script;
	gn = gn_script;
	nap = nap_script;
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

	baswap((bdaddr_t *)&req.dst, dst);
	req.flags = 0;
	if (ioctl(ctl, BNEPCONNDEL, &req)) {
		int err = errno;
		error("Failed to kill connection: %s (%d)",
						strerror(err), err);
		return -err;
	}
	return 0;
}

int bnep_kill_all_connections(void)
{
	struct bnep_connlist_req req;
	struct bnep_conninfo ci[7];
	int i, err;

	memset(&req, 0, sizeof(req));
	req.cnum = 7;
	req.ci   = ci;
	if (ioctl(ctl, BNEPGETCONNLIST, &req)) {
		err = errno;
		error("Failed to get connection list: %s (%d)",
						strerror(err), err);
		return -err;
	}

	for (i=0; i < req.cnum; i++) {
		struct bnep_conndel_req req;
		memcpy(req.dst, ci[i].dst, ETH_ALEN);
		req.flags = 0;
		ioctl(ctl, BNEPCONNDEL, &req);
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
	if (ioctl(ctl, BNEPCONNADD, &req) < 0) {
		int err = errno;
		error("Failed to add device %s: %s(%d)",
				dev, strerror(err), err);
		return -err;
	}

	strncpy(dev, req.device, 16);
	return 0;
}

static void bnep_setup(gpointer data)
{
}

int bnep_if_up(const char *devname, uint16_t id)
{
	int sd, err, pid;
	struct ifreq ifr;
	const char *argv[3], *script;
	struct bnep_data *bnep;
	GSpawnFlags flags;

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, devname);

	ifr.ifr_flags |= IFF_UP;

	if ((ioctl(sd, SIOCSIFFLAGS, (caddr_t) &ifr)) < 0) {
		err = errno;
		error("Could not bring up %d. %s(%d)", devname, strerror(err),
			err);
		return -err;
	}

	if (!id)
		return 0;

	if (id == BNEP_SVC_PANU)
		script = panu;
	else if (id == BNEP_SVC_GN)
		script = gn;
	else
		script = nap;

	if (!script)
		return 0;

	argv[0] = script;
	argv[1] = devname;
	argv[2] = NULL;
	flags = G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH;
	if (!g_spawn_async(NULL, (char **) argv, NULL, flags, bnep_setup,
				(gpointer) devname, &pid, NULL)) {
		error("Unable to execute %s", argv[0]);
		return -1;
	}

	bnep = g_new0(struct bnep_data, 1);
	bnep->devname = g_strdup(devname);
	bnep->pid = pid;
	pids = g_slist_append(pids, bnep);
	g_child_watch_add(pid, script_exited, bnep);

	return pid;
}

int bnep_if_down(const char *devname)
{
	int sd, err;
	struct ifreq ifr;
	GSList *l;

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, devname);

	ifr.ifr_flags &= ~IFF_UP;

	if ((ioctl(sd, SIOCSIFFLAGS, (caddr_t) &ifr)) < 0) {
		err = errno;
		error("Could not bring down %d. %s(%d)", devname, strerror(err),
			err);
		return -err;
	}

	for(l = pids; l; l = g_slist_next(l)) {
		struct bnep_data *bnep = l->data;

		if (strcmp(devname, bnep->devname) == 0) {
			if (kill(bnep->pid, SIGTERM) < 0)
				error("kill(%d, SIGTERM): %s (%d)", bnep->pid,
					strerror(errno), errno);
			break;
		}
	}

	return 0;
}

int read_remote_name(bdaddr_t *src, bdaddr_t *dst, char *buf, size_t size)
{
	char filename[PATH_MAX + 1], addr[18], *str;

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "names");

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	snprintf(buf, size, "%s", str);
	free(str);

	return 0;
}
