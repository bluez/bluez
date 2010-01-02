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

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include <glib.h>

#include "logging.h"
#include "common.h"

static int ctl;
static GSList *pids;

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
	char *script;
	int pid;
};

static gint find_devname(gconstpointer a, gconstpointer b)
{
	struct bnep_data *data = (struct bnep_data *) a;
	const char *devname = b;

	return strcmp(data->devname, devname);
}

static void script_exited(GPid pid, gint status, gpointer data)
{
	if (WIFEXITED(status))
		debug("%d exited with status %d", pid, WEXITSTATUS(status));
	else
		debug("%d was killed by signal %d", pid, WTERMSIG(status));

	g_spawn_close_pid(pid);
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

	memset(&req, 0, sizeof(req));
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
	unsigned int i;
	int err;

	memset(&req, 0, sizeof(req));
	req.cnum = 7;
	req.ci   = ci;
	if (ioctl(ctl, BNEPGETCONNLIST, &req)) {
		err = errno;
		error("Failed to get connection list: %s (%d)",
						strerror(err), err);
		return -err;
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

static int bnep_exec(const char **argv)
{
	int pid;
	GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH;

	if (!g_spawn_async(NULL, (char **) argv, NULL, flags, bnep_setup, NULL,
				&pid, NULL)) {
		error("Unable to execute %s %s", argv[0], argv[1]);
		return -EINVAL;
	}

	return pid;
}

int bnep_if_up(const char *devname, uint16_t id)
{
	int sd, err;
	struct ifreq ifr;
	const char *argv[5];
	struct bnep_data *bnep = NULL;
	GSList *l;

	/* Check if a script is running */
	l = g_slist_find_custom(pids, devname, find_devname);
	if (l) {
		bnep = l->data;

		if (bnep->script && !strcmp(bnep->script, "avahi-autoipd")) {
			argv[0] = bnep->script;
			argv[1] = devname;
			argv[2] = "--refresh";
			argv[3] = NULL;

			bnep->pid = bnep_exec(argv);
		}
	}

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, IF_NAMESIZE - 1);

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_MULTICAST;

	if ((ioctl(sd, SIOCSIFFLAGS, (caddr_t) &ifr)) < 0) {
		err = errno;
		error("Could not bring up %s. %s(%d)", devname, strerror(err),
			err);
		return -err;
	}

	if (bnep)
		return bnep->pid;

	bnep = g_new0(struct bnep_data, 1);
	bnep->devname = g_strdup(devname);

	if (!id)
		goto done;

	if (id == BNEP_SVC_PANU)
		bnep->script = g_strdup(panu);
	else if (id == BNEP_SVC_GN)
		bnep->script = g_strdup(gn);
	else
		bnep->script = g_strdup(nap);

	if (!bnep->script)
		goto done;

	argv[0] = bnep->script;
	argv[1] = devname;

	if (!strcmp(bnep->script, "avahi-autoipd")) {
		argv[2] = "--no-drop-root";
		argv[3] = "--no-chroot";
		argv[4] = NULL;
	} else
		argv[2] = NULL;

	bnep->pid = bnep_exec(argv);
	g_child_watch_add(bnep->pid, script_exited, bnep);

done:
	pids = g_slist_append(pids, bnep);

	return bnep->pid;
}

int bnep_if_down(const char *devname)
{
	int sd, err, pid;
	struct ifreq ifr;
	struct bnep_data *bnep;
	GSList *l;
	GSpawnFlags flags;
	const char *argv[4];

	l = g_slist_find_custom(pids, devname, find_devname);
	if (!l)
		return 0;

	bnep = l->data;

	if (!bnep->pid)
		goto done;

	if (bnep->script && !strcmp(bnep->script, "avahi-autoipd")) {
		argv[0] = bnep->script;
		argv[1] = devname;
		argv[2] = "--kill";
		argv[3] = NULL;

		flags = G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH;
		g_spawn_async(NULL, (char **) argv, NULL, flags, bnep_setup,
				(gpointer) devname, &pid, NULL);

		goto done;
	}

	/* Kill script */
	err = kill(bnep->pid, SIGTERM);
	if (err < 0)
		error("kill(%d, SIGTERM): %s (%d)", bnep->pid,
			strerror(errno), errno);

done:
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, IF_NAMESIZE - 1);

	ifr.ifr_flags &= ~IFF_UP;

	/* Bring down the interface */
	ioctl(sd, SIOCSIFFLAGS, (caddr_t) &ifr);

	pids = g_slist_remove(pids, bnep);

	if (bnep->devname)
		g_free(bnep->devname);

	if (bnep->script)
		g_free(bnep->script);

	g_free(bnep);

	return 0;
}
