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
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "dund.h"
#include "lib.h"

#define PROC_BASE  "/proc"

static int for_each_port(int (*func)(struct rfcomm_dev_info *, unsigned long), unsigned long arg)
{
	struct rfcomm_dev_list_req *dl;
	struct rfcomm_dev_info *di;
	long r = 0;
	int  sk, i;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
	if (sk < 0 ) {
		perror("Can't open RFCOMM control socket");
		exit(1);
	}

	dl = malloc(sizeof(*dl) + RFCOMM_MAX_DEV * sizeof(*di));
	if (!dl) {
		perror("Can't allocate request memory");
		close(sk);
		exit(1);
	}

	dl->dev_num = RFCOMM_MAX_DEV;
	di = dl->dev_info;

	if (ioctl(sk, RFCOMMGETDEVLIST, (void *) dl) < 0) {
		perror("Can't get device list");
		exit(1);
	}

	for (i = 0; i < dl->dev_num; i++) {
		r = func(di + i, arg);
		if (r) break;
	}

	close(sk);
	free(dl);
	return r;
}

static int uses_rfcomm(char *path, char *dev)
{
	struct dirent *de;
	DIR   *dir;

	dir = opendir(path);
	if (!dir)
		return 0;

	if (chdir(path) < 0)
		return 0;

	while ((de = readdir(dir)) != NULL) {
		char link[PATH_MAX + 1];
		int  len = readlink(de->d_name, link, sizeof(link));
		if (len > 0) {
			link[len] = 0;
			if (strstr(link, dev)) {
				closedir(dir);
				return 1;
			}
		}
	}

	closedir(dir);

	return 0;
}

static int find_pppd(int id, pid_t *pid)
{
	struct dirent *de;
	char  path[PATH_MAX + 1];
	char  dev[10];
	int   empty = 1;
	DIR   *dir;

	dir = opendir(PROC_BASE);
	if (!dir) {
		perror(PROC_BASE);
		return -1;
	}

	sprintf(dev, "rfcomm%d", id);

	*pid = 0;
	while ((de = readdir(dir)) != NULL) {
		empty = 0;
		if (isdigit(de->d_name[0])) {
			sprintf(path, "%s/%s/fd", PROC_BASE, de->d_name);
			if (uses_rfcomm(path, dev)) {
				*pid = atoi(de->d_name);
				break;
			}
		}
	}
	closedir(dir);

	if (empty)
		fprintf(stderr, "%s is empty (not mounted ?)\n", PROC_BASE);

	return *pid != 0;
}

static int dun_exec(char *tty, char *prog, char **args)
{
	int pid = fork();
	int fd;

	switch (pid) {
	case -1:
		return -1;

	case 0:
		break;

	default:
		return pid;
	}

	setsid();

	/* Close all FDs */
	for (fd = 3; fd < 20; fd++)
		close(fd);

	execvp(prog, args);

	syslog(LOG_ERR, "Error while executing %s", prog);

	exit(1);
}

static int dun_create_tty(int sk, char *tty, int size)
{
	struct sockaddr_rc sa;
	struct stat st;
	socklen_t alen;
	int id, try = 30;

	struct rfcomm_dev_req req = {
		flags:   (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP),
		dev_id:  -1
	};

	alen = sizeof(sa);
	if (getpeername(sk, (struct sockaddr *) &sa, &alen) < 0)
		return -1;
	bacpy(&req.dst, &sa.rc_bdaddr);

	alen = sizeof(sa);
	if (getsockname(sk, (struct sockaddr *) &sa, &alen) < 0)
		return -1;
	bacpy(&req.src, &sa.rc_bdaddr);
	req.channel = sa.rc_channel;

	id = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (id < 0)
		return id;

	snprintf(tty, size, "/dev/rfcomm%d", id);
	while (stat(tty, &st) < 0) {
		snprintf(tty, size, "/dev/bluetooth/rfcomm/%d", id);
		if (stat(tty, &st) < 0) {
			snprintf(tty, size, "/dev/rfcomm%d", id);
			if (try--) {
				usleep(100 * 1000);
				continue;
			}

			memset(&req, 0, sizeof(req));
			req.dev_id = id;
			ioctl(sk, RFCOMMRELEASEDEV, &req);

			return -1;
		}
	}

	return id;
}

int dun_init(void)
{
	return 0;
}

int dun_cleanup(void)
{
	return 0;
}

static int show_conn(struct rfcomm_dev_info *di, unsigned long arg)
{
	pid_t pid;

	if (di->state == BT_CONNECTED &&
		(di->flags & (1<<RFCOMM_REUSE_DLC)) &&
		(di->flags & (1<<RFCOMM_TTY_ATTACHED)) &&
		(di->flags & (1<<RFCOMM_RELEASE_ONHUP))) {

		if (find_pppd(di->id, &pid)) {
			char dst[18];
			ba2str(&di->dst, dst);

			printf("rfcomm%d: %s channel %d pppd pid %d\n",
					di->id, dst, di->channel, pid);
		}
	}
	return 0;
}

static int kill_conn(struct rfcomm_dev_info *di, unsigned long arg)
{
	bdaddr_t *dst = (bdaddr_t *) arg;
	pid_t pid;

	if (di->state == BT_CONNECTED &&
		(di->flags & (1<<RFCOMM_REUSE_DLC)) &&
		(di->flags & (1<<RFCOMM_TTY_ATTACHED)) &&
		(di->flags & (1<<RFCOMM_RELEASE_ONHUP))) {

		if (dst && bacmp(&di->dst, dst))
			return 0;

		if (find_pppd(di->id, &pid)) {
			if (kill(pid, SIGINT) < 0)
				perror("Kill");

			if (!dst)
				return 0;
			return 1;
		}
	}
	return 0;
}

int dun_show_connections(void)
{
	for_each_port(show_conn, 0);
	return 0;
}

int dun_kill_connection(uint8_t *dst)
{
	for_each_port(kill_conn, (unsigned long) dst);
	return 0;
}

int dun_kill_all_connections(void)
{
	for_each_port(kill_conn, 0);
	return 0;
}

int dun_open_connection(int sk, char *pppd, char **args, int wait)
{
	char tty[100];
	int  pid;

	if (dun_create_tty(sk, tty, sizeof(tty) - 1) < 0) {
		syslog(LOG_ERR, "RFCOMM TTY creation failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	args[0] = "pppd";
	args[1] = tty;
	args[2] = "nodetach";

	pid = dun_exec(tty, pppd, args);
	if (pid < 0) {
		syslog(LOG_ERR, "Exec failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	if (wait) {
		int status;
		waitpid(pid, &status, 0);
		/* FIXME: Check for waitpid errors */
	}

	return 0;
}
