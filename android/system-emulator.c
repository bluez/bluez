/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <libgen.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "monitor/mainloop.h"

static char exec_dir[PATH_MAX + 1];

static pid_t daemon_pid = -1;

static void ctl_start(void)
{
	char *prg_argv[1] = { NULL };
	char prg_name[PATH_MAX + 1];
	pid_t pid;

	snprintf(prg_name, sizeof(prg_name), "%s/%s", exec_dir, "bluetoothd");

	printf("Starting %s\n", prg_name);

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		return;
	}

	if (pid == 0) {
		execv(prg_name, prg_argv);
		exit(0);
	}

	daemon_pid = pid;
}

static void system_socket_callback(int fd, uint32_t events, void *user_data)
{
	char buf[4096];
	ssize_t len;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return;

	printf("Received %s\n", buf);

	if (strcmp(buf, "ctl.start=bluetoothd"))
		return;

	ctl_start();
}

int main(int argc, char *argv[])
{
	static const char SYSTEM_SOCKET_PATH[] = "\0android_system";

	struct sockaddr_un addr;
	int fd;

	mainloop_init();

	printf("Android system emulator ver %s\n", VERSION);

	snprintf(exec_dir, sizeof(exec_dir), "%s", dirname(argv[0]));

	fd = socket(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("Failed to create system socket");
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SYSTEM_SOCKET_PATH, sizeof(SYSTEM_SOCKET_PATH));

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind system socket");
		close(fd);
		return EXIT_FAILURE;
	}

	mainloop_add_fd(fd, EPOLLIN, system_socket_callback, NULL, NULL);

	return mainloop_run();
}
