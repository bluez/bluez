/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <glib.h>

#include "logging.h"
#include "process.h"

static void child_exit(GPid pid, gint status, gpointer data)
{
	debug("Child with PID %d exits with status %d", pid, status);

	debug("Exit status %d", WEXITSTATUS(status));
}

int create_reader(uid_t uid, const char *pathname,
					GIOFunc func, gpointer user_data)
{
	pid_t pid;
	unsigned char buf[512];
	int fd, pfd[2], len, written;

	if (pipe(pfd) < 0) {
		error("Failed to create new pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		error("Failed to fork new process");
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (pid > 0) {
		GIOChannel *io;

		g_child_watch_add(pid, child_exit, NULL);

		close(pfd[1]);

		io = g_io_channel_unix_new(pfd[0]);
		g_io_channel_set_close_on_unref(io, TRUE);

		g_io_add_watch(io, G_IO_IN | G_IO_ERR | G_IO_HUP, func,
				user_data);

		g_io_channel_unref(io);

		return 0;
	}

	/* Child process */

	close(pfd[0]);

	if (setuid(uid) < 0) {
		error("Failed to switch to UID %d", uid);
		close(pfd[1]);
		exit(EXIT_FAILURE);
	}

	fd = open(pathname, O_RDONLY);
	if (fd < 0) {
		error("Failed to open file %s: %s",
					pathname, strerror(errno));
		close(pfd[1]);
		exit(EXIT_FAILURE);
	}

	while (1) {
		len = read(fd, buf, sizeof(buf));
		if (len <= 0) {
			debug("Reading failed");
			break;
		}

		written = write(pfd[1], buf, len);
		if (written < len) {
			debug("Writing failed");
			break;
		}
	}

	debug("Reader finished");

	close(fd);

	close(pfd[1]);

	exit(EXIT_SUCCESS);
}
