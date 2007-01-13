/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <unistd.h>
#include <string.h>
#include <sys/inotify.h>

#include "glib-ectomy.h"
#include "logging.h"
#include "notify.h"

static GIOChannel *io = NULL;

static int fd = -1;
static int wd = -1;

static gboolean io_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[129];
	struct inotify_event *evt = (struct inotify_event *) buf;
	int len;

	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	len = read(fd, buf, sizeof(buf) - 1);
	if (len < sizeof(struct inotify_event))
		return TRUE;

	if (evt->mask & (IN_CREATE | IN_MOVED_TO))
		debug("File %s/%s created", CONFIGDIR, evt->name);

	if (evt->mask & (IN_DELETE | IN_MOVED_FROM))
		debug("File %s/%s deleted", CONFIGDIR, evt->name);

	if (evt->mask & IN_MODIFY)
		debug("File %s/%s modified", CONFIGDIR, evt->name);

	return TRUE;
}

void notify_init(void)
{
	fd = inotify_init();
	if (fd < 0) {
		error("Creation of inotify context failed");
		return;
	}

	io = g_io_channel_unix_new(fd);
	if (!io) {
		error("Creation of inotify channel failed");
		return;
	}

	g_io_add_watch(io, G_IO_IN, io_event, NULL);

	wd = inotify_add_watch(fd, CONFIGDIR,
		IN_ONLYDIR | IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVE);
	if (wd < 0)
		error("Creation of watch for %s failed", CONFIGDIR);
}

void notify_close(void)
{
	if (wd != -1) {
		inotify_rm_watch(fd, wd);
		wd = -1;
	}

	if (io) {
		g_io_channel_unref(io);
		io = NULL;
	}

	if (fd != -1) {
		close(fd);
		fd = -1;
	}
}
