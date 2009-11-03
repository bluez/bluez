/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009  Intel Corporation
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <wait.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "logging.h"
#include "mimetype.h"
#include "obex.h"
#include "service.h"

#define EOL_CHARS "\n"

#define FL_VERSION "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" EOL_CHARS

#define FL_TYPE "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">" EOL_CHARS

#define FL_TYPE_PCSUITE "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\"" EOL_CHARS \
                        "  [ <!ATTLIST folder mem-type CDATA #IMPLIED> ]>" EOL_CHARS

#define FL_BODY_BEGIN "<folder-listing version=\"1.0\">" EOL_CHARS

#define FL_BODY_END "</folder-listing>" EOL_CHARS

#define FL_PARENT_FOLDER_ELEMENT "<parent-folder/>" EOL_CHARS

#define FL_FILE_ELEMENT "<file name=\"%s\" size=\"%lu\"" \
			" %s accessed=\"%s\" " \
			"modified=\"%s\" created=\"%s\"/>" EOL_CHARS

#define FL_FOLDER_ELEMENT "<folder name=\"%s\" %s accessed=\"%s\" " \
			"modified=\"%s\" created=\"%s\"/>" EOL_CHARS

#define FL_FOLDER_ELEMENT_PCSUITE "<folder name=\"%s\" %s accessed=\"%s\"" \
			" modified=\"%s\" mem-type=\"DEV\"" \
			" created=\"%s\"/>" EOL_CHARS

static const guint8 FTP_TARGET[TARGET_SIZE] = {
			0xF9, 0xEC, 0x7B, 0xC4,  0x95, 0x3C, 0x11, 0xD2,
			0x98, 0x4E, 0x52, 0x54,  0x00, 0xDC, 0x9E, 0x09  };

static gchar *file_stat_line(gchar *filename, struct stat *fstat,
				struct stat *dstat, gboolean root,
				gboolean pcsuite)
{
	gchar perm[51], atime[18], ctime[18], mtime[18];
	gchar *escaped, *ret = NULL;

	snprintf(perm, 50, "user-perm=\"%s%s%s\" group-perm=\"%s%s%s\" "
			"other-perm=\"%s%s%s\"",
			(fstat->st_mode & S_IRUSR ? "R" : ""),
			(fstat->st_mode & S_IWUSR ? "W" : ""),
			(dstat->st_mode & S_IWUSR ? "D" : ""),
			(fstat->st_mode & S_IRGRP ? "R" : ""),
			(fstat->st_mode & S_IWGRP ? "W" : ""),
			(dstat->st_mode & S_IWGRP ? "D" : ""),
			(fstat->st_mode & S_IROTH ? "R" : ""),
			(fstat->st_mode & S_IWOTH ? "W" : ""),
			(dstat->st_mode & S_IWOTH ? "D" : ""));

	strftime(atime, 17, "%Y%m%dT%H%M%SZ", gmtime(&fstat->st_atime));
	strftime(ctime, 17, "%Y%m%dT%H%M%SZ", gmtime(&fstat->st_ctime));
	strftime(mtime, 17, "%Y%m%dT%H%M%SZ", gmtime(&fstat->st_mtime));

	escaped = g_markup_escape_text(filename, -1);

	if (S_ISDIR(fstat->st_mode)) {
		if (pcsuite && root && g_str_equal(filename, "Data"))
			ret = g_strdup_printf(FL_FOLDER_ELEMENT_PCSUITE,
						escaped, perm, atime,
						mtime, ctime);
		else
			ret = g_strdup_printf(FL_FOLDER_ELEMENT, escaped, perm,
						atime, mtime, ctime);
	} else if (S_ISREG(fstat->st_mode))
		ret = g_strdup_printf(FL_FILE_ELEMENT, escaped, fstat->st_size,
					perm, atime, mtime, ctime);

	g_free(escaped);

	return ret;
}

static gpointer filesystem_open(const char *name, int oflag, mode_t mode,
				size_t *size)
{
	struct stat stats;
	struct statvfs buf;
	int fd = open(name, oflag, mode);

	if (fd < 0)
		return NULL;

	if (fstat(fd, &stats) < 0) {
		error("fstat(fd=%d): %s (%d)", fd, strerror(errno), errno);
		goto failed;
	}

	if (oflag == O_RDONLY) {
		*size =  stats.st_size;
		return GINT_TO_POINTER(fd);
	}

	if (fstatvfs(fd, &buf) < 0)
		goto failed;

	if (buf.f_bsize * buf.f_bavail < *size) {
		debug("Not enough free space on disk");
		errno = -ENOSPC;
		goto failed;
	}

	return GINT_TO_POINTER(fd);

failed:
	close(fd);
	return NULL;
}

static int filesystem_close(gpointer object)
{
	return close(GPOINTER_TO_INT(object));
}

static ssize_t filesystem_read(gpointer object, void *buf, size_t count)
{
	return read(GPOINTER_TO_INT(object), buf, count);
}

static ssize_t filesystem_write(gpointer object, const void *buf, size_t count)
{
	return write(GPOINTER_TO_INT(object), buf, count);
}

static gpointer capability_open(const char *name, int oflag, mode_t mode,
				size_t *size)
{
	GError *gerr = NULL;
	gchar *buf;
	gint exit;
	gboolean ret;

	if (oflag != O_RDONLY)
		goto fail;

	if (name[0] != '!') {
		ret = g_file_get_contents(name, &buf, NULL, &gerr);
		if (ret == FALSE) {
			error("%s", gerr->message);
			goto fail;
		}

		goto done;
	}

	ret = g_spawn_command_line_sync(name + 1, &buf, NULL, &exit, &gerr);
	if (ret == FALSE) {
		error("%s", gerr->message);
		goto fail;
	}

	if (WEXITSTATUS(exit) != EXIT_SUCCESS) {
		error("%s failed", name + 1);
		g_free(buf);
		goto fail;
	}

done:
	if (size)
		*size = strlen(buf);

	return buf;

fail:
	if (gerr)
		g_error_free(gerr);

	errno = EPERM;
	return NULL;
}

static int capability_close(gpointer object)
{
	g_free(object);
	return 0;
}

static ssize_t capability_read(gpointer object, void *buf, size_t count)
{
	strncpy(buf, object, count);
	return strlen(buf);
}

static gpointer folder_open(const char *name, int oflag, mode_t mode,
				size_t *size)
{
	DIR *dir = opendir(name);

	if (dir == NULL)
		return NULL;

	if (size)
		*size = 1;

	return dir;
}

static int folder_close(gpointer object)
{
	DIR *dir = (DIR *) object;

	return closedir(dir);
}

static ssize_t folder_read(gpointer object, void *buf, size_t count)
{
	struct obex_session *os;
	struct stat fstat, dstat;
	struct dirent *ep;
	DIR *dp = (DIR *) object;
	GString *listing;
	gboolean root, pcsuite;
	gint err, len;

	os = obex_get_session(object);
	if (os->finished)
		return 0;

	pcsuite = os->service->service & OBEX_PCSUITE ? TRUE : FALSE;

	listing = g_string_new(FL_VERSION);
	listing = g_string_append(listing, pcsuite ? FL_TYPE_PCSUITE : FL_TYPE);

	listing = g_string_append(listing, FL_BODY_BEGIN);

	root = g_str_equal(os->current_folder, os->server->folder);

	if (root && os->server->symlinks)
		err = stat(os->current_folder, &dstat);
	else {
		listing = g_string_append(listing, FL_PARENT_FOLDER_ELEMENT);
		err = lstat(os->current_folder, &dstat);
	}

	if (err < 0) {
		err = -errno;
		error("%s: %s(%d)", root ? "stat" : "lstat",
				strerror(errno), errno);
		goto failed;
	}

	while ((ep = readdir(dp))) {
		gchar *name;
		gchar *fullname;
		gchar *line;

		if (ep->d_name[0] == '.')
			continue;

		name = g_filename_to_utf8(ep->d_name, -1, NULL, NULL, NULL);
		if (name == NULL) {
			error("g_filename_to_utf8: invalid filename");
			continue;
		}

		fullname = g_build_filename(os->current_folder, ep->d_name, NULL);

		if (root && os->server->symlinks)
			err = stat(fullname, &fstat);
		else
			err = lstat(fullname, &fstat);

		if (err < 0) {
			debug("%s: %s(%d)", root ? "stat" : "lstat",
					strerror(errno), errno);
			g_free(name);
			g_free(fullname);
			continue;
		}

		g_free(fullname);

		line = file_stat_line(name, &fstat, &dstat, root, pcsuite);
		if (line == NULL) {
			g_free(name);
			continue;
		}

		g_free(name);

		listing = g_string_append(listing, line);
		g_free(line);
	}

	listing = g_string_append(listing, FL_BODY_END);
	len = listing->len;
	memcpy(buf, listing->str, len);
	g_string_free(listing, TRUE);
	os->finished = TRUE;

	return len;

failed:
	g_string_free(listing, TRUE);
	return err;
}

struct obex_mime_type_driver file = {
	.open = filesystem_open,
	.close = filesystem_close,
	.read = filesystem_read,
	.write = filesystem_write,
	.remove = remove,
};

struct obex_mime_type_driver capability = {
	.target = FTP_TARGET,
	.mimetype = "x-obex/capability",
	.open = capability_open,
	.close = capability_close,
	.read = capability_read,
};

struct obex_mime_type_driver folder = {
	.target = FTP_TARGET,
	.mimetype = "x-obex/folder-listing",
	.open = folder_open,
	.close = folder_close,
	.read = folder_read,
};

static int filesystem_init(void)
{
	int err;

	err = obex_mime_type_driver_register(&folder);
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&capability);
	if (err < 0)
		return err;

	return obex_mime_type_driver_register(&file);
}

static void filesystem_exit(void)
{
	obex_mime_type_driver_unregister(&folder);
	obex_mime_type_driver_unregister(&capability);
	obex_mime_type_driver_unregister(&file);
}

OBEX_PLUGIN_DEFINE(filesystem, filesystem_init, filesystem_exit)
