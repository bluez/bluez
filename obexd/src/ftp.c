/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "dbus.h"

#define LST_TYPE "x-obex/folder-listing"
#define CAP_TYPE "x-obex/capability"

#define CAP_FILE CONFIGDIR "/capability.xml"

#define EOL_CHARS "\n"

#define FL_VERSION "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" EOL_CHARS

#define FL_TYPE "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">" EOL_CHARS

#define FL_BODY_BEGIN "<folder-listing version=\"1.0\">" EOL_CHARS

#define FL_BODY_END "</folder-listing>" EOL_CHARS

#define FL_PARENT_FOLDER_ELEMENT "<parent-folder/>" EOL_CHARS

#define FL_FILE_ELEMENT "<file name=\"%s\" size=\"%lu\"" \
			" %s accessed=\"%s\" " \
			"modified=\"%s\" created=\"%s\"/>" EOL_CHARS

#define FL_FOLDER_ELEMENT "<folder name=\"%s\" %s accessed=\"%s\" " \
			"modified=\"%s\" created=\"%s\"/>" EOL_CHARS


static gchar *file_stat_line(gchar *filename, struct stat *fstat,
				struct stat *dstat)
{
	gchar perm[50], atime[17], ctime[17], mtime[17];

	snprintf(perm, 49, "user-perm=\"%s%s%s\" group-perm=\"%s%s%s\" "
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

	strftime(atime, 16, "%Y%m%dT%H%M%S", gmtime(&fstat->st_atime));
	strftime(ctime, 16, "%Y%m%dT%H%M%S", gmtime(&fstat->st_ctime));
	strftime(mtime, 16, "%Y%m%dT%H%M%S", gmtime(&fstat->st_mtime));

	if (S_ISDIR(fstat->st_mode))
		return g_strdup_printf(FL_FOLDER_ELEMENT, filename,
					perm, atime, mtime, ctime);

	return g_strdup_printf(FL_FILE_ELEMENT, filename, fstat->st_size,
				perm, atime, mtime, ctime);
}

static gboolean folder_listing(struct obex_session *os, guint32 *size)
{
	struct stat fstat, dstat;
	struct dirent *ep;
	DIR *dp;
	GString *listing;

	listing = g_string_new(FL_VERSION);
	listing = g_string_append(listing, FL_TYPE);
	listing = g_string_append(listing, FL_BODY_BEGIN);

	if (strcmp(os->current_folder,os->server->folder))
		listing = g_string_append(listing, FL_PARENT_FOLDER_ELEMENT);

	if (lstat(os->current_folder, &dstat) < 0) {
		error("lstat: %s(%d)", strerror(errno), errno);
		return FALSE;
	}

	dp = opendir(os->current_folder);
	while (dp && (ep = readdir(dp))) {
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

		if (lstat(fullname, &fstat) < 0) {
			debug("lstat: %s(%d)", strerror(errno), errno);
			g_free(name);
			g_free(fullname);
			continue;
		}
		g_free(fullname);

		line = file_stat_line(name, &fstat, &dstat);
		if (line == NULL) {
			g_free(name);
			continue;
		}
		g_free(name);

		listing = g_string_append(listing, line);
		g_free(line);
	}
	closedir(dp);

	listing = g_string_append(listing, FL_BODY_END);
	*size = listing->len + 1;
	os->buf = (guint8*) g_string_free(listing, FALSE);

	return TRUE;
}

static gboolean get_by_type(struct obex_session *os, gchar *type, guint32 *size)
{
	if (type == NULL)
		return FALSE;

	if (g_str_equal(type, CAP_TYPE))
		return os_prepare_get(os, CAP_FILE, size);

	if (g_str_equal(type, LST_TYPE))
		return folder_listing(os, size);

	return FALSE;
}

void ftp_get(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hv;
	struct obex_session *os;
	guint32 size;
	gboolean ret;
	gchar *path;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_folder == NULL)
		goto fail;

	if (!get_by_type(os, os->type, &size)) {
		if (!os->name)
			goto fail;

		path = g_build_filename(os->current_folder,
					os->name, NULL);

		ret = os_prepare_get(os, path, &size);

		g_free(path);

		if (!ret)
			goto fail;
	}

	hv.bq4 = size;
	os->size = size;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_LENGTH, hv, 4, 0);

	/* Add body header */
	hv.bs = NULL;
	if (size == 0)
		OBEX_ObjectAddHeader (obex, obj, OBEX_HDR_BODY,
				hv, 0, OBEX_FL_FIT_ONE_PACKET);
	else
		OBEX_ObjectAddHeader (obex, obj, OBEX_HDR_BODY,
				hv, 0, OBEX_FL_STREAM_START);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
			OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

	return;
}

gint ftp_chkput(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return -EINVAL;

	if (!os->size)
		return -EINVAL;

	return os_prepare_put(os);
}

void ftp_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_folder == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	if (os->name == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
		return;
	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

void ftp_setpath(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	guint8 *nonhdr;
	gchar *fullname;

	os = OBEX_GetUserData(obex);

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag and constants not found!");
		return;
	}

	/* Check flag "Backup" */
	if ((nonhdr[0] & 0x01) == 0x01) {

		debug("Set to parent path");

		if (strcmp(os->server->folder, os->current_folder) == 0) {
			OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			return;
		}

		fullname = g_path_get_dirname(os->current_folder);
		g_free(os->current_folder);
		os->current_folder = g_strdup(fullname);
		g_free(fullname);

		debug("Set to parent path: %s", os->current_folder);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		return;
	}

	if (!os->name) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		debug("Set path failed: name missing!");
		return;
	}

	if (strlen(os->name) == 0) {
		debug("Set to root");
		g_free(os->current_folder);
		os->current_folder = g_strdup(os->server->folder);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		return;
	}

	/* Check and set to name path */
	if (strstr(os->name, "/") || strcmp(os->name, "..") == 0) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		error("Set path failed: name incorrect!");
		return;
	}

	fullname = g_build_filename(os->current_folder, os->name, NULL);

	debug("Fullname: %s", fullname);

	if (g_file_test(fullname, G_FILE_TEST_IS_DIR)) {
		g_free(os->current_folder);
		os->current_folder = g_strdup(fullname);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!g_file_test(fullname, G_FILE_TEST_EXISTS) && nonhdr[0] == 0 &&
				mkdir(fullname, 0755) >=  0) {
		g_free(os->current_folder);
		os->current_folder = g_strdup(fullname);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;

	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
done:
	g_free(fullname);
}
