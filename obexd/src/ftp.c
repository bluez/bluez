/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
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

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"

#define LST_TYPE "x-obex/folder-listing"
#define CAP_TYPE "x-obex/capability"

static gint folder_listing(struct obex_session *os, size_t *size)
{
	return os_prepare_get(os, os->current_folder, size);
}

static gint get_capability(struct obex_session *os, size_t *size)
{
	return os_prepare_get(os, os->server->capability, size);
}

static gint get_by_type(struct obex_session *os, gchar *type, size_t *size)
{
	if (type == NULL)
		return -ENOENT;

	if (g_str_equal(type, CAP_TYPE))
		return get_capability(os, size);

	if (g_str_equal(type, LST_TYPE))
		return folder_listing(os, size);

	return FALSE;
}

static gint ftp_prepare_get(struct obex_session *os, gchar *file,
				size_t *size)
{
	gboolean root;

	root = g_str_equal(os->server->folder, os->current_folder);

	if (!root || !os->server->symlinks) {
		struct stat dstat;
		gint err;

		if (lstat(file, &dstat) < 0) {
			err = -errno;
			debug("lstat: %s(%d)", strerror(errno), errno);
			return err;
		}

		if (S_ISLNK(dstat.st_mode))
			return -EPERM;
	}

	return os_prepare_get(os, file, size);
}

void ftp_get(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hv;
	struct obex_session *os;
	size_t size;
	gint err;
	gchar *path;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_folder == NULL) {
		err = -ENOENT;
		goto fail;
	}

	err = get_by_type(os, os->type, &size);
	if (err < 0) {
		if (!os->name)
			goto fail;

		path = g_build_filename(os->current_folder, os->name, NULL);

		err = ftp_prepare_get(os, path, &size);

		g_free(path);

		if (err < 0)
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
	switch (err) {
	case -ENOENT:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
		break;
	default:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	}
}

static gint ftp_delete(struct obex_session *os)
{
	gchar *path;
	int ret = 0;

	if (!(os->current_folder && os->name))
		return -EINVAL;

	path = g_build_filename(os->current_folder, os->name, NULL);

	if (os->driver->remove(path) < 0)
		ret = -errno;

	g_free(path);

	return ret;
}

gint ftp_chkput(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return -EINVAL;

	if (os->size == OBJECT_SIZE_DELETE)
		return 0;

	return os_prepare_put(os);
}

void ftp_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	int ret = 0;

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

	if (os->size == OBJECT_SIZE_DELETE)
		ret = ftp_delete(os);

	switch (ret) {
	case 0:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		break;
	case -ENOENT:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
		break;
	case -ENOTEMPTY:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_PRECONDITION_FAILED,
					OBEX_RSP_PRECONDITION_FAILED);
		break;
	default:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		break;
	}
}

void ftp_setpath(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	guint8 *nonhdr;
	gchar *fullname;
	struct stat dstat;
	gboolean root;
	int err;

	os = OBEX_GetUserData(obex);

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag and constants not found!");
		return;
	}

	root = g_str_equal(os->server->folder, os->current_folder);

	/* Check flag "Backup" */
	if ((nonhdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (root) {
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

	if (root && os->server->symlinks)
		err = stat(fullname, &dstat);
	else
		err = lstat(fullname, &dstat);

	if (err < 0) {
		int err = errno;
		debug("%s: %s(%d)", root ? "stat" : "lstat",
				strerror(err), err);
		if (err == ENOENT)
			goto not_found;

		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		goto done;
	}

	if (S_ISDIR(dstat.st_mode) && (dstat.st_mode & S_IRUSR) &&
						(dstat.st_mode & S_IXUSR)) {
		g_free(os->current_folder);
		os->current_folder = g_strdup(fullname);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	goto done;

not_found:
	if (nonhdr[0] != 0) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
		goto done;
	}

	if (mkdir(fullname, 0755) <  0) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		goto done;
	}

	g_free(os->current_folder);
	os->current_folder = g_strdup(fullname);
	OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);

done:
	g_free(fullname);
}
