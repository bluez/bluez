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

#include "plugin.h"
#include "logging.h"
#include "obex.h"
#include "dbus.h"
#include "mimetype.h"
#include "service.h"

#define LST_TYPE "x-obex/folder-listing"
#define CAP_TYPE "x-obex/capability"

#define FTP_CHANNEL    10
#define FTP_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>        \
<record>                                                                       \
  <attribute id=\"0x0001\">                                                    \
    <sequence>                                                                 \
      <uuid value=\"0x1106\"/>                                                 \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0004\">                                                    \
    <sequence>                                                                 \
      <sequence>                                                               \
        <uuid value=\"0x0100\"/>                                               \
      </sequence>                                                              \
      <sequence>                                                               \
        <uuid value=\"0x0003\"/>                                               \
        <uint8 value=\"%u\" name=\"channel\"/>                                 \
      </sequence>                                                              \
      <sequence>                                                               \
        <uuid value=\"0x0008\"/>                                               \
      </sequence>                                                              \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0009\">                                                    \
    <sequence>                                                                 \
      <sequence>                                                               \
        <uuid value=\"0x1106\"/>                                               \
        <uint16 value=\"0x0100\" name=\"version\"/>                            \
      </sequence>                                                              \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0100\">                                                    \
    <text value=\"%s\" name=\"name\"/>                                         \
  </attribute>                                                                 \
</record>"

#define PCSUITE_CHANNEL        24
#define PCSUITE_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>                                    \
<record>                                                                       \
  <attribute id=\"0x0001\">                                                    \
    <sequence>                                                                 \
      <uuid value=\"00005005-0000-1000-8000-0002ee000001\"/>                   \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0004\">                                                    \
    <sequence>                                                                 \
      <sequence>                                                               \
        <uuid value=\"0x0100\"/>                                               \
      </sequence>                                                              \
      <sequence>                                                               \
        <uuid value=\"0x0003\"/>                                               \
        <uint8 value=\"%u\" name=\"channel\"/>                                 \
      </sequence>                                                              \
      <sequence>                                                               \
        <uuid value=\"0x0008\"/>                                               \
      </sequence>                                                              \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0005\">                                                    \
    <sequence>                                                                 \
      <uuid value=\"0x1002\"/>                                                 \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0009\">                                                    \
    <sequence>                                                                 \
      <sequence>                                                               \
        <uuid value=\"00005005-0000-1000-8000-0002ee000001\"/>                         \
        <uint16 value=\"0x0100\" name=\"version\"/>                            \
      </sequence>                                                              \
    </sequence>                                                                        \
  </attribute>                                                                 \
                                                                               \
  <attribute id=\"0x0100\">                                                    \
    <text value=\"%s\" name=\"name\"/>                                         \
  </attribute>                                                                 \
</record>"

static const guint8 FTP_TARGET[TARGET_SIZE] = {
			0xF9, 0xEC, 0x7B, 0xC4,  0x95, 0x3C, 0x11, 0xD2,
			0x98, 0x4E, 0x52, 0x54,  0x00, 0xDC, 0x9E, 0x09  };

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

static void ftp_connect(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os = OBEX_GetUserData(obex);
	obex_headerdata_t hd;

	register_session(os->cid, os);
	emit_session_created(os->cid);

	/* Append received UUID in WHO header */
	hd.bs = FTP_TARGET;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_WHO, hd, sizeof(FTP_TARGET),
			OBEX_FL_FIT_ONE_PACKET);
	hd.bq4 = os->cid;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_CONNECTION, hd, 4,
			OBEX_FL_FIT_ONE_PACKET);

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void ftp_get(obex_t *obex, obex_object_t *obj)
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

static gint ftp_chkput(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return -EINVAL;

	if (!os->name)
		return -EINVAL;

	if (os->size == OBJECT_SIZE_DELETE)
		return 0;

	return os_prepare_put(os);
}

static void ftp_put(obex_t *obex, obex_object_t *obj)
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

static void ftp_setpath(obex_t *obex, obex_object_t *obj)
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

static void ftp_disconnect(obex_t *obex)
{
	struct obex_session *os = OBEX_GetUserData(obex);

	emit_session_removed(os->cid);
	unregister_session(os->cid);
}

struct obex_service_driver pcsuite = {
	.name = "Nokia OBEX PC Suite Services",
	.service = OBEX_PCSUITE,
	.channel = PCSUITE_CHANNEL,
	.record = PCSUITE_RECORD,
	.target = FTP_TARGET,
	.target_size = TARGET_SIZE,
	.connect = ftp_connect,
	.get = ftp_get,
	.put = ftp_put,
	.chkput = ftp_chkput,
	.setpath = ftp_setpath,
	.disconnect = ftp_disconnect
};

struct obex_service_driver ftp = {
	.name = "File Transfer server",
	.service = OBEX_FTP,
	.channel = FTP_CHANNEL,
	.record = FTP_RECORD,
	.target = FTP_TARGET,
	.target_size = TARGET_SIZE,
	.connect = ftp_connect,
	.get = ftp_get,
	.put = ftp_put,
	.chkput = ftp_chkput,
	.setpath = ftp_setpath,
	.disconnect = ftp_disconnect
};

static int ftp_init(void)
{
	int err;

	err = obex_service_driver_register(&ftp);
	if (err < 0)
		return err;

	return obex_service_driver_register(&pcsuite);
}

static void ftp_exit(void)
{
	obex_service_driver_unregister(&ftp);
	obex_service_driver_unregister(&pcsuite);
}

OBEX_PLUGIN_DEFINE(ftp, ftp_init, ftp_exit)
