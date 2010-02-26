/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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
#define PCSUITE_WHO_SIZE 8
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

static const guint8 PCSUITE_WHO[PCSUITE_WHO_SIZE] = {
			'P','C',' ','S','u','i','t','e' };

static gint get_by_type(struct OBEX_session *os, gchar *type)
{
	if (type == NULL)
		return -ENOENT;

	if (g_str_equal(type, CAP_TYPE))
		return obex_stream_start(os, os->server->capability);

	if (g_str_equal(type, LST_TYPE))
		return obex_stream_start(os, os->current_folder);

	return -ENOENT;
}

static gint ftp_prepare_get(struct obex_session *os, gchar *file)
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

	return obex_stream_start(os, file);
}

static obex_rsp_t ftp_connect(struct OBEX_session *os)
{
	manager_register_session(os);

	return OBEX_RSP_SUCCESS;
}

static obex_rsp_t ftp_get(struct OBEX_session *os)
{
	gint err;
	gchar *path;

	if (os->current_folder == NULL) {
		err = -ENOENT;
		goto fail;
	}

	err = get_by_type(os, os->type);
	if (err < 0) {
		if (!os->name)
			goto fail;

		path = g_build_filename(os->current_folder, os->name, NULL);

		err = ftp_prepare_get(os, path);

		g_free(path);

		if (err < 0)
			goto fail;
	}

	return OBEX_RSP_SUCCESS;

fail:
	switch (err) {
	case -ENOENT:
		return OBEX_RSP_NOT_FOUND;

	default:
		return OBEX_RSP_FORBIDDEN;
	}
}

static gint ftp_delete(struct OBEX_session *os)
{
	const char *name = obex_get_name(os);
	const char *folder = obex_get_folder(os);
	gchar *path;
	int ret = 0;

	if (!(folder && name))
		return -EINVAL;

	path = g_build_filename(folder, name, NULL);

	if (os->driver->remove(path) < 0)
		ret = -errno;

	g_free(path);

	return ret;
}

static gint ftp_chkput(struct OBEX_session *os)
{

	if (obex_get_size(os) == OBJECT_SIZE_DELETE)
		return 0;

	return obex_prepare_put(os);
}

static obex_rsp_t ftp_put(struct OBEX_session *os)
{
	const char *folder = obex_get_folder(os);
	const char *name = obex_get_name(os);
	ssize_t size = obex_get_size(os);
	int ret = 0;

	if (folder == NULL)
		return OBEX_RSP_FORBIDDEN;

	if (name == NULL)
		return OBEX_RSP_BAD_REQUEST;

	if (size == OBJECT_SIZE_DELETE)
		ret = ftp_delete(os);

	switch (ret) {
	case 0:
		return OBEX_RSP_SUCCESS;
	case -ENOENT:
		return OBEX_RSP_NOT_FOUND;
	case -ENOTEMPTY:
		return OBEX_RSP_PRECONDITION_FAILED;
	default:
		return OBEX_RSP_FORBIDDEN;
	}
}

static obex_rsp_t ftp_setpath(struct OBEX_session *os, obex_object_t *obj)
{
	const gchar *root_folder, *current_folder, *name;
	guint8 *nonhdr;
	gchar *fullname;
	struct stat dstat;
	gboolean root;
	obex_rsp_t rsp = OBEX_RSP_SUCCESS;
	int err;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return OBEX_RSP_PRECONDITION_FAILED;
	}

	name = obex_get_name(os);
	root_folder = obex_get_root_folder(os);
	current_folder = obex_get_folder(os);
	root = g_str_equal(root_folder, current_folder);

	/* Check flag "Backup" */
	if ((nonhdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (root)
			return OBEX_RSP_FORBIDDEN;

		fullname = g_path_get_dirname(current_folder);
		obex_set_folder(os, fullname);
		g_free(fullname);

		debug("Set to parent path: %s", current_folder);

		return OBEX_RSP_SUCCESS;
	}

	if (!name) {
		debug("Set path failed: name missing!");
		return OBEX_RSP_BAD_REQUEST;
	}

	if (strlen(name) == 0) {
		debug("Set to root");
		obex_set_folder(os, root_folder);
		return OBEX_RSP_SUCCESS;
	}

	/* Check and set to name path */
	if (strstr(name, "/") || strcmp(name, "..") == 0) {
		error("Set path failed: name incorrect!");
		return OBEX_RSP_FORBIDDEN;
	}

	fullname = g_build_filename(current_folder, name, NULL);

	debug("Fullname: %s", fullname);

	if (root && obex_get_symlinks(os))
		err = stat(fullname, &dstat);
	else
		err = lstat(fullname, &dstat);

	if (err < 0) {
		int err = errno;
		debug("%s: %s(%d)", root ? "stat" : "lstat",
				strerror(err), err);
		if (err == ENOENT)
			goto not_found;

		rsp = OBEX_RSP_FORBIDDEN;
		goto done;
	}

	if (S_ISDIR(dstat.st_mode) && (dstat.st_mode & S_IRUSR) &&
						(dstat.st_mode & S_IXUSR)) {
		obex_set_folder(os, fullname);
		goto done;
	}

	rsp = OBEX_RSP_FORBIDDEN;
	goto done;

not_found:
	if (nonhdr[0] != 0) {
		rsp = OBEX_RSP_NOT_FOUND;
		goto done;
	}

	if (mkdir(fullname, 0755) <  0) {
		rsp = OBEX_RSP_FORBIDDEN;
		goto done;
	}

	obex_set_folder(os, fullname);

done:
	g_free(fullname);
	return rsp;
}

static void ftp_disconnect(struct OBEX_session *os)
{
	manager_unregister_session(os);
}

struct obex_service_driver pcsuite = {
	.name = "Nokia OBEX PC Suite Services",
	.service = OBEX_PCSUITE,
	.channel = PCSUITE_CHANNEL,
	.record = PCSUITE_RECORD,
	.target = FTP_TARGET,
	.target_size = TARGET_SIZE,
	.who = PCSUITE_WHO,
	.who_size = PCSUITE_WHO_SIZE,
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
