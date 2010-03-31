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

struct ftp_session {
	struct obex_session *os;
	gchar *folder;
};

static void set_folder(struct ftp_session *ftp, const char *new_folder)
{
	g_free(ftp->folder);

	ftp->folder = new_folder ? g_strdup(new_folder) : NULL;
}

static gint get_by_type(struct ftp_session *ftp, const gchar *type)
{
	struct obex_session *os = ftp->os;
	const char *capability = obex_get_capability_path(os);

	if (type == NULL)
		return obex_get_stream_start(os, ftp->folder, os);

	if (g_str_equal(type, CAP_TYPE))
		return obex_get_stream_start(os, capability, os);

	if (g_str_equal(type, LST_TYPE))
		return obex_get_stream_start(os, ftp->folder, os);

	return -ENOENT;
}

static gpointer ftp_connect(struct obex_session *os, int *err)
{
	struct ftp_session *ftp;
	const char *root_folder;

	root_folder = obex_get_root_folder(os);

	manager_register_session(os);

	ftp = g_new0(struct ftp_session, 1);
	set_folder(ftp, root_folder);
	ftp->os = os;

	if (err)
		*err = 0;

	return ftp;
}

static int ftp_get(struct obex_session *os, obex_object_t *obj,
		gpointer user_data)
{
	struct ftp_session *ftp = user_data;
	const char *type = obex_get_type(os);
	int ret;

	if (ftp->folder == NULL)
		return -ENOENT;

	ret = get_by_type(ftp, type);
	if (ret < 0)
		return ret;

	return 0;
}

static gint ftp_delete(struct ftp_session *ftp, const char *name)
{
	gchar *path;
	int ret = 0;

	if (!(ftp->folder && name))
		return -EINVAL;

	path = g_build_filename(ftp->folder, name, NULL);

	if (obex_remove(ftp->os, path) < 0)
		ret = -errno;

	g_free(path);

	return ret;
}

static gint ftp_chkput(struct obex_session *os, gpointer user_data)
{
	struct ftp_session *ftp = user_data;
	const gchar *name = obex_get_name(os);
	gchar *path;
	int ret;

	if (obex_get_size(os) == OBJECT_SIZE_DELETE)
		return 0;

	path = g_build_filename(ftp->folder, name, NULL);

	ret = obex_put_stream_start(os, path, os);

	g_free(path);

	return ret;
}

static int ftp_put(struct obex_session *os, gpointer user_data)
{
	struct ftp_session *ftp = user_data;
	const char *name = obex_get_name(os);
	ssize_t size = obex_get_size(os);

	if (ftp->folder == NULL)
		return -EPERM;

	if (name == NULL)
		return -EBADR;

	if (size == OBJECT_SIZE_DELETE)
		return ftp_delete(ftp, name);

	return 0;
}

static int ftp_setpath(struct obex_session *os, obex_object_t *obj,
		gpointer user_data)
{
	struct ftp_session *ftp = user_data;
	const gchar *root_folder, *name;
	guint8 *nonhdr;
	gchar *fullname;
	struct stat dstat;
	gboolean root;
	int err;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return -EBADMSG;
	}

	name = obex_get_name(os);
	root_folder = obex_get_root_folder(os);
	root = g_str_equal(root_folder, ftp->folder);

	/* Check flag "Backup" */
	if ((nonhdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (root)
			return -EPERM;

		fullname = g_path_get_dirname(ftp->folder);
		set_folder(ftp, fullname);
		g_free(fullname);

		debug("Set to parent path: %s", ftp->folder);

		return 0;
	}

	if (!name) {
		debug("Set path failed: name missing!");
		return -EINVAL;
	}

	if (strlen(name) == 0) {
		debug("Set to root");
		set_folder(ftp, root_folder);
		return 0;
	}

	/* Check and set to name path */
	if (strstr(name, "/") || strcmp(name, "..") == 0) {
		error("Set path failed: name incorrect!");
		return -EPERM;
	}

	fullname = g_build_filename(ftp->folder, name, NULL);

	debug("Fullname: %s", fullname);

	if (root && obex_get_symlinks(os))
		err = stat(fullname, &dstat);
	else
		err = lstat(fullname, &dstat);

	if (err < 0) {
		err = -errno;

		if (err == -ENOENT)
			goto not_found;

		debug("%s: %s(%d)", root ? "stat" : "lstat",
				strerror(-err), -err);

		goto done;
	}

	if (S_ISDIR(dstat.st_mode) && (dstat.st_mode & S_IRUSR) &&
						(dstat.st_mode & S_IXUSR)) {
		set_folder(ftp, fullname);
		goto done;
	}

	err = -EPERM;
	goto done;

not_found:
	if (nonhdr[0] != 0) {
		err = -ENOENT;
		goto done;
	}

	if (mkdir(fullname, 0755) <  0) {
		err = -errno;
		debug("mkdir: %s(%d)", strerror(-err), -err);
		goto done;
	}

	err = 0;
	set_folder(ftp, fullname);

done:
	g_free(fullname);
	return err;
}

static void ftp_disconnect(struct obex_session *os, gpointer user_data)
{
	struct ftp_session *ftp = user_data;

	manager_unregister_session(os);

	g_free(ftp->folder);
	g_free(ftp);
}

static struct obex_service_driver pcsuite = {
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

static struct obex_service_driver ftp = {
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
