/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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
#include "gdbus.h"


#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "mimetype.h"
#include "service.h"

#define BACKUP_BUS_NAME		"com.nokia.backup.plugin"
#define BACKUP_PATH		"/com/nokia/backup"
#define BACKUP_PLUGIN_INTERFACE	"com.nokia.backup.plugin"
#define BACKUP_DBUS_TIMEOUT	(1000 * 60 * 15)

static const uint8_t FTP_TARGET[TARGET_SIZE] = {
	0xF9, 0xEC, 0x7B, 0xC4,  0x95, 0x3C, 0x11, 0xD2,
	0x98, 0x4E, 0x52, 0x54,  0x00, 0xDC, 0x9E, 0x09  };

struct backup_object{
	gchar *cmd;
	int fd;
	int oflag;
	int error_code;
	mode_t mode;
	DBusPendingCall *pending_call;
	DBusConnection *conn;
};

static void on_backup_dbus_notify(DBusPendingCall *pending_call,
					void *user_data)
{
	struct backup_object *obj = user_data;
	DBusMessage *reply;
	const char *filename;
	int error_code;

	DBG("Notification received for pending call - %s", obj->cmd);

	reply = dbus_pending_call_steal_reply(pending_call);

	if (reply && dbus_message_get_args(reply, NULL, DBUS_TYPE_INT32,
					&error_code, DBUS_TYPE_STRING,
					&filename, DBUS_TYPE_INVALID)) {

		obj->error_code = error_code;

		if (filename) {
			DBG("Notification - file path = %s, error_code = %d",
					filename, error_code);
			if (error_code == 0)
				obj->fd = open(filename,obj->oflag,obj->mode);
		}

	} else
		DBG("Notification timed out or connection got closed");

	if (reply)
		dbus_message_unref(reply);

	dbus_pending_call_unref(pending_call);
	obj->pending_call = NULL;
	dbus_connection_unref(obj->conn);
	obj->conn = NULL;

	if (obj->fd >= 0) {
		DBG("File opened, setting io flags, cmd = %s",
				obj->cmd);
		if (obj->oflag == O_RDONLY)
			obex_object_set_io_flags(user_data, G_IO_IN, 0);
		else
			obex_object_set_io_flags(user_data, G_IO_OUT, 0);
	} else {
		DBG("File open error, setting io error, cmd = %s",
				obj->cmd);
		obex_object_set_io_flags(user_data, G_IO_ERR, -EPERM);
	}
}

static gboolean send_backup_dbus_message(const char *oper,
					struct backup_object *obj,
					size_t *size)
{
	DBusConnection *conn;
	DBusMessage *msg;
	DBusPendingCall *pending_call;
	gboolean ret = FALSE;
	dbus_uint32_t file_size;

	file_size = size ? *size : 0;

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, NULL, NULL);

	if (conn == NULL)
		return FALSE;

	msg = dbus_message_new_method_call(BACKUP_BUS_NAME, BACKUP_PATH,
						BACKUP_PLUGIN_INTERFACE,
						"request");
	if (msg == NULL) {
		dbus_connection_unref(conn);
		return FALSE;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &oper,
					DBUS_TYPE_STRING, &obj->cmd,
					DBUS_TYPE_INT32, &file_size,
					DBUS_TYPE_INVALID);

	if (strcmp(oper, "open") == 0) {
		ret = dbus_connection_send_with_reply(conn, msg, &pending_call,
							BACKUP_DBUS_TIMEOUT);
		dbus_message_unref(msg);
		if (ret) {
			obj->conn = conn;
			obj->pending_call = pending_call;
			ret = dbus_pending_call_set_notify(pending_call,
							on_backup_dbus_notify,
							obj, NULL);
		} else
			dbus_connection_unref(conn);
	} else {
		ret = dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		dbus_connection_unref(conn);
	}

	return ret;
}

static void *backup_open(const char *name, int oflag, mode_t mode,
				void *context, size_t *size, int *err)
{
	struct backup_object *obj = g_new0(struct backup_object, 1);

	DBG("cmd = %s", name);

	obj->cmd = g_path_get_basename(name);
	obj->oflag = oflag;
	obj->mode = mode;
	obj->fd = -1;
	obj->pending_call = NULL;
	obj->conn = NULL;
	obj->error_code = 0;

	if (send_backup_dbus_message("open", obj, size) == FALSE) {
		g_free(obj);
		obj = NULL;
	}

	if (err)
		*err = 0;

	return obj;
}

static int backup_close(void *object)
{
	struct backup_object *obj = object;
	size_t size = 0;

	DBG("cmd = %s", obj->cmd);

	if (obj->fd != -1)
		close(obj->fd);

	if (obj->pending_call) {
		dbus_pending_call_cancel(obj->pending_call);
		dbus_pending_call_unref(obj->pending_call);
		dbus_connection_unref(obj->conn);
	}

	send_backup_dbus_message("close", obj, &size);

	g_free(obj->cmd);
	g_free(obj);

	return 0;
}

static ssize_t backup_read(void *object, void *buf, size_t count,
					uint8_t *hi, unsigned int *flags)
{
	struct backup_object *obj = object;
	ssize_t ret = 0;

	*hi = OBEX_HDR_BODY;

	if (flags)
		*flags = 0;

	if (obj->pending_call) {
		DBG("cmd = %s, IN WAITING STAGE", obj->cmd);
		return -EAGAIN;
	}

	if (obj->fd != -1) {
		DBG("cmd = %s, READING DATA", obj->cmd);
		ret = read(obj->fd, buf, count);
		if (ret < 0)
			ret = -errno;
	} else {
		DBG("cmd = %s, PERMANENT FAILURE", obj->cmd);
		ret = obj->error_code ? -obj->error_code : -ENOENT;
	}

	return ret;
}

static ssize_t backup_write(void *object, const void *buf, size_t count)
{
	struct backup_object *obj = object;
	ssize_t ret = 0;

	if (obj->pending_call) {
		DBG("cmd = %s, IN WAITING STAGE", obj->cmd);
		return -EAGAIN;
	}

	if (obj->fd != -1) {
		ret = write(obj->fd, buf, count);

		DBG("cmd = %s, WRITTING", obj->cmd);

		if (ret < 0) {
			error("backup: cmd = %s", obj->cmd);
			ret = -errno;
		}
	} else {
		error("backup: cmd = %s", obj->cmd);
		ret = obj->error_code ? -obj->error_code : -ENOENT;
	}

	return ret;
}

static int backup_flush(void *object)
{
	DBG("%p", object);

	return 0;
}

static struct obex_mime_type_driver backup = {
	.target = FTP_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "application/vnd.nokia-backup",
	.open = backup_open,
	.close = backup_close,
	.read = backup_read,
	.write = backup_write,
	.flush = backup_flush,
};

static int backup_init(void)
{
	return obex_mime_type_driver_register(&backup);
}

static void backup_exit(void)
{
	obex_mime_type_driver_unregister(&backup);
}

OBEX_PLUGIN_DEFINE(backup, backup_init, backup_exit)
