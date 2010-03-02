/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
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

#include <string.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bluetooth/bluetooth.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "logging.h"
#include "obex.h"
#include "service.h"
#include "phonebook.h"
#include "telephony.h"
#include "mimetype.h"
#include "filesystem.h"
#include "dbus.h"

#define PHONEBOOK_TYPE		"x-bt/phonebook"
#define VCARDLISTING_TYPE	"x-bt/vcard-listing"
#define VCARDENTRY_TYPE		"x-bt/vcard"

#define ORDER_TAG		0x01
#define SEARCHVALUE_TAG		0x02
#define SEARCHATTRIB_TAG	0x03
#define MAXLISTCOUNT_TAG	0x04
#define LISTSTARTOFFSET_TAG	0x05
#define FILTER_TAG		0x06
#define FORMAT_TAG		0X07
#define PHONEBOOKSIZE_TAG	0X08
#define NEWMISSEDCALLS_TAG	0X09

/* The following length is in the unit of byte */
#define ORDER_LEN		1
#define SEARCHATTRIB_LEN	1
#define MAXLISTCOUNT_LEN	2
#define LISTSTARTOFFSET_LEN	2
#define FILTER_LEN		8
#define FORMAT_LEN		1
#define PHONEBOOKSIZE_LEN	2
#define NEWMISSEDCALLS_LEN	1

#define MCH		"telecom/mch.vcf"
#define SIM1_MCH	"SIM1/telecom/mch.vcf"

#define DEFAULT_COUNT 65535

#define APPARAM_HDR_SIZE 2

#define get_be64(val)	GUINT64_FROM_BE(bt_get_unaligned((guint64 *) val))
#define get_be16(val)	GUINT16_FROM_BE(bt_get_unaligned((guint16 *) val))

#define put_be16(val, ptr) bt_put_unaligned(GUINT16_TO_BE(val), (guint16 *) ptr)

#define PBAP_CHANNEL	15

#define PBAP_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>	\
<record>									\
  <attribute id=\"0x0001\">							\
    <sequence>									\
      <uuid value=\"0x112f\"/>							\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0004\">							\
    <sequence>									\
      <sequence>								\
        <uuid value=\"0x0100\"/>						\
      </sequence>								\
      <sequence>								\
        <uuid value=\"0x0003\"/>						\
        <uint8 value=\"%u\" name=\"channel\"/>					\
      </sequence>								\
      <sequence>								\
        <uuid value=\"0x0008\"/>						\
      </sequence>								\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0009\">							\
    <sequence>									\
      <sequence>								\
        <uuid value=\"0x1130\"/>						\
        <uint16 value=\"0x0100\" name=\"version\"/>				\
      </sequence>								\
    </sequence>									\
  </attribute>									\
										\
  <attribute id=\"0x0100\">							\
    <text value=\"%s\" name=\"name\"/>						\
  </attribute>									\
										\
  <attribute id=\"0x0314\">							\
    <uint8 value=\"0x01\"/>							\
  </attribute>									\
</record>"

struct apparam_hdr {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed));

struct phonebook_query {
	const char *type;
	GString *buffer;
	struct OBEX_session *os;
};

static const guint8 PBAP_TARGET[TARGET_SIZE] = {
			0x79, 0x61, 0x35, 0xF0,  0xF0, 0xC5, 0x11, 0xD8,
			0x09, 0x66, 0x08, 0x00,  0x20, 0x0C, 0x9A, 0x66  };

static obex_rsp_t pbap_connect(struct OBEX_session *os)
{
	manager_register_session(os);

	return OBEX_RSP_SUCCESS;
}

static obex_rsp_t pbap_get(struct OBEX_session *os, obex_object_t *obj)
{
	const gchar *type = obex_get_type(os);
	const gchar *folder = obex_get_folder(os);
	const gchar *name = obex_get_name(os);
	gchar *path;
	gint ret;

	if (type == NULL)
		return OBEX_RSP_BAD_REQUEST;

	if (strcmp(type, PHONEBOOK_TYPE) == 0)
		/* Always contains the absolute path */
		path = g_strdup(name);
	else if (strcmp(type, VCARDLISTING_TYPE) == 0)
		/* Always relative */
		if (!name || strlen(name) == 0)
			/* Current folder */
			path = g_strdup(folder);
		else
			/* Current folder + relative path */
			path = g_build_filename(folder, name, NULL);

	else if (strcmp(type, VCARDENTRY_TYPE) == 0)
		/* Always relative */
		path = g_build_filename(folder, name, NULL);
	else
		return OBEX_RSP_BAD_REQUEST;

	ret = obex_stream_start(os, path);
	g_free(path);

	switch (ret) {
	case 0:
		return OBEX_RSP_SUCCESS;
	case -ENOENT:
		return OBEX_RSP_NOT_FOUND;
	default:
		return OBEX_RSP_FORBIDDEN;

	}
}

static gboolean pbap_is_valid_folder(struct obex_session *session)
{
	if (session->current_folder == NULL) {
		if (g_str_equal(session->name, "telecom") == TRUE ||
			g_str_equal(session->name, "SIM1") == TRUE)
			return TRUE;
	} else if (g_str_equal(session->current_folder, "SIM1") == TRUE) {
		if (g_str_equal(session->name, "telecom") == TRUE)
			return TRUE;
	} else if (g_str_equal(session->current_folder, "telecom") == TRUE ||
		g_str_equal(session->current_folder, "SIM1/telecom") == TRUE) {
		if (g_str_equal(session->name, "pb") == TRUE ||
				g_str_equal(session->name, "ich") == TRUE ||
				g_str_equal(session->name, "och") == TRUE ||
				g_str_equal(session->name, "mch") == TRUE ||
				g_str_equal(session->name, "cch") == TRUE)
			return TRUE;
	}

	return FALSE;
}

static obex_rsp_t pbap_setpath(struct OBEX_session *os, obex_object_t *obj)
{
	const gchar *current_folder, *name;
	guint8 *nonhdr;
	gchar *fullname;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return OBEX_RSP_PRECONDITION_FAILED;
	}

	current_folder = obex_get_folder(os);
	name = obex_get_name(os);

	/* Check "Backup" flag */
	if ((nonhdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (current_folder == NULL) {
			/* we are already in top level folder */
			return OBEX_RSP_FORBIDDEN;
		}

		fullname = g_path_get_dirname(current_folder);

		if (strlen(fullname) == 1 && *fullname == '.')
			obex_set_folder(os, NULL);
		else
			obex_set_folder(os, fullname);

		g_free(fullname);

		debug("Set to parent path: %s", current_folder);

		return OBEX_RSP_SUCCESS;
	}

	if (!name) {
		error("Set path failed: name missing!");
		return OBEX_RSP_BAD_REQUEST;
	}

	if (strlen(name) == 0) {
		debug("Set to root");

		obex_set_folder(os, NULL);

		return OBEX_RSP_SUCCESS;
	}

	/* Check and set to name path */
	if (strstr(name, "/")) {
		error("Set path failed: name incorrect!");
		return OBEX_RSP_FORBIDDEN;
	}

	if (pbap_is_valid_folder(os) == FALSE)
		return OBEX_RSP_NOT_FOUND;

	if (current_folder == NULL)
		fullname = g_build_filename("", name, NULL);
	else
		fullname = g_build_filename(current_folder, name, NULL);

	debug("Fullname: %s", fullname);

	obex_set_folder(os, fullname);

	return OBEX_RSP_SUCCESS;
}

static void pbap_disconnect(struct OBEX_session *os)
{
	manager_unregister_session(os);
}

static gint pbap_chkput(struct OBEX_session *os)
{
	/* Rejects all PUTs */
	return -EINVAL;
}

struct obex_service_driver pbap = {
	.name = "Phonebook Access server",
	.service = OBEX_PBAP,
	.channel = PBAP_CHANNEL,
	.record = PBAP_RECORD,
	.target = PBAP_TARGET,
	.target_size = TARGET_SIZE,
	.connect = pbap_connect,
	.get = pbap_get,
	.setpath = pbap_setpath,
	.disconnect = pbap_disconnect,
	.chkput = pbap_chkput
};

static void query_result(const gchar *buffer, size_t bufsize,
		gint vcards, gint missed, gpointer user_data)
{
	struct phonebook_query *query = user_data;

	if (!query->buffer)
		query->buffer = g_string_new_len(buffer, bufsize);
	else
		query->buffer = g_string_append_len(query->buffer, buffer, bufsize);

	obex_object_set_io_flags(query, G_IO_IN, 0);
}

static gpointer vobject_open(const char *name, int oflag, mode_t mode,
		size_t *size, struct OBEX_session *os, int *err)
{
	const gchar *type = obex_get_type(os);
	struct phonebook_query *query;

	if (oflag != O_RDONLY)
		goto fail;

	/* TODO: mch? */

	/* TODO: get application parameter */
	query = g_new0(struct phonebook_query, 1);
	query->type = type;
	query->os = os;

	if (phonebook_query(name, query_result, query) < 0) {
		g_free(query);
		goto fail;
	}

	if (size)
		*size = OBJECT_SIZE_UNKNOWN;

	return query;

fail:
	if (err)
		*err = -EPERM;

	return NULL;
}

static ssize_t vobject_read(gpointer object, void *buf, size_t count)
{
	struct phonebook_query *query = object;

	if (query->buffer)
		return string_read(query->buffer, buf, count);

	return -EAGAIN;
}

static int vobject_close(gpointer object)
{
	struct phonebook_query *query = object;

	if (query->buffer)
		string_free(query->buffer);

	g_free(query);

	return 0;
}

struct obex_mime_type_driver mime_pull = {
	.target		= PBAP_TARGET,
	.mimetype	= "x-bt/phonebook",
	.open		= vobject_open,
	.close		= vobject_close,
	.read		= vobject_read,
};

struct obex_mime_type_driver mime_list = {
	.target		= PBAP_TARGET,
	.mimetype	= "x-bt/vcard-listing",
	.open		= vobject_open,
	.close		= vobject_close,
	.read		= vobject_read,
};

struct obex_mime_type_driver mime_vcard = {
	.target		= PBAP_TARGET,
	.mimetype	= "x-bt/vcard",
	.open		= vobject_open,
	.close		= vobject_close,
	.read		= vobject_read,
};

static int pbap_init(void)
{
	int err;

	err = phonebook_init();
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&mime_pull);
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&mime_list);
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&mime_vcard);
	if (err < 0)
		return err;

	return obex_service_driver_register(&pbap);
}

static void pbap_exit(void)
{
	obex_service_driver_unregister(&pbap);
	obex_mime_type_driver_unregister(&mime_pull);
	obex_mime_type_driver_unregister(&mime_list);
	obex_mime_type_driver_unregister(&mime_vcard);
	phonebook_exit();
}

OBEX_PLUGIN_DEFINE(pbap, pbap_init, pbap_exit)
