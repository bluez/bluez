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

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "plugin.h"
#include "logging.h"
#include "obex.h"
#include "service.h"
#include "phonebook.h"
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

struct aparam_header {
	uint8_t		tag;
	uint8_t		len;
	uint8_t		val[0];
} __attribute__ ((packed));

struct pbap_session {
	struct obex_session *os;
	struct apparam_field *params;
	gchar *folder;
	GString *buffer;
};

static const guint8 PBAP_TARGET[TARGET_SIZE] = {
			0x79, 0x61, 0x35, 0xF0,  0xF0, 0xC5, 0x11, 0xD8,
			0x09, 0x66, 0x08, 0x00,  0x20, 0x0C, 0x9A, 0x66  };

static void set_folder(struct pbap_session *pbap, const char *new_folder)
{
	g_free(pbap->folder);

	pbap->folder = new_folder ? g_strdup(new_folder) : NULL;
}

static struct apparam_field *parse_aparam(const guint8 *buffer, guint32 hlen)
{
	struct apparam_field *param;
	struct aparam_header *hdr;
	guint32 len = 0;
	guint16 val16;
	guint64 val64;

	param = g_new0(struct apparam_field, 1);

	while (len < hlen) {
		hdr = (void *) buffer + len;

		switch (hdr->tag) {
		case ORDER_TAG:
			if (hdr->len != ORDER_LEN)
				goto failed;

			param->order = hdr->val[0];
			break;

		case SEARCHATTRIB_TAG:
			if (hdr->len != SEARCHATTRIB_LEN)
				goto failed;

			param->searchattrib = hdr->val[0];
			break;
		case SEARCHVALUE_TAG:
			param->searchval = g_try_malloc0(hdr->len + 1);
			if (param->searchval)
				memcpy(param->searchval, hdr->val, hdr->len);
			break;
		case FILTER_TAG:
			if (hdr->len != FILTER_LEN)
				goto failed;

			memcpy(&val64, hdr->val, sizeof(val64));
			param->filter = GUINT64_FROM_BE(val64);

			break;
		case FORMAT_TAG:
			if (hdr->len != FORMAT_LEN)
				goto failed;

			param->format = hdr->val[0];
			break;
		case MAXLISTCOUNT_TAG:
			if (hdr->len != MAXLISTCOUNT_LEN)
				goto failed;

			memcpy(&val16, hdr->val, sizeof(val16));
			param->maxlistcount = GUINT16_FROM_BE(val16);
			break;
		case LISTSTARTOFFSET_TAG:
			if (hdr->len != LISTSTARTOFFSET_LEN)
				goto failed;

			memcpy(&val16, hdr->val, sizeof(val16));
			param->liststartoffset = GUINT16_FROM_BE(val16);
			break;
		default:
			goto failed;
		}

		len += hdr->len + sizeof(struct aparam_header);
	}

	return param;

failed:
	g_free(param);

	return NULL;
}

static gpointer pbap_connect(struct obex_session *os, int *err)
{
	struct pbap_session *pbap;

	manager_register_session(os);

	pbap = g_new0(struct pbap_session, 1);
	pbap->folder = g_strdup("/");
	pbap->os = os;

	if (err)
		*err = 0;

	return pbap;
}

static int pbap_get(struct obex_session *os, obex_object_t *obj,
		gpointer user_data)
{
	struct pbap_session *pbap = user_data;
	const gchar *type = obex_get_type(os);
	const gchar *name = obex_get_name(os);
	struct apparam_field *params;
	const guint8 *buffer;
	gchar *path;
	ssize_t rsize;
	gint ret;

	if (type == NULL)
		return -EBADR;

	if (strcmp(type, PHONEBOOK_TYPE) == 0)
		/* Always contains the absolute path */
		path = g_strdup(name);
	else if (strcmp(type, VCARDLISTING_TYPE) == 0)
		/* Always relative */
		if (!name || strlen(name) == 0)
			/* Current folder */
			path = g_strdup(pbap->folder);
		else
			/* Current folder + relative path */
			path = g_build_filename(pbap->folder, name, NULL);

	else if (strcmp(type, VCARDENTRY_TYPE) == 0)
		/* Always relative */
		path = g_build_filename(pbap->folder, name, NULL);
	else
		return -EBADR;

	rsize = obex_aparam_read(os, obj, &buffer);
	if (rsize < 0) {
		ret = -EBADR;
		goto failed;
	}

	params = parse_aparam(buffer, rsize);
	if (params == NULL) {
		ret = -EBADR;
		goto failed;
	}

	if (pbap->params) {
		g_free(pbap->params->searchval);
		g_free(pbap->params);
	}

	pbap->params = params;

	ret = obex_get_stream_start(os, path, pbap);
failed:
	g_free(path);

	return ret;
}


static int pbap_setpath(struct obex_session *os, obex_object_t *obj,
		gpointer user_data)
{
	struct pbap_session *pbap = user_data;
	const gchar *name;
	guint8 *nonhdr;
	gchar *fullname;
	int ret;

	if (OBEX_ObjectGetNonHdrData(obj, &nonhdr) != 2) {
		error("Set path failed: flag and constants not found!");
		return -EBADMSG;
	}

	name = obex_get_name(os);

	ret = phonebook_set_folder(pbap->folder, name, nonhdr[0]);
	if (ret < 0)
		return ret;

	if (!pbap->folder)
		fullname = g_strdup(name);
	else
		fullname = g_build_filename(pbap->folder, name, NULL);

	set_folder(pbap, fullname);

	g_free(fullname);

	return 0;
}

static void pbap_disconnect(struct obex_session *os,
		gpointer user_data)
{
	struct pbap_session *pbap = user_data;

	manager_unregister_session(os);

	if (pbap->params) {
		g_free(pbap->params->searchval);
		g_free(pbap->params);
	}

	g_free(pbap->folder);
	g_free(pbap);
}

static gint pbap_chkput(struct obex_session *os,
		gpointer user_data)
{
	/* Rejects all PUTs */
	return -EINVAL;
}

static struct obex_service_driver pbap = {
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
	struct pbap_session *pbap = user_data;

	if (!pbap->buffer)
		pbap->buffer = g_string_new_len(buffer, bufsize);
	else
		pbap->buffer = g_string_append_len(pbap->buffer, buffer, bufsize);

	obex_object_set_io_flags(pbap, G_IO_IN, 0);
}

static gpointer vobject_open(const char *name, int oflag, mode_t mode,
		gpointer context, size_t *size, int *err)
{
	struct pbap_session *pbap = context;
	int ret;

	if (oflag != O_RDONLY) {
		ret = -EPERM;
		goto fail;
	}

	ret = phonebook_pull(name, pbap->params, query_result, pbap);
	if (ret < 0)
		goto fail;

	if (size)
		*size = OBJECT_SIZE_UNKNOWN;

	return pbap;

fail:
	if (err)
		*err = ret;

	return NULL;
}

static ssize_t vobject_read(gpointer object, void *buf, size_t count)
{
	struct pbap_session *pbap = object;

	if (pbap->buffer)
		return string_read(pbap->buffer, buf, count);

	return -EAGAIN;
}

static int vobject_close(gpointer object)
{
	struct pbap_session *pbap = object;

	if (pbap->buffer) {
		string_free(pbap->buffer);
		pbap->buffer = NULL;
	}

	return 0;
}

static struct obex_mime_type_driver mime_pull = {
	.target		= PBAP_TARGET,
	.mimetype	= "x-bt/phonebook",
	.open		= vobject_open,
	.close		= vobject_close,
	.read		= vobject_read,
};

static struct obex_mime_type_driver mime_list = {
	.target		= PBAP_TARGET,
	.mimetype	= "x-bt/vcard-listing",
	.open		= vobject_open,
	.close		= vobject_close,
	.read		= vobject_read,
};

static struct obex_mime_type_driver mime_vcard = {
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
