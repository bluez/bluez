/*
 *
 *  OBEX IrMC Sync Server
 *
 *  Copyright (C) 2010  Marcel Mol <marcel@mesa.nl>
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
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "obexd.h"
#include "plugin.h"
#include "log.h"
#include "obex.h"
#include "service.h"
#include "phonebook.h"
#include "mimetype.h"
#include "filesystem.h"
#include "manager.h"

#define IRMC_CHANNEL	14

#define IRMC_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>	\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"0x1104\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0008\"/>					\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0009\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x1104\"/>					\
        <uint16 value=\"0x0100\" name=\"version\"/>			\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
									\
  <attribute id=\"0x0301\">						\
    <sequence>								\
      <uint8 value=\"0x01\"/>						\
    </sequence>								\
  </attribute>								\
</record>"


struct aparam_header {
	uint8_t tag;
	uint8_t len;
	uint8_t val[0];
} __attribute__ ((packed));

#define DID_LEN 18

struct irmc_session {
	struct obex_session *os;
	struct apparam_field *params;
	uint16_t entries;
	GString *buffer;
	char sn[DID_LEN];
	char did[DID_LEN];
	char manu[DID_LEN];
	char model[DID_LEN];
	void *request;
};

#define IRMC_TARGET_SIZE 9

static const guint8 IRMC_TARGET[IRMC_TARGET_SIZE] = {
			0x49, 0x52, 0x4d, 0x43,  0x2d, 0x53, 0x59, 0x4e, 0x43 };

/* FIXME:
 * the IrMC specs state the first vcard should be the owner
 * vcard. As there is no simple way to collect ownerdetails
 * just create an empty vcard (which is allowed according to the
 * specs).
 */
static const char *owner_vcard =
		"BEGIN:VCARD\r\n"
		"VERSION:2.1\r\n"
		"N:\r\n"
		"TEL:\r\n"
		"X-IRMX-LUID:0\r\n"
		"END:VCARD\r\n";

static void phonebook_size_result(const char *buffer, size_t bufsize,
					int vcards, int missed,
					gboolean lastpart, void *user_data)
{
	struct irmc_session *irmc = user_data;

	DBG("vcards %d", vcards);

	irmc->params->maxlistcount = vcards;

	if (irmc->request) {
		phonebook_req_finalize(irmc->request);
		irmc->request = NULL;
	}
}

static void query_result(const char *buffer, size_t bufsize, int vcards,
				int missed, gboolean lastpart, void *user_data)
{
	struct irmc_session *irmc = user_data;
	const char *s, *t;

	DBG("bufsize %zu vcards %d missed %d", bufsize, vcards, missed);

	if (irmc->request) {
		phonebook_req_finalize(irmc->request);
		irmc->request = NULL;
	}

	/* first add a 'owner' vcard */
	if (!irmc->buffer)
		irmc->buffer = g_string_new(owner_vcard);
	else
		irmc->buffer = g_string_append(irmc->buffer, owner_vcard);

	if (buffer == NULL)
		goto done;

	/* loop around buffer and add X-IRMC-LUID attribs */
	s = buffer;
	while ((t = strstr(s, "UID:")) != NULL) {
		/* add upto UID: into buffer */
		irmc->buffer = g_string_append_len(irmc->buffer, s, t-s);
		/*
		 * add UID: line into buffer
		 * Not sure if UID is still needed if X-IRMC-LUID is there
		 */
		s = t;
		t = strstr(s, "\r\n");
		t += 2;
		irmc->buffer = g_string_append_len(irmc->buffer, s, t-s);
		/* add X-IRMC-LUID with same number as UID */
		irmc->buffer = g_string_append_len(irmc->buffer,
							"X-IRMC-LUID:", 12);
		s += 4; /* point to uid number */
		irmc->buffer = g_string_append_len(irmc->buffer, s, t-s);
		s = t;
	}
	/* add remaining bit of buffer */
	irmc->buffer = g_string_append(irmc->buffer, s);

done:
	obex_object_set_io_flags(irmc, G_IO_IN, 0);
}

static void *irmc_connect(struct obex_session *os, int *err)
{
	struct irmc_session *irmc;
	struct apparam_field *param;
	int ret;

	DBG("");

	manager_register_session(os);

	irmc = g_new0(struct irmc_session, 1);
	irmc->os = os;

	/* FIXME:
	 * Ideally get capabilities info here and use that to define
	 * IrMC DID and SN etc parameters.
	 * For now lets used hostname and some 'random' value
	 */
	gethostname(irmc->did, DID_LEN);
	strncpy(irmc->sn, "12345", sizeof(irmc->sn) - 1);
	strncpy(irmc->manu, "obex", sizeof(irmc->manu) - 1);
	strncpy(irmc->model, "mymodel", sizeof(irmc->model) - 1);

	/* We need to know the number of contact/cal/nt entries
	 * somewhere so why not do it now.
	 */
	param = g_new0(struct apparam_field, 1);
	param->maxlistcount = 0; /* to count the number of vcards... */
	param->filter = 0x200085; /* UID TEL N VERSION */
	irmc->params = param;
	irmc->request = phonebook_pull("telecom/pb.vcf", irmc->params,
					phonebook_size_result, irmc, err);
	ret = phonebook_pull_read(irmc->request);
	if (err)
		*err = ret;

	return irmc;
}

static int irmc_get(struct obex_session *os, void *user_data)
{
	struct irmc_session *irmc = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	char *path;
	int ret;

	DBG("name %s type %s irmc %p", name, type ? type : "NA", irmc);

	path = g_strdup(name);

	ret = obex_get_stream_start(os, path);

	g_free(path);

	return ret;
}

static void irmc_disconnect(struct obex_session *os, void *user_data)
{
	struct irmc_session *irmc = user_data;

	DBG("");

	manager_unregister_session(os);

	if (irmc->params) {
		if (irmc->params->searchval)
			g_free(irmc->params->searchval);
		g_free(irmc->params);
	}

	if (irmc->buffer)
		g_string_free(irmc->buffer, TRUE);

	g_free(irmc);
}

static int irmc_chkput(struct obex_session *os, void *user_data)
{
	DBG("");
	/* Reject all PUTs */
	return -EBADR;
}

static void *irmc_open_devinfo(struct irmc_session *irmc, int *err)
{
	if (!irmc->buffer)
		irmc->buffer = g_string_new("");

	g_string_append_printf(irmc->buffer,
				"MANU:%s\r\n"
				"MOD:%s\r\n"
				"SN:%s\r\n"
				"IRMC-VERSION:1.1\r\n"
				"PB-TYPE-TX:VCARD2.1\r\n"
				"PB-TYPE-RX:NONE\r\n"
				"CAL-TYPE-TX:NONE\r\n"
				"CAL-TYPE-RX:NONE\r\n"
				"MSG-TYPE-TX:NONE\r\n"
				"MSG-TYPE-RX:NONE\r\n"
				"NOTE-TYPE-TX:NONE\r\n"
				"NOTE-TYPE-RX:NONE\r\n",
				irmc->manu, irmc->model, irmc->sn);

	return irmc;
}

static void *irmc_open_pb(const char *name, struct irmc_session *irmc,
								int *err)
{
	GString *mybuf;
	int ret;

	if (!g_strcmp0(name, ".vcf")) {
		/* how can we tell if the vcard count call already finished? */
		irmc->request = phonebook_pull("telecom/pb.vcf", irmc->params,
						query_result, irmc, &ret);
		if (ret < 0) {
			DBG("phonebook_pull failed...");
			goto fail;
		}

		ret = phonebook_pull_read(irmc->request);
		if (ret < 0) {
			DBG("phonebook_pull_read failed...");
			goto fail;
		}

		return irmc;
	}

	if (!g_strcmp0(name, "/info.log")) {
		mybuf = g_string_new("");
		g_string_printf(mybuf, "Total-Records:%d\r\n"
				"Maximum-Records:%d\r\n"
				"IEL:2\r\n"
				"DID:%s\r\n",
				irmc->params->maxlistcount,
				irmc->params->maxlistcount, irmc->did);
	} else if (!strncmp(name, "/luid/", 6)) {
		name += 6;
		if (!g_strcmp0(name, "cc.log")) {
			mybuf = g_string_new("");
			g_string_printf(mybuf, "%d\r\n",
						irmc->params->maxlistcount);
		} else {
			int l = strlen(name);
			/* FIXME:
			 * Reply the same to any *.log so we hopefully force a
			 * full phonebook dump.
			 * Is IEL:2 ok?
			 */
			if (l > 4 && !g_strcmp0(name + l - 4, ".log")) {
				DBG("changelog request, force whole book");
				mybuf = g_string_new("");
				g_string_printf(mybuf, "SN:%s\r\n"
							"DID:%s\r\n"
							"Total-Records:%d\r\n"
							"Maximum-Records:%d\r\n"
							"*\r\n",
						irmc->sn, irmc->did,
						irmc->params->maxlistcount,
						irmc->params->maxlistcount);
			} else {
				ret = -EBADR;
				goto fail;
			}
		}
	} else {
		ret = -EBADR;
		goto fail;
	}

	if (!irmc->buffer)
		irmc->buffer = mybuf;
	else {
		irmc->buffer = g_string_append(irmc->buffer, mybuf->str);
		g_string_free(mybuf, TRUE);
	}

	return irmc;

fail:
	if (err)
		*err = ret;

	return NULL;
}

static void *irmc_open_cal(const char *name, struct irmc_session *irmc,
								int *err)
{
	/* no suport yet. Just return an empty buffer. cal.vcs */
	DBG("unsupported, returning empty buffer");

	if (!irmc->buffer)
		irmc->buffer = g_string_new("");

	return irmc;
}

static void *irmc_open_nt(const char *name, struct irmc_session *irmc,
								int *err)
{
	/* no suport yet. Just return an empty buffer. nt.vnt */
	DBG("unsupported, returning empty buffer");

	if (!irmc->buffer)
		irmc->buffer = g_string_new("");

	return irmc;
}

static void *irmc_open(const char *name, int oflag, mode_t mode, void *context,
							size_t *size, int *err)
{
	struct irmc_session *irmc = context;
	int ret = 0;
	const char *p;

	DBG("name %s context %p", name, context);

	if (oflag != O_RDONLY) {
		ret = -EPERM;
		goto fail;
	}
	if (name == NULL || strncmp(name, "telecom/", 8) != 0) {
		ret = -EBADR;
		goto fail;
	}

	p = name + 8;
	if (!g_strcmp0(p, "devinfo.txt"))
		return irmc_open_devinfo(irmc, err);
	else if (!strncmp(p, "pb", 2))
		return irmc_open_pb(p+2, irmc, err);
	else if (!strncmp(p, "cal", 3))
		return irmc_open_cal(p+3, irmc, err);
	else if (!strncmp(p, "nt", 2))
		return irmc_open_nt(p+2, irmc, err);

fail:
	if (err)
		*err = ret;

	return NULL;
}

static int irmc_close(void *object)
{
	struct irmc_session *irmc = object;

	DBG("");

	if (irmc->buffer) {
		g_string_free(irmc->buffer, TRUE);
		irmc->buffer = NULL;
	}

	if (irmc->request) {
		phonebook_req_finalize(irmc->request);
		irmc->request = NULL;
	}

	return 0;
}

static ssize_t irmc_read(void *object, void *buf, size_t count)
{
	struct irmc_session *irmc = object;
	int len;

	DBG("buffer %p count %zu", irmc->buffer, count);
	if (!irmc->buffer)
                return -EAGAIN;

	len = string_read(irmc->buffer, buf, count);
	DBG("returning %d bytes", len);
	return len;
}

static struct obex_mime_type_driver irmc_driver = {
	.target = IRMC_TARGET,
	.target_size = IRMC_TARGET_SIZE,
	.open = irmc_open,
	.close = irmc_close,
	.read = irmc_read,
};

static struct obex_service_driver irmc = {
	.name = "IRMC Sync server",
	.service = OBEX_IRMC,
	.channel = IRMC_CHANNEL,
	.secure = TRUE,
	.record = IRMC_RECORD,
	.target = IRMC_TARGET,
	.target_size = IRMC_TARGET_SIZE,
	.connect = irmc_connect,
	.get = irmc_get,
	.disconnect = irmc_disconnect,
	.chkput = irmc_chkput
};

static int irmc_init(void)
{
	int err;

	DBG("");
	err = phonebook_init();
	if (err < 0)
		return err;

	err = obex_mime_type_driver_register(&irmc_driver);
	if (err < 0)
		goto fail_mime_irmc;

	err = obex_service_driver_register(&irmc);
	if (err < 0)
		goto fail_irmc_reg;

	return 0;

fail_irmc_reg:
	obex_mime_type_driver_unregister(&irmc_driver);
fail_mime_irmc:
	phonebook_exit();

	return err;
}

static void irmc_exit(void)
{
	DBG("");
	obex_service_driver_unregister(&irmc);
	obex_mime_type_driver_unregister(&irmc_driver);
	phonebook_exit();
}

OBEX_PLUGIN_DEFINE(irmc, irmc_init, irmc_exit)
