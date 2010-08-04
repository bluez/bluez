/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "att.h"
#include "gattrib.h"
#include "gatt.h"

#define GATT_UNIX_PATH "/var/run/gatt"
#define GATT_PSM 27

static gchar *opt_src = NULL;
static gchar *opt_dst = NULL;
static int opt_start = 0x0001;
static int opt_end = 0xffff;
static int opt_handle = 0x0001;
static gboolean opt_unix = FALSE;
static gboolean opt_primary = FALSE;
static gboolean opt_characteristics = FALSE;
static gboolean opt_char_read = FALSE;
static GMainLoop *event_loop;

struct characteristic_data {
	GAttrib *attrib;
	uint16_t start;
	uint16_t end;
};

static int l2cap_connect(void)
{
	struct sockaddr_l2 addr;
	bdaddr_t sba, dba;
	int err, sk;

	/* Remote device */
	if (opt_dst == NULL) {
		g_printerr("Remote Bluetooth address required\n");
		return -EINVAL;
	}

	str2ba(opt_dst, &dba);

	/* Local adapter */
	if (opt_src != NULL) {
		if (!strncmp(opt_src, "hci", 3))
			hci_devba(atoi(opt_src + 3), &sba);
		else
			str2ba(opt_src, &sba);
		g_free(opt_src);
	} else
		bacpy(&sba, BDADDR_ANY);

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		err = errno;
		g_printerr("L2CAP socket create failed: %s(%d)\n",
							strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &sba);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		g_printerr("L2CAP socket bind failed: %s(%d)\n",
							strerror(err), err);
		close(sk);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &dba);
	addr.l2_psm = htobs(GATT_PSM);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		err = errno;
		g_printerr("L2CAP socket connect failed: %s(%d)\n",
							strerror(err), err);
		close(sk);
		return -err;
	}

	return sk;
}

static int unix_connect(const char *address)
{
	struct sockaddr_un addr;
	int sk, err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	strncpy(addr.sun_path, address, sizeof(addr.sun_path) - 1);

	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		g_printerr("Unix socket(%s) create failed: %s(%d)\n", address,
							strerror(err), err);
		return -err;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		g_printerr("Unix socket(%s) connect failed: %s(%d)\n", address,
							strerror(err), err);
		close(sk);
		return -err;
	}

	return sk;
}

static GIOChannel *do_connect(void)
{
	GIOChannel *chan;
	int sk;

	if (opt_unix)
		sk = unix_connect(GATT_UNIX_PATH);
	else
		sk = l2cap_connect();
	if (sk < 0)
		return NULL;

	chan = g_io_channel_unix_new(sk);
	g_io_channel_set_flags(chan, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(chan, TRUE);

	return chan;
}

static void primary_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	GAttrib *attrib = user_data;
	struct att_data_list *list;
	unsigned int i;
	uint16_t end;

	if (status == ATT_ECODE_ATTR_NOT_FOUND)
		goto done;

	if (status != 0) {
		g_printerr("Discover all primary services failed: %s\n",
							att_ecode2str(status));
		goto done;
	}

	list = dec_read_by_grp_resp(pdu, plen);
	if (list == NULL)
		goto done;

	for (i = 0, end = 0; i < list->num; i++) {
		uint16_t *u16, length, start;
		int j;

		u16 = (uint16_t *) list->data[i];

		/* Each element contains: attribute handle, end group handle
		 * and attribute value */
		length = list->len - 2 * sizeof(*u16);
		start = btohs(*u16);
		u16++;
		end = btohs(*u16);
		u16++;

		g_print("attr handle = 0x%04x, end grp handle = 0x%04x, ",
								start, end);
		g_print("attr value (UUID) = ");
		if (length == 2)
			g_print("0x%04x\n", btohs(*u16));
		else {
			uint8_t *value = (uint8_t *) u16;

			/* FIXME: pretty print 128-bit UUIDs */
			for (j = 0; j < length; j++)
				g_print("%02x ", value[j]);
			g_print("\n");
		}
	}

	att_data_list_free(list);

	/*
	 * Discover all primary services sub-procedure shall send another
	 * Read by Group Type Request until Error Response is received and
	 * the Error Code is set to Attribute Not Found.
	 */
	gatt_discover_primary(attrib, end + 1, opt_end, primary_cb, attrib);

done:
	g_main_loop_quit(event_loop);
}

static gboolean primary(gpointer user_data)
{
	GAttrib *attrib = user_data;

	gatt_discover_primary(attrib, opt_start, opt_end, primary_cb, attrib);

	return FALSE;
}

static void char_discovered_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct characteristic_data *char_data = user_data;
	struct att_data_list *list;
	uint16_t last = char_data->start;
	int i;

	if (status == ATT_ECODE_ATTR_NOT_FOUND)
		goto done;

	if (status != 0) {
		g_printerr("Discover all characteristics failed: %s\n",
							att_ecode2str(status));
		goto done;
	}

	list = dec_read_by_type_resp(pdu, plen);
	if (list == NULL)
		return;

	for (i = 0; i < list->num; i++) {
		uint16_t *u16, length;
		uint8_t *data;
		int j;

		u16 = (uint16_t *) list->data[i];

		/* Each element contains: handle and attribute value */
		length = list->len - sizeof(*u16);
		last = btohs(*u16);
		u16++;

		data = (uint8_t *)u16;
		g_print("handle = 0x%04x, length = %d, ", last, length);
		g_print("permission = %02x, char value handle = %02x %02x, ",
					*data, *(data + 1), *(data + 2));
		g_print("uuid = ");
		for (j = 3; j < length; j++) {
			data = (uint8_t *)u16 + j;
			g_print("%02x ", *data);
		}
		g_print("\n");
	}

	att_data_list_free(list);

	/* Fetch remaining characteristics for the CURRENT primary service */
	gatt_discover_char(char_data->attrib, last + 1, char_data->end,
						char_discovered_cb, char_data);

done:
	g_free(char_data);
	g_main_loop_quit(event_loop);
}

static gboolean characteristics(gpointer user_data)
{
	GAttrib *attrib = user_data;
	struct characteristic_data *char_data;

	char_data = g_new(struct characteristic_data, 1);
	char_data->attrib = attrib;
	char_data->start = opt_start;
	char_data->end = opt_end;

	gatt_discover_char(attrib, opt_start, opt_end, char_discovered_cb,
								char_data);

	return FALSE;
}

static void char_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	uint8_t value[ATT_MTU];
	int i, vlen;

	if (status != 0) {
		g_printerr("Characteristic value/descriptor read failed: %s\n",
							att_ecode2str(status));
		goto done;
	}
	if (!dec_read_resp(pdu, plen, value, &vlen)) {
		g_printerr("Protocol error\n");
		goto done;
	}
	g_print("Characteristic value/descriptor: ");
	for (i = 0; i < vlen; i++)
		g_print("%02x ", value[i]);
	g_print("\n");

done:
	g_main_loop_quit(event_loop);
}

static gboolean characteristics_read(gpointer user_data)
{
	GAttrib *attrib = user_data;

	gatt_read_char(attrib, opt_handle, char_read_cb, attrib);

	return FALSE;
}

static GOptionEntry primary_char_options[] = {
	{ "start", 's' , 0, G_OPTION_ARG_INT, &opt_start,
		"Starting handle(optional)", "0x0001" },
	{ "end", 'e' , 0, G_OPTION_ARG_INT, &opt_end,
		"Ending handle(optional)", "0xffff" },
	{ NULL },
};

static GOptionEntry char_read_options[] = {
	{ "handle", 'a' , 0, G_OPTION_ARG_INT, &opt_handle,
		"Read characteristic by handle(optional)", "0x0001" },
	{NULL},
};

static GOptionEntry gatt_options[] = {
	{ "primary", 0, 0, G_OPTION_ARG_NONE, &opt_primary,
		"Primary Service Discovery", NULL },
	{ "characteristics", 0, 0, G_OPTION_ARG_NONE, &opt_characteristics,
		"Characteristics Discovery", NULL },
	{ "char-read", 0, 0, G_OPTION_ARG_NONE, &opt_char_read,
		"Characteristics Value/Descriptor Read", NULL },
	{ NULL },
};

static GOptionEntry options[] = {
	{ "unix", 'u', 0, G_OPTION_ARG_NONE, &opt_unix,
		"Connect to server using Unix socket" , NULL },
	{ "adapter", 'i', 0, G_OPTION_ARG_STRING, &opt_src,
		"Specify local adapter interface", "hciX" },
	{ "device", 'b', 0, G_OPTION_ARG_STRING, &opt_dst,
		"Specify remote Bluetooth address", "MAC" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GOptionGroup *gatt_group, *params_group, *char_read_group;
	GError *gerr = NULL;
	GAttrib *attrib;
	GIOChannel *chan;
	GSourceFunc callback;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	/* GATT commands */
	gatt_group = g_option_group_new("gatt", "GATT commands",
					"Show all GATT commands", NULL, NULL);
	g_option_context_add_group(context, gatt_group);
	g_option_group_add_entries(gatt_group, gatt_options);

	/* Primary Services and Characteristics arguments */
	params_group = g_option_group_new("params",
			"Primary Services/Characteristics arguments",
			"Show all Primary Services/Characteristics arguments",
			NULL, NULL);
	g_option_context_add_group(context, params_group);
	g_option_group_add_entries(params_group, primary_char_options);

	/* Characteristics value/descriptor read arguments */
	char_read_group = g_option_group_new("char-read",
		"Characteristics Value/Descriptor Read arguments",
		"Show all Characteristics Value/Descriptor Read arguments",
		NULL, NULL);
	g_option_context_add_group(context, char_read_group);
	g_option_group_add_entries(char_read_group, char_read_options);

	if (g_option_context_parse(context, &argc, &argv, &gerr) == FALSE) {
		g_printerr("%s\n", gerr->message);
		g_error_free(gerr);
	}

	event_loop = g_main_loop_new(NULL, FALSE);

	chan = do_connect();
	if (chan == NULL)
		return 1;
	attrib = g_attrib_new(chan);

	if (opt_primary)
		callback = primary;
	else if (opt_characteristics)
		callback = characteristics;
	else if (opt_char_read)
		callback = characteristics_read;

	g_idle_add(callback, attrib);

	g_main_loop_run(event_loop);

	g_option_context_free(context);

	g_attrib_unref(attrib);

	return 0;
}
