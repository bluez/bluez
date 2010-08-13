/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
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

#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "att.h"
#include "gattrib.h"
#include "gatt.h"

#define GATT_PSM 27

static gchar *opt_src = NULL;
static gchar *opt_dst = NULL;
static int opt_start = 0x0001;
static int opt_end = 0xffff;
static int opt_handle = 0x0001;
static gboolean opt_primary = FALSE;
static gboolean opt_characteristics = FALSE;
static gboolean opt_char_read = FALSE;
static gboolean opt_listen = FALSE;
static guint listen_watch = 0;
static gboolean opt_char_desc = FALSE;
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

static GIOChannel *do_connect(void)
{
	GIOChannel *chan;
	int sk;

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
		uint8_t *value = list->data[i];
		uint8_t length;
		uint16_t start;
		int j;

		/* Each element contains: attribute handle, end group handle
		 * and attribute value */
		length = list->len - 2 * sizeof(uint16_t);
		start = att_get_u16((uint16_t *) value);
		end = att_get_u16((uint16_t *) &value[2]);

		g_print("attr handle = 0x%04x, end grp handle = 0x%04x, ",
								start, end);
		g_print("attr value (UUID) = ");
		if (length == 2)
			g_print("0x%04x\n", att_get_u16((uint16_t *)
							&value[4]));
		else {
			/* FIXME: pretty print 128-bit UUIDs */
			for (j = 4; j < length; j++)
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

	return;

done:
	if (opt_listen == FALSE)
		g_main_loop_quit(event_loop);
}

static void events_handler(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint16_t handle, i;

	handle = att_get_u16((uint16_t *) &pdu[1]);

	switch (pdu[0]) {
	case ATT_OP_HANDLE_NOTIFY:
		g_print("attr handle = 0x%04x value: ", handle);
		for (i = 3; i < len; i++)
			g_print("%02x ", pdu[i]);

		g_print("\n");
		break;
	case ATT_OP_HANDLE_IND:
		break;
	}
}

static gboolean listen_start(gpointer user_data)
{
	GAttrib *attrib = user_data;
	uint8_t events = ATT_OP_HANDLE_NOTIFY;

	listen_watch = g_attrib_register(attrib, events, events_handler,
								NULL, NULL);

	return FALSE;
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
		uint8_t *value = list->data[i];

		last = att_get_u16((uint16_t *) value);

		g_print("handle = 0x%04x, char properties = 0x%02x, "
			"char value handle = 0x%04x, ", last, value[2],
			att_get_u16((uint16_t *) &value[3]));

		g_print("uuid = ");
		if (list->len == 7) {
			g_print("0x%04x\n", att_get_u16((uint16_t *)
							&value[5]));
		} else {
			int j;

			/* FIXME: pretty print 128-bit UUIDs */
			for (j = 5; j < list->len; j++)
				g_print("%02x ", value[j]);
			g_print("\n");
		}
	}

	att_data_list_free(list);

	/* Fetch remaining characteristics for the CURRENT primary service */
	gatt_discover_char(char_data->attrib, last + 1, char_data->end,
						char_discovered_cb, char_data);

	return;

done:
	g_free(char_data);
	if (opt_listen == FALSE)
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
	if (opt_listen == FALSE)
		g_main_loop_quit(event_loop);
}

static gboolean characteristics_read(gpointer user_data)
{
	GAttrib *attrib = user_data;

	gatt_read_char(attrib, opt_handle, char_read_cb, attrib);

	return FALSE;
}

static void char_desc_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct att_data_list *list;
	guint8 format;
	int i;

	if (status != 0) {
		g_printerr("Discover all characteristic descriptors failed: "
						"%s\n", att_ecode2str(status));
		goto done;
	}

	list = dec_find_info_resp(pdu, plen, &format);
	if (list == NULL)
		goto done;

	for (i = 0; i < list->num; i++) {
		char uuidstr[MAX_LEN_UUID_STR];
		uint16_t handle;
		uint8_t *value;
		uuid_t uuid;

		value = list->data[i];
		handle = att_get_u16((uint16_t *) value);

		if (format == 0x01)
			sdp_uuid16_create(&uuid, att_get_u16((uint16_t *)
								&value[2]));
		else
			sdp_uuid128_create(&uuid, &value[2]);

		sdp_uuid2strn(&uuid, uuidstr, MAX_LEN_UUID_STR);
		g_print("handle = 0x%04x, uuid = %s\n", handle, uuidstr);
	}

	att_data_list_free(list);

done:
	if (opt_listen == FALSE)
		g_main_loop_quit(event_loop);
}

static gboolean characteristics_desc(gpointer user_data)
{
	GAttrib *attrib = user_data;

	gatt_find_info(attrib, opt_start, opt_end, char_desc_cb, NULL);

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
	{ "char-desc", 0, 0, G_OPTION_ARG_NONE, &opt_char_desc,
		"Characteristics Descriptor Discovery", NULL },
	{ "listen", 0, 0, G_OPTION_ARG_NONE, &opt_listen,
		"Listen for notifications", NULL },
	{ NULL },
};

static GOptionEntry options[] = {
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
	int ret = 0;

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

	if (opt_primary)
		callback = primary;
	else if (opt_characteristics)
		callback = characteristics;
	else if (opt_char_read)
		callback = characteristics_read;
	else if (opt_char_desc)
		callback = characteristics_desc;
	else {
		gchar *help = g_option_context_get_help(context, TRUE, NULL);
		g_print("%s\n", help);
		g_free(help);
		ret = 1;
		goto done;
	}

	chan = do_connect();
	if (chan == NULL) {
		ret = 1;
		goto done;
	}

	attrib = g_attrib_new(chan);

	event_loop = g_main_loop_new(NULL, FALSE);

	if (opt_listen)
		g_idle_add(listen_start, attrib);

	g_idle_add(callback, attrib);

	g_main_loop_run(event_loop);

	if (listen_watch)
		g_attrib_unregister(attrib, listen_watch);

	g_main_loop_unref(event_loop);

	g_io_channel_unref(chan);
	g_attrib_unref(attrib);

done:
	g_option_context_free(context);
	g_free(opt_src);
	g_free(opt_dst);

	return ret;
}
