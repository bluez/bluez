/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"

#include "src/shared/util.h"
#include "src/sdpd.h"

struct context {
	GMainLoop *main_loop;
	guint server_source;
	guint client_source;
	int fd;
	const void *req_data;
	size_t req_size;
	const void *rsp_data;
	size_t rsp_size;
};

static void sdp_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	g_print("%s%s\n", prefix, str);
}

void btd_debug(const char *format, ...);

void btd_debug(const char *format, ...)
{
}

void info(const char *format, ...);

void info(const char *format, ...)
{
}

struct btd_adapter;

typedef void (*adapter_cb) (struct btd_adapter *adapter, gpointer user_data);

void adapter_foreach(adapter_cb func, gpointer user_data);

void adapter_foreach(adapter_cb func, gpointer user_data)
{
}

struct btd_adapter *adapter_find(const bdaddr_t *sba);

struct btd_adapter *adapter_find(const bdaddr_t *sba)
{
	return NULL;
}

void adapter_service_insert(struct btd_adapter *adapter, void *rec);

void adapter_service_insert(struct btd_adapter *adapter, void *rec)
{
}

void adapter_service_remove(struct btd_adapter *adapter, void *rec);

void adapter_service_remove(struct btd_adapter *adapter, void *rec)
{
}

static void context_quit(struct context *context)
{
	g_main_loop_quit(context->main_loop);
}

static gboolean server_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	//struct context *context = user_data;
	sdp_pdu_hdr_t hdr;
	void *buf;
	size_t size;
	ssize_t len;
	int fd;

	fd = g_io_channel_unix_get_fd(channel);

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		sdp_svcdb_collect_all(fd);
		return FALSE;
	}

	len = recv(fd, &hdr, sizeof(sdp_pdu_hdr_t), MSG_PEEK);
	if (len != sizeof(sdp_pdu_hdr_t)) {
		sdp_svcdb_collect_all(fd);
		return FALSE;
	}

	size = sizeof(sdp_pdu_hdr_t) + ntohs(hdr.plen);

	buf = malloc(size);
	if (!buf)
		return TRUE;

	len = recv(fd, buf, size, 0);
	if (len <= 0) {
		sdp_svcdb_collect_all(fd);
		free(buf);
		return FALSE;
	}

	if (g_test_verbose() == TRUE)
		util_hexdump('<', buf, len, sdp_debug, "SDP: ");

	handle_request(fd, buf, len);

	return TRUE;
}

static gboolean client_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	unsigned char buf[512];
	ssize_t len;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return FALSE;

	if (g_test_verbose() == TRUE)
		util_hexdump('>', buf, len, sdp_debug, "SDP: ");

	if ((size_t) len != context->rsp_size)
		g_test_fail();
	else if (memcmp(context->rsp_data, buf, len))
		g_test_fail();

	context_quit(context);

	return TRUE;
}

static void update_db_timestamp(void)
{
}

static void register_serial_port(void)
{
	sdp_list_t *svclass_id, *apseq, *proto[2], *profiles, *root, *aproto;
	uuid_t root_uuid, sp_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	uint8_t u8 = 1;
	sdp_data_t *sdp_data, *channel;
	sdp_record_t *record = sdp_record_alloc();

	record->handle = sdp_next_handle();

	sdp_record_add(BDADDR_ANY, record);
	sdp_data = sdp_data_alloc(SDP_UINT32, &record->handle);
	sdp_attr_add(record, SDP_ATTR_RECORD_HANDLE, sdp_data);

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, 0);

	sdp_uuid16_create(&sp_uuid, SERIAL_PORT_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &sp_uuid);
	sdp_set_service_classes(record, svclass_id);
	sdp_list_free(svclass_id, 0);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, profiles);
	sdp_list_free(profiles, 0);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_add_lang_attr(record);

	sdp_set_info_attr(record, "Serial Port", "BlueZ", "COM Port");

	sdp_set_url_attr(record, "http://www.bluez.org/",
			"http://www.bluez.org/", "http://www.bluez.org/");

	sdp_set_service_id(record, sp_uuid);
	sdp_set_service_ttl(record, 0xffff);
	sdp_set_service_avail(record, 0xff);
	sdp_set_record_state(record, 0x00001234);

	update_db_timestamp();
}

static void register_object_push(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, opush_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	uint8_t chan = 9;
	sdp_data_t *channel;
	uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
	void *dtds[sizeof(formats)], *values[sizeof(formats)];
	unsigned int i;
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sdp_data, *sflist;
	sdp_record_t *record = sdp_record_alloc();

	record->handle = sdp_next_handle();

	sdp_record_add(BDADDR_ANY, record);
	sdp_data = sdp_data_alloc(SDP_UINT32, &record->handle);
	sdp_attr_add(record, SDP_ATTR_RECORD_HANDLE, sdp_data);

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&opush_uuid, OBEX_OBJPUSH_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &opush_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_OBJPUSH_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	for (i = 0; i < sizeof(formats); i++) {
		dtds[i] = &dtd;
		values[i] = &formats[i];
	}
	sflist = sdp_seq_alloc(dtds, values, sizeof(formats));
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FORMATS_LIST, sflist);

	sdp_set_info_attr(record, "OBEX Object Push", 0, 0);

	update_db_timestamp();
}

static void register_hid_keyboard(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, hidkb_uuid, l2cap_uuid, hidp_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *psm, *lang_lst, *lang_lst2, *hid_spec_lst, *hid_spec_lst2;
	unsigned int i;
	uint8_t dtd = SDP_UINT16;
	uint8_t dtd2 = SDP_UINT8;
	uint8_t dtd_data = SDP_TEXT_STR8;
	void *dtds[2];
	void *values[2];
	void *dtds2[2];
	void *values2[2];
	int leng[2];
	uint8_t hid_spec_type = 0x22;
	uint16_t hid_attr_lang[] = { 0x409, 0x100 };
	static const uint16_t ctrl = 0x11;
	static const uint16_t intr = 0x13;
	static const uint16_t hid_attr[] = { 0x100, 0x111, 0x40, 0x0d,
								0x01, 0x01 };
	static const uint16_t hid_attr2[] = { 0x0, 0x01, 0x100, 0x1f40,
								0x01, 0x01 };
	const uint8_t hid_spec[] = {
		0x05, 0x01, // usage page
		0x09, 0x06, // keyboard
		0xa1, 0x01, // key codes
		0x85, 0x01, // minimum
		0x05, 0x07, // max
		0x19, 0xe0, // logical min
		0x29, 0xe7, // logical max
		0x15, 0x00, // report size
		0x25, 0x01, // report count
		0x75, 0x01, // input data variable absolute
		0x95, 0x08, // report count
		0x81, 0x02, // report size
		0x75, 0x08,
		0x95, 0x01,
		0x81, 0x01,
		0x75, 0x01,
		0x95, 0x05,
		0x05, 0x08,
		0x19, 0x01,
		0x29, 0x05,
		0x91, 0x02,
		0x75, 0x03,
		0x95, 0x01,
		0x91, 0x01,
		0x75, 0x08,
		0x95, 0x06,
		0x15, 0x00,
		0x26, 0xff,
		0x00, 0x05,
		0x07, 0x19,
		0x00, 0x2a,
		0xff, 0x00,
		0x81, 0x00,
		0x75, 0x01,
		0x95, 0x01,
		0x15, 0x00,
		0x25, 0x01,
		0x05, 0x0c,
		0x09, 0xb8,
		0x81, 0x06,
		0x09, 0xe2,
		0x81, 0x06,
		0x09, 0xe9,
		0x81, 0x02,
		0x09, 0xea,
		0x81, 0x02,
		0x75, 0x01,
		0x95, 0x04,
		0x81, 0x01,
		0xc0         // end tag
	};
	sdp_data_t *sdp_data;
	sdp_record_t *record = sdp_record_alloc();

	record->handle = sdp_next_handle();

	sdp_record_add(BDADDR_ANY, record);
	sdp_data = sdp_data_alloc(SDP_UINT32, &record->handle);
	sdp_attr_add(record, SDP_ATTR_RECORD_HANDLE, sdp_data);

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_add_lang_attr(record);

	sdp_uuid16_create(&hidkb_uuid, HID_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &hidkb_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, HID_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, profile);
	sdp_set_profile_descs(record, pfseq);

	/* protocols */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[1] = sdp_list_append(0, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &ctrl);
	proto[1] = sdp_list_append(proto[1], psm);
	apseq = sdp_list_append(0, proto[1]);

	sdp_uuid16_create(&hidp_uuid, HIDP_UUID);
	proto[2] = sdp_list_append(0, &hidp_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* additional protocols */
	proto[1] = sdp_list_append(0, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &intr);
	proto[1] = sdp_list_append(proto[1], psm);
	apseq = sdp_list_append(0, proto[1]);

	sdp_uuid16_create(&hidp_uuid, HIDP_UUID);
	proto[2] = sdp_list_append(0, &hidp_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_add_access_protos(record, aproto);

	sdp_set_info_attr(record, "HID Keyboard", NULL, NULL);

	for (i = 0; i < sizeof(hid_attr) / 2; i++)
		sdp_attr_add_new(record,
				SDP_ATTR_HID_DEVICE_RELEASE_NUMBER + i,
				SDP_UINT16, &hid_attr[i]);

	dtds[0] = &dtd2;
	values[0] = &hid_spec_type;
	dtds[1] = &dtd_data;
	values[1] = (uint8_t *) hid_spec;
	leng[0] = 0;
	leng[1] = sizeof(hid_spec);
	hid_spec_lst = sdp_seq_alloc_with_length(dtds, values, leng, 2);
	hid_spec_lst2 = sdp_data_alloc(SDP_SEQ8, hid_spec_lst);
	sdp_attr_add(record, SDP_ATTR_HID_DESCRIPTOR_LIST, hid_spec_lst2);

	for (i = 0; i < sizeof(hid_attr_lang) / 2; i++) {
		dtds2[i] = &dtd;
		values2[i] = &hid_attr_lang[i];
	}

	lang_lst = sdp_seq_alloc(dtds2, values2, sizeof(hid_attr_lang) / 2);
	lang_lst2 = sdp_data_alloc(SDP_SEQ8, lang_lst);
	sdp_attr_add(record, SDP_ATTR_HID_LANG_ID_BASE_LIST, lang_lst2);

	sdp_attr_add_new(record, SDP_ATTR_HID_SDP_DISABLE,
						SDP_UINT16, &hid_attr2[0]);

	for (i = 0; i < sizeof(hid_attr2) / 2 - 1; i++)
		sdp_attr_add_new(record, SDP_ATTR_HID_REMOTE_WAKEUP + i,
						SDP_UINT16, &hid_attr2[i + 1]);

	update_db_timestamp();
}

static void register_file_transfer(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, ftrn_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	uint8_t u8 = 10;
	sdp_data_t *sdp_data, *channel;
	sdp_record_t *record = sdp_record_alloc();

	record->handle = sdp_next_handle();

	sdp_record_add(BDADDR_ANY, record);
	sdp_data = sdp_data_alloc(SDP_UINT32, &record->handle);
	sdp_attr_add(record, SDP_ATTR_RECORD_HANDLE, sdp_data);

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&ftrn_uuid, OBEX_FILETRANS_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &ftrn_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_FILETRANS_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "OBEX File Transfer", 0, 0);

	update_db_timestamp();
}

static struct context *create_context(void)
{
	struct context *context = g_new0(struct context, 1);
	GIOChannel *channel;
	int err, sv[2];

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	channel = g_io_channel_unix_new(sv[0]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->server_source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				server_handler, context);
	g_assert(context->server_source > 0);

	g_io_channel_unref(channel);

	channel = g_io_channel_unix_new(sv[1]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->client_source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				client_handler, context);
	g_assert(context->client_source > 0);

	g_io_channel_unref(channel);

	context->fd = sv[1];

	register_public_browse_group();
	register_server_service();

	register_serial_port();
	register_object_push();
	register_hid_keyboard();
	register_file_transfer();
	register_file_transfer();
	register_file_transfer();
	register_file_transfer();
	register_file_transfer();

	return context;
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	sdp_svcdb_collect_all(context->fd);
	sdp_svcdb_reset();

	g_source_remove(context->server_source);
	g_source_remove(context->client_source);

	g_main_loop_unref(context->main_loop);

	g_free(context);
}

struct test_data {
	const void *req_data;
	size_t req_size;
	const void *rsp_data;
	size_t rsp_size;
};

static gboolean send_pdu(gpointer user_data)
{
	struct context *context = user_data;

	write(context->fd, context->req_data, context->req_size);

	return FALSE;
}

static void test_sdp(gconstpointer data)
{
	const struct test_data *test = data;
	struct context *context = create_context();

	context->req_data = test->req_data;
	context->req_size = test->req_size;
	context->rsp_data = test->rsp_data;
	context->rsp_size = test->rsp_size;

	g_idle_add(send_pdu, context);

	execute_context(context);
}

#define makepdu(args...) (const unsigned char[]) { args }

#define sdp_test(name, req, rsp) \
	do {								\
		static const unsigned char req_data[] = req;		\
		static const unsigned char rsp_data[] = rsp;		\
		static const struct test_data test_data = {		\
			.req_data = req_data,				\
			.req_size = sizeof(req_data),			\
			.rsp_data = rsp_data,				\
			.rsp_size = sizeof(rsp_data),			\
		};							\
		g_test_add_data_func(name, &test_data, test_sdp);	\
	} while (0)

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	/* Service Search Request
	 *
	 * Verify the correct behaviour of the IUT when searching for
	 * existing service(s).
	 */
	sdp_test("/TP/SERVER/SS/BV-01-C/UUID-128",
		makepdu(0x02, 0x00, 0x01, 0x00, 0x16, 0x35, 0x11, 0x1c,
			0x00, 0x00, 0x11, 0x05, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
			0x00, 0x01, 0x00),
		makepdu(0x03, 0x00, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x01, 0x00));
	sdp_test("/TP/SERVER/SS/BV-01-C/UUID-16",
		makepdu(0x02, 0x00, 0x01, 0x00, 0x08, 0x35, 0x03, 0x19,
			0x11, 0x05, 0x00, 0x01, 0x00),
		makepdu(0x03, 0x00, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x01, 0x00));
	sdp_test("/TP/SERVER/SS/BV-01-C/UUID-32",
		makepdu(0x02, 0x00, 0x01, 0x00, 0x0a, 0x35, 0x05, 0x1a,
			0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00),
		makepdu(0x03, 0x00, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x00, 0x00));

	return g_test_run();
}
