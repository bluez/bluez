// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  AVRCP 1.6 Cover Art Responder
 *
 *  Copyright (C) 2026  Jan-Michael Brummer <jan.brummer@tabos.org>
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"

#include "gobex/gobex.h"
#include "btio/btio.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"

#include "avctp.h"
#include "avrcp-bip.h"

/* OBEX Target UUID for AVRCP Cover Art (AVRCP 1.6, section 5.14.2.1) */
static const uint8_t cover_art_target_uuid[] = {
	0x71, 0x63, 0xDD, 0x54, 0x4A, 0x7E, 0x11, 0xE2,
	0xB4, 0x7C, 0x00, 0x50, 0xC2, 0x49, 0x00, 0x48
};

/* BIP user defined headers */
#define BIP_HDR_IMG_HANDLE	0x30	/* Unicode text */
#define BIP_HDR_IMG_DESCRIPTOR	0x71	/* Byte sequence */

#define BIP_TYPE_CAPABILITIES	"x-bt/img-capabilities"
#define BIP_TYPE_PROPERTIES	"x-bt/img-properties"
#define BIP_TYPE_IMAGE		"x-bt/img-img"
#define BIP_TYPE_THUMBNAIL	"x-bt/img-thm"

#define COVER_ART_MAX_IMAGES	4

struct cover_image {
	char		handle[8];	/* 7 digit handle + NUL */
	GBytes		*data;
	unsigned int	width;
	unsigned int	height;
};

struct bip_session {
	GObex		*obex;
	GBytes		*pending;	/* image being transferred */
	size_t		offset;
	bool		connected;	/* CONNECT with valid target seen */
	bdaddr_t	src;		/* local adapter address */
	bdaddr_t	dst;		/* peer address */
};

static const uint16_t candidate_psms[] = {
	0x10F1, 0x10F3, 0x10F5, 0x10F7, 0x10F9
};

static GIOChannel *server_io;
static uint16_t server_psm;
static unsigned int server_ref;
static uint32_t next_handle = 1;
static GSList *images;		/* struct cover_image, newest first */
static GSList *sessions;	/* struct bip_session */

static bool session_has_avrcp(struct bip_session *session);

static bool jpeg_get_size(const uint8_t *data, size_t len,
				unsigned int *width, unsigned int *height)
{
	size_t i;

	if (len < 4 || data[0] != 0xff || data[1] != 0xd8)
		return false;

	i = 2;
	while (i + 9 < len) {
		uint8_t marker;
		uint16_t seglen;

		if (data[i] != 0xff) {
			i++;
			continue;
		}

		marker = data[i + 1];

		/* Standalone markers without length field */
		if (marker == 0xff || (marker >= 0xd0 && marker <= 0xd9)) {
			i += 2;
			continue;
		}

		seglen = (data[i + 2] << 8) | data[i + 3];
		if (seglen < 2)
			return false;

		/* SOF0..SOF15 except DHT(C4)/JPG(C8)/DAC(CC) */
		if (marker >= 0xc0 && marker <= 0xcf && marker != 0xc4 &&
				marker != 0xc8 && marker != 0xcc) {
			if (i + 9 >= len)
				return false;
			*height = (data[i + 5] << 8) | data[i + 6];
			*width = (data[i + 7] << 8) | data[i + 8];
			return true;
		}

		i += 2 + seglen;
	}

	return false;
}

static void cover_image_free(void *data)
{
	struct cover_image *img = data;

	g_bytes_unref(img->data);
	g_free(img);
}

static struct cover_image *find_image(const char *handle)
{
	GSList *l;

	for (l = images; l; l = l->next) {
		struct cover_image *img = l->data;

		if (g_str_equal(img->handle, handle))
			return img;
	}

	return NULL;
}

const char *avrcp_bip_set_cover_art(const uint8_t *data, size_t len)
{
	struct cover_image *img;
	unsigned int width = 0, height = 0;

	if (data == NULL || len == 0)
		return NULL;

	if (!jpeg_get_size(data, len, &width, &height)) {
		DBG("cover art is not a valid JPEG image");
		return NULL;
	}

	img = g_new0(struct cover_image, 1);
	snprintf(img->handle, sizeof(img->handle), "%07u",
					next_handle++ % 10000000);
	img->data = g_bytes_new(data, len);
	img->width = width;
	img->height = height;

	images = g_slist_prepend(images, img);

	while (g_slist_length(images) > COVER_ART_MAX_IMAGES) {
		GSList *last = g_slist_last(images);

		cover_image_free(last->data);
		images = g_slist_delete_link(images, last);
	}

	DBG("handle %s (%zu bytes, %ux%u)", img->handle, len, width, height);

	return img->handle;
}

void avrcp_bip_clear_cover_art(void)
{
	g_slist_free_full(images, cover_image_free);
	images = NULL;
}

static void session_free(struct bip_session *session)
{
	sessions = g_slist_remove(sessions, session);

	if (session->pending)
		g_bytes_unref(session->pending);

	if (session->obex)
		g_obex_unref(session->obex);

	g_free(session);
}

static void disconn_func(GObex *obex, GError *err, gpointer user_data)
{
	struct bip_session *session = user_data;

	DBG("BIP session disconnected");

	session_free(session);
}

static char *packet_get_type(GObexPacket *req)
{
	GObexHeader *hdr;
	const guint8 *type;
	gsize len;

	hdr = g_obex_packet_get_header(req, G_OBEX_HDR_TYPE);
	if (hdr == NULL)
		return NULL;

	if (!g_obex_header_get_bytes(hdr, &type, &len) || len == 0)
		return NULL;

	return g_strndup((const char *) type, len);
}

static char *packet_get_img_handle(GObexPacket *req)
{
	GObexHeader *hdr;
	const char *handle;

	hdr = g_obex_packet_get_header(req, BIP_HDR_IMG_HANDLE);
	if (hdr == NULL)
		return NULL;

	if (!g_obex_header_get_unicode(hdr, &handle))
		return NULL;

	return g_strdup(handle);
}

static void connect_func(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct bip_session *session = user_data;
	GObexHeader *hdr;
	const guint8 *target;
	gsize len;
	GError *err = NULL;

	hdr = g_obex_packet_get_header(req, G_OBEX_HDR_TARGET);
	if (hdr == NULL || !g_obex_header_get_bytes(hdr, &target, &len) ||
			len != sizeof(cover_art_target_uuid) ||
			memcmp(target, cover_art_target_uuid, len) != 0) {
		g_obex_send_rsp(obex, G_OBEX_RSP_NOT_ACCEPTABLE, NULL,
							G_OBEX_HDR_INVALID);
		return;
	}

	session->connected = true;

	DBG("Cover Art OBEX session connected");

	/* gobex fills in version/flags/mpl and the Connection ID */
	g_obex_send_rsp(obex, G_OBEX_RSP_SUCCESS, &err,
			G_OBEX_HDR_WHO, cover_art_target_uuid,
			sizeof(cover_art_target_uuid),
			G_OBEX_HDR_INVALID);

	if (err != NULL) {
		error("Cover Art CONNECT rsp: %s", err->message);
		g_error_free(err);
	}
}

static void disconnect_func(GObex *obex, GObexPacket *req, gpointer user_data)
{
	g_obex_send_rsp(obex, G_OBEX_RSP_SUCCESS, NULL, G_OBEX_HDR_INVALID);
}

static gssize pending_data_producer(void *buf, gsize len, gpointer user_data)
{
	struct bip_session *session = user_data;
	gsize size, remaining;
	const uint8_t *data;

	if (session->pending == NULL)
		return 0;

	data = g_bytes_get_data(session->pending, &size);

	if (session->offset >= size)
		remaining = 0;
	else
		remaining = size - session->offset;

	if (remaining == 0) {
		g_bytes_unref(session->pending);
		session->pending = NULL;
		session->offset = 0;
		return 0;
	}

	len = MIN(len, remaining);
	memcpy(buf, data + session->offset, len);
	session->offset += len;

	return len;
}

static void transfer_complete(GObex *obex, GError *err, gpointer user_data)
{
	struct bip_session *session = user_data;

	if (err != NULL)
		DBG("Cover Art transfer failed: %s", err->message);

	if (session->pending) {
		g_bytes_unref(session->pending);
		session->pending = NULL;
	}

	session->offset = 0;
}

static void respond_with_bytes(struct bip_session *session, GBytes *bytes,
							gboolean with_length)
{
	GError *err = NULL;
	gsize size;

	g_bytes_get_data(bytes, &size);

	if (session->pending)
		g_bytes_unref(session->pending);

	session->pending = g_bytes_ref(bytes);
	session->offset = 0;

	if (with_length)
		g_obex_get_rsp(session->obex, pending_data_producer,
				transfer_complete, session, &err,
				G_OBEX_HDR_LENGTH, (guint32) size,
				G_OBEX_HDR_INVALID);
	else
		g_obex_get_rsp(session->obex, pending_data_producer,
				transfer_complete, session, &err,
				G_OBEX_HDR_INVALID);

	if (err != NULL) {
		error("Cover Art GET rsp: %s", err->message);
		g_error_free(err);
		g_bytes_unref(session->pending);
		session->pending = NULL;
	}
}

static void get_image_properties(struct bip_session *session,
						struct cover_image *img)
{
	GString *xml;
	GBytes *bytes;
	gsize size;
	char *str;

	g_bytes_get_data(img->data, &size);

	xml = g_string_new("");
	g_string_append_printf(xml,
		"<image-properties version=\"1.0\" handle=\"%s\">\r\n"
		"<native encoding=\"JPEG\" pixel=\"%u*%u\" size=\"%zu\"/>\r\n"
		"<variant encoding=\"JPEG\" pixel=\"200*200\"/>\r\n"
		"</image-properties>\r\n",
		img->handle, img->width, img->height, size);

	str = g_string_free(xml, FALSE);
	bytes = g_bytes_new_take(str, strlen(str));

	respond_with_bytes(session, bytes, FALSE);
	g_bytes_unref(bytes);
}

static void get_func(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct bip_session *session = user_data;
	struct cover_image *img = NULL;
	char *type, *handle;

	if (!session->connected || !session_has_avrcp(session)) {
		g_obex_send_rsp(obex, G_OBEX_RSP_FORBIDDEN, NULL,
							G_OBEX_HDR_INVALID);
		return;
	}

	type = packet_get_type(req);
	if (type == NULL) {
		g_obex_send_rsp(obex, G_OBEX_RSP_BAD_REQUEST, NULL,
							G_OBEX_HDR_INVALID);
		return;
	}

	handle = packet_get_img_handle(req);

	DBG("type %s handle %s", type, handle ? handle : "(none)");

	if (handle != NULL)
		img = find_image(handle);
	else if (images != NULL)
		img = images->data;	/* newest */

	if (img == NULL) {
		g_obex_send_rsp(obex, G_OBEX_RSP_NOT_FOUND, NULL,
							G_OBEX_HDR_INVALID);
		goto done;
	}

	if (g_str_equal(type, BIP_TYPE_PROPERTIES)) {
		get_image_properties(session, img);
	} else if (g_str_equal(type, BIP_TYPE_THUMBNAIL)) {
		respond_with_bytes(session, img->data, FALSE);
	} else if (g_str_equal(type, BIP_TYPE_IMAGE)) {
		respond_with_bytes(session, img->data, TRUE);
	} else {
		g_obex_send_rsp(obex, G_OBEX_RSP_NOT_IMPLEMENTED, NULL,
							G_OBEX_HDR_INVALID);
	}

done:
	g_free(type);
	g_free(handle);
}

static void bip_connect_cb(GIOChannel *io, GError *gerr, gpointer user_data)
{
	struct bip_session *session;
	GObex *obex;

	if (gerr != NULL) {
		error("Cover Art accept: %s", gerr->message);
		return;
	}

	obex = g_obex_new(io, G_OBEX_TRANSPORT_PACKET, -1, -1);
	if (obex == NULL) {
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	session = g_new0(struct bip_session, 1);
	session->obex = obex;

	bt_io_get(io, NULL, BT_IO_OPT_SOURCE_BDADDR, &session->src,
			BT_IO_OPT_DEST_BDADDR, &session->dst,
			BT_IO_OPT_INVALID);

	sessions = g_slist_prepend(sessions, session);

	g_obex_set_disconnect_function(obex, disconn_func, session);
	g_obex_add_request_function(obex, G_OBEX_OP_CONNECT, connect_func,
								session);
	g_obex_add_request_function(obex, G_OBEX_OP_DISCONNECT,
						disconnect_func, session);
	g_obex_add_request_function(obex, G_OBEX_OP_GET, get_func, session);

	DBG("Cover Art transport connected");
}

static bool session_has_avrcp(struct bip_session *session)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	adapter = adapter_find(&session->src);
	if (adapter == NULL)
		return false;

	device = btd_adapter_find_device(adapter, &session->dst,
								BDADDR_BREDR);
	if (device == NULL || avctp_get(device) == NULL) {
		DBG("Peer has no AVRCP session");
		return false;
	}

	return true;
}

static void bip_confirm_cb(GIOChannel *io, gpointer user_data)
{
	GError *gerr = NULL;

	if (!bt_io_accept(io, bip_connect_cb, NULL, NULL, &gerr)) {
		error("Cover Art bt_io_accept: %s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(io, TRUE, NULL);
	}
}

uint16_t avrcp_bip_server_start(void)
{
	size_t i;

	if (server_io != NULL) {
		server_ref++;
		return server_psm;
	}

	for (i = 0; i < G_N_ELEMENTS(candidate_psms); i++) {
		GError *gerr = NULL;

		server_io = bt_io_listen(NULL, bip_confirm_cb, NULL, NULL,
				&gerr,
				BT_IO_OPT_PSM, candidate_psms[i],
				BT_IO_OPT_MODE, BT_IO_MODE_ERTM,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_INVALID);
		if (server_io != NULL) {
			server_psm = candidate_psms[i];
			break;
		}

		DBG("Cover Art responder PSM 0x%04x: %s",
				candidate_psms[i], gerr->message);
		g_error_free(gerr);
	}

	if (server_io == NULL) {
		error("Cover Art responder: no free PSM");
		return 0;
	}

	server_ref = 1;

	DBG("Cover Art responder listening on PSM 0x%04x", server_psm);

	return server_psm;
}

void avrcp_bip_server_stop(void)
{
	if (server_io == NULL)
		return;

	if (--server_ref > 0)
		return;

	while (sessions != NULL)
		session_free(sessions->data);

	avrcp_bip_clear_cover_art();

	g_io_channel_shutdown(server_io, TRUE, NULL);
	g_io_channel_unref(server_io);
	server_io = NULL;
	server_psm = 0;
}

bool avrcp_bip_server_active(void)
{
	return server_io != NULL;
}

uint16_t avrcp_bip_server_get_psm(void)
{
	return server_psm;
}
