/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014 Intel Corporation
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
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "btio/btio.h"
#include "avdtp.h"

static GMainLoop *mainloop = NULL;
static int dev_role = AVDTP_SEP_TYPE_SOURCE;
static bool initiator = false;
static struct avdtp *avdtp = NULL;
struct avdtp_stream *avdtp_stream = NULL;
struct avdtp_local_sep *local_sep = NULL;
struct avdtp_remote_sep *remote_sep = NULL;
static GIOChannel *io = NULL;
static bool reject = false;
static bdaddr_t src;
static bdaddr_t dst;

static guint media_player = 0;
static guint idle_id = 0;

static const char sbc_codec[] = {0x00, 0x00, 0x11, 0x15, 0x02, 0x40};
static const char sbc_media_frame[] = {
	0x00, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x01, 0x9c, 0xfd, 0x40, 0xbd, 0xde, 0xa9, 0x75, 0x43, 0x20, 0x87, 0x64,
	0x44, 0x32, 0x7f, 0xbe, 0xf7, 0x76, 0xfe, 0xf7, 0xbb, 0xbb, 0x7f, 0xbe,
	0xf7, 0x76, 0xfe, 0xf7, 0xbb, 0xbb, 0x7f, 0xbe, 0xf7, 0x76, 0xfe, 0xf7,
	0xbb, 0xbb, 0x80, 0x3e, 0xf7, 0x76, 0xfe, 0xf7, 0xbb, 0xbb, 0x83, 0x41,
	0x07, 0x77, 0x09, 0x07, 0x43, 0xb3, 0x81, 0xbc, 0xf8, 0x77, 0x02, 0xe5,
	0xa4, 0x3a, 0xa0, 0xcb, 0x38, 0xbb, 0x57, 0x90, 0xd9, 0x08, 0x9c, 0x1d,
	0x86, 0x59, 0x01, 0x0c, 0x21, 0x44, 0x68, 0x35, 0xa8, 0x57, 0x97, 0x0e,
	0x9b, 0xbb, 0x62, 0xc4, 0xca, 0x57, 0x04, 0xa1, 0xca, 0x3b, 0xa3, 0x48,
	0xd2, 0x66, 0x11, 0x33, 0x6a, 0x3b, 0xb4, 0xbb, 0x08, 0x77, 0x17, 0x03,
	0xb4, 0x3b, 0x79, 0x3b, 0x46, 0x97, 0x0e, 0xf7, 0x3d, 0xbb, 0x3d, 0x49,
	0x25, 0x86, 0x88, 0xb4, 0xad, 0x3b, 0x62, 0xbb, 0xa4, 0x47, 0x29, 0x99,
	0x3b, 0x3b, 0xaf, 0xc6, 0xd4, 0x37, 0x68, 0x94, 0x0a, 0xbb
	};

static gboolean media_writer(gpointer user_data)
{
	uint16_t omtu;
	int fd;
	int to_write;

	if (!avdtp_stream_get_transport(avdtp_stream, &fd, NULL, &omtu, NULL))
		return TRUE;

	if (omtu < sizeof(sbc_media_frame))
		to_write = omtu;
	else
		to_write = sizeof(sbc_media_frame);

	if (write(fd, sbc_media_frame, to_write))
		return TRUE;

	return TRUE;
}

static bool start_media_player(void)
{
	int fd;
	uint16_t omtu;

	printf("Media streaming started\n");

	if (media_player || !avdtp_stream)
		return false;

	if (!avdtp_stream_get_transport(avdtp_stream, &fd, NULL, &omtu, NULL))
		return false;

	media_player = g_timeout_add(200, media_writer, NULL);
	if (!media_player)
		return false;

	return true;
}

static void stop_media_player(void)
{
	if (!media_player)
		return;

	printf("Media streaming stopped\n");

	g_source_remove(media_player);
	media_player = 0;
}

static void set_configuration_cfm(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					struct avdtp_stream *stream,
					struct avdtp_error *err,
					void *user_data)
{
	printf("%s\n", __func__);

	if (initiator)
		avdtp_open(avdtp, avdtp_stream);
}

static void get_configuration_cfm(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					struct avdtp_stream *stream,
					struct avdtp_error *err,
					void *user_data)
	{
	printf("%s\n", __func__);
}

static void disconnect_cb(void *user_data)
{
	printf("Disconnected\n");

	g_main_loop_quit(mainloop);
}

static void discover_cb(struct avdtp *session, GSList *seps,
				struct avdtp_error *err, void *user_data)
{
	struct avdtp_service_capability *service;
	GSList *caps = NULL;
	int ret;

	remote_sep = avdtp_find_remote_sep(avdtp, local_sep);
	if (!remote_sep) {
		printf("Unable to find matching endpoint\n");
		avdtp_shutdown(session);
		return;
	}

	service = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT, NULL, 0);
	caps = g_slist_append(caps, service);

	service = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, sbc_codec,
							sizeof(sbc_codec));
	caps = g_slist_append(caps, service);

	ret = avdtp_set_configuration(avdtp, remote_sep, local_sep, caps,
								&avdtp_stream);

	g_slist_free_full(caps, g_free);

	if (ret < 0) {
		printf("Failed to set configuration (%s)\n", strerror(-ret));
		avdtp_shutdown(session);
	}
}

static gboolean idle_timeout(gpointer user_data)
{
	int err;

	idle_id = 0;

	err = avdtp_discover(avdtp, discover_cb, NULL);
	if (err < 0) {
		printf("avdtp_discover failed: %s", strerror(-err));
		g_main_loop_quit(mainloop);
	}

	return FALSE;
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	uint16_t imtu, omtu;
	GError *gerr = NULL;
	int fd;

	if (err) {
		printf("%s\n", err->message);
		g_main_loop_quit(mainloop);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_OMTU, &omtu,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (gerr) {
		printf("%s\n", gerr->message);
		g_main_loop_quit(mainloop);
		return;
	}

	fd = g_io_channel_unix_get_fd(chan);

	if (avdtp && avdtp_stream) {
		if (!avdtp_stream_set_transport(avdtp_stream, fd, imtu, omtu)) {
			printf("avdtp_stream_set_transport: failed\n");
			g_main_loop_quit(mainloop);
		}

		g_io_channel_set_close_on_unref(chan, FALSE);

		if (initiator)
			avdtp_start(avdtp, avdtp_stream);

		return;
	}

	/* TODO allow to set version from command line? */
	avdtp = avdtp_new(fd, imtu, omtu, 0x0103);
	if (!avdtp) {
		printf("Failed to create avdtp instance\n");
		g_main_loop_quit(mainloop);
		return;
	}

	avdtp_add_disconnect_cb(avdtp, disconnect_cb, NULL);

	if (initiator) {
		int ret;

		ret = avdtp_discover(avdtp, discover_cb, NULL);
		if (ret < 0) {
			printf("avdtp_discover failed: %s", strerror(-ret));
			g_main_loop_quit(mainloop);
		}
	} else {
		idle_id = g_timeout_add_seconds(1, idle_timeout, NULL);
	}
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	GError *gerr = NULL;

	printf("%s\n", __func__);

	if (!initiator)
		return;

	bt_io_connect(connect_cb, NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, &src,
					BT_IO_OPT_DEST_BDADDR, &dst,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_PSM, AVDTP_PSM,
					BT_IO_OPT_INVALID);
	if (gerr) {
		printf("connect failed: %s\n", gerr->message);
		g_error_free(gerr);
		g_main_loop_quit(mainloop);
	}
}

static void start_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	printf("%s\n", __func__);

	start_media_player();
}

static void suspend_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);

	stop_media_player();
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);

	stop_media_player();
	avdtp_stream = NULL;
}

static void abort_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);

	stop_media_player();
	avdtp_stream = NULL;
}

static void reconfigure_cfm(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream,
				struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);
}

static void delay_report_cfm(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream,
				struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);
}

static struct avdtp_sep_cfm sep_cfm = {
	.set_configuration	= set_configuration_cfm,
	.get_configuration	= get_configuration_cfm,
	.open			= open_cfm,
	.start			= start_cfm,
	.suspend		= suspend_cfm,
	.close			= close_cfm,
	.abort			= abort_cfm,
	.reconfigure		= reconfigure_cfm,
	.delay_report		= delay_report_cfm,
};

static gboolean get_capability_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					GSList **caps, uint8_t *err,
					void *user_data)
{
	struct avdtp_service_capability *service;

	printf("%s\n", __func__);

	if (idle_id > 0) {
		g_source_remove(idle_id);
		idle_id = 0;
	}

	if (reject)
		return FALSE;

	*caps = NULL;

	service = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT, NULL, 0);
	*caps = g_slist_append(*caps, service);

	service = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, sbc_codec,
							sizeof(sbc_codec));
	*caps = g_slist_append(*caps, service);

	return TRUE;
}

static gboolean set_configuration_ind(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					struct avdtp_stream *stream,
					GSList *caps,
					avdtp_set_configuration_cb cb,
					void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	if (idle_id > 0) {
		g_source_remove(idle_id);
		idle_id = 0;
	}

	avdtp_stream = stream;

	cb(session, stream, NULL);

	return TRUE;
}

static gboolean get_configuration_ind(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	return TRUE;
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	return TRUE;
}

static gboolean start_ind(struct avdtp *session, struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	start_media_player();

	return TRUE;
}

static gboolean suspend_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	stop_media_player();

	return TRUE;
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	stop_media_player();
	avdtp_stream = NULL;

	return TRUE;
}

static void abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, uint8_t *err,
			void *user_data)
{
	printf("%s\n", __func__);

	stop_media_player();
	avdtp_stream = NULL;
}

static gboolean reconfigure_ind(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	return TRUE;
}

static gboolean delayreport_ind(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				uint8_t rseid, uint16_t delay,
				uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	if (reject)
		return FALSE;

	return TRUE;
}

static struct avdtp_sep_ind sep_ind = {
	.get_capability		= get_capability_ind,
	.set_configuration	= set_configuration_ind,
	.get_configuration	= get_configuration_ind,
	.open			= open_ind,
	.close			= close_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.abort			= abort_ind,
	.reconfigure		= reconfigure_ind,
	.delayreport		= delayreport_ind,
};

static void usage(void)
{
	printf("avdtptest - AVDTP testing ver %s\n", VERSION);
	printf("Usage:\n"
		"\tavdtptest [options]\n");
	printf("options:\n"
		"\t-d <device_role>   SRC (source) or SINK (sink)\n"
		"\t-s <stream_role>   INT (initiator) or ACP (acceptor)\n"
		"\t-i <hcidev>        HCI adapter\n"
		"\t-c <bdaddr>        connect\n"
		"\t-l                 listen\n"
		"\t-r                 reject commands\n");
}

static struct option main_options[] = {
	{ "help",		0, 0, 'h' },
	{ "device_role",	1, 0, 'd' },
	{ "stream_role",	1, 0, 's' },
	{ "adapter",		1, 0, 'i' },
	{ "connect",		1, 0, 'c' },
	{ "listen",		0, 0, 'l' },
	{ "reject",		0, 0, 'r' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	GError *err = NULL;
	int opt;

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		printf("Failed to create main loop\n");

		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "d:hi:s:c:lr",
						main_options, NULL)) != EOF) {
		switch (opt) {
		case 'i':
			if (!strncmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &src);
			else
				str2ba(optarg, &src);
			break;
		case 'd':
			if (!strncasecmp(optarg, "SRC", sizeof("SRC"))) {
				dev_role = AVDTP_SEP_TYPE_SOURCE;
			} else if (!strncasecmp(optarg, "SINK",
							sizeof("SINK"))) {
				dev_role = AVDTP_SEP_TYPE_SINK;
			} else {
				usage();
				exit(0);
			}
			break;
		case 's':
			if (!strncasecmp(optarg, "INT", sizeof("INT"))) {
				initiator = true;
			} else if (!strncasecmp(optarg, "ACP", sizeof("ACP"))) {
				initiator = false;
			} else {
				usage();
				exit(0);
			}
			break;
		case 'c':
			if (str2ba(optarg, &dst) < 0) {
				usage();
				exit(0);
			}
			break;
		case 'l':
			bacpy(&dst, BDADDR_ANY);
			break;
		case 'r':
			reject = true;
			break;
		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	local_sep = avdtp_register_sep(dev_role, AVDTP_MEDIA_TYPE_AUDIO,
					0x00, FALSE, &sep_ind, &sep_cfm, NULL);
	if (!local_sep) {
		printf("Failed to register sep\n");
		exit(0);
	}

	if (!bacmp(&dst, BDADDR_ANY)) {
		printf("Listening...\n");
		io =  bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &src,
					BT_IO_OPT_PSM, AVDTP_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	} else {
		printf("Connecting...\n");
		io = bt_io_connect(connect_cb, NULL, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &src,
					BT_IO_OPT_DEST_BDADDR, &dst,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_PSM, AVDTP_PSM,
					BT_IO_OPT_INVALID);
	}

	if (!io) {
		printf("Failed: %s\n", err->message);
		g_error_free(err);
		exit(0);
	}

	g_main_loop_run(mainloop);

	printf("Done\n");

	avdtp_unref(avdtp);
	avdtp = NULL;

	g_main_loop_unref(mainloop);
	mainloop = NULL;

	return 0;
}
