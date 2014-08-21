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
static GIOChannel *io = NULL;

static void set_configuration_cfm(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					struct avdtp_stream *stream,
					struct avdtp_error *err,
					void *user_data)
{
	printf("%s\n", __func__);
}

static void get_configuration_cfm(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					struct avdtp_stream *stream,
					struct avdtp_error *err,
					void *user_data)
	{
	printf("%s\n", __func__);
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	printf("%s\n", __func__);
}

static void start_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	printf("%s\n", __func__);
}

static void suspend_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);

	avdtp_stream = NULL;
}

static void abort_cfm(struct avdtp *session, struct avdtp_local_sep *lsep,
			struct avdtp_stream *stream,
			struct avdtp_error *err, void *user_data)
{
	printf("%s\n", __func__);

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

static const char sbc_codec[] = {0x00, 0x00, 0xff, 0xff, 0x02, 0x40};

static gboolean get_capability_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					GSList **caps, uint8_t *err,
					void *user_data)
{
	struct avdtp_service_capability *service;

	printf("%s\n", __func__);

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

	avdtp_stream = stream;

	cb(session, stream, NULL);

	return TRUE;
}

static gboolean get_configuration_ind(struct avdtp *session,
					struct avdtp_local_sep *lsep,
					uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	return TRUE;
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	return TRUE;
}

static gboolean start_ind(struct avdtp *session, struct avdtp_local_sep *lsep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	return TRUE;
}

static gboolean suspend_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	return FALSE;
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	printf("%s\n", __func__);

	return FALSE;
}

static void abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, uint8_t *err,
			void *user_data)
{
	printf("%s\n", __func__);
}

static gboolean reconfigure_ind(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	return FALSE;
}

static gboolean delayreport_ind(struct avdtp *session,
				struct avdtp_local_sep *lsep,
				uint8_t rseid, uint16_t delay,
				uint8_t *err, void *user_data)
{
	printf("%s\n", __func__);

	return FALSE;
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

static void disconnect_cb(void *user_data)
{
	printf("Disconnected\n");

	g_main_loop_quit(mainloop);
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

	/* TODO handle initiator */
}

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
		"\t-l                 listen\n");
}

static struct option main_options[] = {
	{ "help",		0, 0, 'h' },
	{ "device_role",	1, 0, 'd' },
	{ "stream_role",	1, 0, 's' },
	{ "adapter",		1, 0, 'i' },
	{ "connect",		1, 0, 'c' },
	{ "listen",		0, 0, 'l' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	GError *err = NULL;
	bdaddr_t src, dst;
	int opt;

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		printf("Failed to create main loop\n");

		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "d:hi:s:c:l",
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
