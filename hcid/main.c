/* 
	BlueZ - Bluetooth protocol stack for Linux
	Copyright (C) 2000-2001 Qualcomm Incorporated

	Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation;

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
	IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
	OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
	RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
	NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
	USE OR PERFORMANCE OF THIS SOFTWARE.

	ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
	TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/
/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <asm/types.h>

#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>

#include <glib.h>

#include "hcid.h"
#include "lib.h"

#define VERSION "1.1"

struct hcid_opts hcid;
struct device_opts devi;

static GMainLoop *event_loop;

gboolean io_stack_event(GIOChannel *chan, GIOCondition cond, gpointer data);
gboolean io_security_event(GIOChannel *chan, GIOCondition cond, gpointer data);

static void usage(void)
{
	printf("hcid - HCI daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\thcid [-n not_daemon] [-f config file]\n");
}

static void configure_device(int hdev)
{
	struct hci_dev_req dr;
	int s;

	/* Do configuration in the separate process */
	switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "Fork failed. Can't init device hci%d. %s(%d)\n",
					hdev, strerror(errno), errno);
		default:
			return;
	}

	set_title("hci%d config", hdev);

	if ((s = hci_open_dev(hdev)) < 0) {
		syslog(LOG_ERR, "Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	dr.dev_id  = hdev;

	/* Set scan mode */
	dr.dev_opt = devi.scan;
	if (ioctl(s, HCISETSCAN, (unsigned long)&dr) < 0) {
		syslog(LOG_ERR, "Can't set scan mode on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
	}

	/* Set authentication */
	if (devi.auth)
		dr.dev_opt = AUTH_ENABLED;
	else
		dr.dev_opt = AUTH_DISABLED;

	if (ioctl(s, HCISETAUTH, (unsigned long)&dr) < 0) {
		syslog(LOG_ERR, "Can't set auth on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
	}

	/* Set encryption */
	if (devi.encrypt)
		dr.dev_opt = ENCRYPT_P2P;
	else
		dr.dev_opt = ENCRYPT_DISABLED;

	if (ioctl(s, HCISETENCRYPT, (unsigned long)&dr) < 0) {
		syslog(LOG_ERR, "Can't set encrypt on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
	}

        /* Set device class */
	if (devi.class) {
		uint32_t class = htobl(devi.class);
		write_class_of_dev_cp cp;
                
		memcpy(cp.dev_class, &class, 3);
		hci_send_cmd(s, OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
			WRITE_CLASS_OF_DEV_CP_SIZE, (void *) &cp);
	}

	/* Set device name */
	if (devi.name) {
		change_local_name_cp cp;
		expand_name(cp.name, devi.name, hdev);

		hci_send_cmd(s, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
			CHANGE_LOCAL_NAME_CP_SIZE, (void *) &cp);
	}

	exit(0);
}

static void init_device(int hdev)
{
	struct hci_dev_req dr;
	int s;

	/* Do initialization in the separate process */
	switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "Fork failed. Can't init device hci%d. %s(%d)\n", 
					hdev, strerror(errno), errno);
		default:
			return;
	}

	set_title("hci%d init", hdev);

	if ((s = hci_open_dev(hdev)) < 0) {
		syslog(LOG_ERR, "Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	dr.dev_id  = hdev;

	/* Set packet type */
	if (devi.pkt_type) {
		dr.dev_opt = devi.pkt_type;
		if (ioctl(s, HCISETPTYPE, (unsigned long)&dr) < 0) {
			syslog(LOG_ERR, "Can't set packet type on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
		}
	}

	/* Set link mode */
	if (devi.link_mode) {
		dr.dev_opt = devi.link_mode;
		if (ioctl(s, HCISETLINKMODE, (unsigned long)&dr) < 0) {
			syslog(LOG_ERR, "Can't set link mode on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
		}
	}

	/* Set link policy */
	if (devi.link_policy) {
		dr.dev_opt = devi.link_policy;
		if (ioctl(s, HCISETLINKPOL, (unsigned long)&dr) < 0) {
			syslog(LOG_ERR, "Can't set link policy on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
		}
	}

	/* Start HCI device */
	if (ioctl(s, HCIDEVUP, hdev) < 0 && errno != EALREADY) {
		syslog(LOG_ERR, "Can't init device hci%d. %s(%d)\n", hdev, 
				strerror(errno), errno);
		exit(1);
	}

	exit(0);
}

static void init_all_devices(int ctl)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	if (!(dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t)))) {
		syslog(LOG_INFO, "Can't allocate devlist buffer. %s(%d)", 
			strerror(errno), errno);
		exit(1);
	}
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void*)dl)) {
		syslog(LOG_INFO, "Can't get device list. %s(%d)",
			strerror(errno), errno);
		exit(1);
	}

	for (i=0; i < dl->dev_num; i++, dr++) {
		if (hcid.auto_init)
			init_device(dr->dev_id);

		if (hcid.auto_init && (dr->dev_opt & (1<<HCI_UP)))
			configure_device(dr->dev_id);

		if (hcid.security && (dr->dev_opt & (1<<HCI_UP)))
			start_security_manager(dr->dev_id);
	}
	
	free(dl);
}

static void init_defaults(void)
{
	hcid.auto_init = 0;
	hcid.security  = 0;

	devi.pkt_type = 0;
	devi.scan = SCAN_PAGE | SCAN_INQUIRY;
	devi.auth = 0;
	devi.encrypt = 0;
}

static void sig_usr1(int sig)
{
	syslog(LOG_INFO, "Flushing link keys");
	flush_link_keys();
}

static void sig_term(int sig)
{
	syslog(LOG_INFO, "Terminating");
	g_main_quit(event_loop);
	save_link_keys();
}

static void sig_hup(int sig)
{
	syslog(LOG_INFO, "Reloading config file");
	init_defaults();
	if (read_config(hcid.config_file) < 0)
		syslog(LOG_ERR, "Config reload failed");

	init_all_devices(hcid.sock);
}

static inline void device_event(GIOChannel *chan, evt_stack_internal *si)
{
	evt_si_device *sd = (void *) &si->data;

	switch (sd->event) {
	case HCI_DEV_REG:
		syslog(LOG_INFO, "HCI dev %d registered", sd->dev_id);
		if (hcid.auto_init)
			init_device(sd->dev_id);
		break;

	case HCI_DEV_UNREG:
		syslog(LOG_INFO, "HCI dev %d unregistered", sd->dev_id);
		break;

	case HCI_DEV_UP:
		syslog(LOG_INFO, "HCI dev %d up", sd->dev_id);
		if (hcid.auto_init)
			configure_device(sd->dev_id);
		if (hcid.security)
			start_security_manager(sd->dev_id);
		break;

	case HCI_DEV_DOWN:
		syslog(LOG_INFO, "HCI dev %d down", sd->dev_id);
		if (hcid.security)
			stop_security_manager(sd->dev_id);
		break;
	}
}

gboolean io_stack_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	hci_event_hdr *eh;
	int  len, type;
	GIOError err;

	ptr = buf;

	if ((err = g_io_channel_read(chan, buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		syslog(LOG_ERR, "Read from control socket failed. %s(%d)", 
				strerror(errno), errno);
		g_main_quit(event_loop);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	if (eh->evt != EVT_STACK_INTERNAL)
		return TRUE;

	ptr += HCI_EVENT_HDR_SIZE;

	si = (evt_stack_internal *) ptr;
	switch (si->type) {
	case EVT_SI_DEVICE:
		device_event(chan, si);
		break;
	}

	return TRUE;
}

extern int optind,opterr,optopt;
extern char *optarg;

int main(int argc, char *argv[], char *env[])
{
	int daemon, dofork, opt, fd;
	struct sockaddr_hci addr;
	struct hci_filter flt;
	struct sigaction sa;
	GIOChannel *ctl_io;

	daemon = 1; dofork = 1;

	/* Default HCId settings */
	hcid.config_file = HCID_CONFIG_FILE;
	hcid.host_name = get_host_name();

	hcid.pin_file   = strdup(HCID_PIN_FILE);
	hcid.pin_helper = strdup(HCID_PIN_HELPER);
	hcid.key_file   = strdup(HCID_KEY_FILE);
	hcid.key_num    = HCID_KEY_NUM;

	init_defaults();
	
	while ((opt=getopt(argc,argv,"f:n")) != EOF) {
		switch(opt) {
			case 'n':
				daemon = 0;
				break;

			case 'f':
				hcid.config_file = strdup(optarg);
				break;

			default:
				usage();
				exit(1);
		}
	}

	if (daemon) {
		if (dofork && fork())
			exit(0);

		/* Direct stdin,stdout,stderr to '/dev/null' */
		fd = open("/dev/null", O_RDWR);
		dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
		close(fd);

		setsid();

		chdir("/");
	}

        init_title(argc, argv, env, "hcid: ");
	set_title("initializing");

	/* Start logging to syslog and stderr */
	openlog("hcid", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "HCI daemon ver %s started", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = sig_usr1;
	sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	/* Create and bind HCI socket */
	if ((hcid.sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		syslog(LOG_ERR, "Can't open HCI socket. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(hcid.sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_ERR, "Can't set filter. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(hcid.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind HCI socket. %s(%d)\n", strerror(errno), errno);
		exit(1);
	}

	if (read_config(hcid.config_file) < 0)
		syslog(LOG_ERR, "Config load failed");

	/* Create event loop */
	event_loop = g_main_new(FALSE);

	/* Initialize already connected devices */
	init_all_devices(hcid.sock);

	set_title("processing events");

	ctl_io = g_io_channel_unix_new(hcid.sock);
	g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	/* Start event processor */
	g_main_run(event_loop);

	syslog(LOG_INFO, "Exit.");
	return 0;
}
