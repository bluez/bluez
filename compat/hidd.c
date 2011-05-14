/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/hidp.h>

#include "sdp.h"
#include "hidd.h"

#ifdef NEED_PPOLL
#include "ppoll.h"
#endif

enum {
	NONE,
	SHOW,
	SERVER,
	SEARCH,
	CONNECT,
	KILL
};

static volatile sig_atomic_t __io_canceled = 0;

static void sig_hup(int sig)
{
}

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static int l2cap_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk;

	if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family  = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	opts.imtu = HIDP_DEFAULT_MTU;
	opts.omtu = HIDP_DEFAULT_MTU;
	opts.flush_to = 0xffff;

	setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts));

	memset(&addr, 0, sizeof(addr));
	addr.l2_family  = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

static int l2cap_listen(const bdaddr_t *bdaddr, unsigned short psm, int lm, int backlog)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk;

	if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, bdaddr);
	addr.l2_psm = htobs(psm);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	setsockopt(sk, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm));

	memset(&opts, 0, sizeof(opts));
	opts.imtu = HIDP_DEFAULT_MTU;
	opts.omtu = HIDP_DEFAULT_MTU;
	opts.flush_to = 0xffff;

	setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts));

	if (listen(sk, backlog) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

static int l2cap_accept(int sk, bdaddr_t *bdaddr)
{
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	int nsk;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if ((nsk = accept(sk, (struct sockaddr *) &addr, &addrlen)) < 0)
		return -1;

	if (bdaddr)
		bacpy(bdaddr, &addr.l2_bdaddr);

	return nsk;
}

static int request_authentication(bdaddr_t *src, bdaddr_t *dst)
{
	struct hci_conn_info_req *cr;
	char addr[18];
	int err, dd, dev_id;

	ba2str(src, addr);
	dev_id = hci_devid(addr);
	if (dev_id < 0)
		return dev_id;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return dd;

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr)
		return -ENOMEM;

	bacpy(&cr->bdaddr, dst);
	cr->type = ACL_LINK;
	err = ioctl(dd, HCIGETCONNINFO, (unsigned long) cr);
	if (err < 0) {
		free(cr);
		hci_close_dev(dd);
		return err;
	}

	err = hci_authenticate_link(dd, htobs(cr->conn_info->handle), 25000);

	free(cr);
	hci_close_dev(dd);

	return err;
}

static int request_encryption(bdaddr_t *src, bdaddr_t *dst)
{
	struct hci_conn_info_req *cr;
	char addr[18];
	int err, dd, dev_id;

	ba2str(src, addr);
	dev_id = hci_devid(addr);
	if (dev_id < 0)
		return dev_id;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return dd;

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr)
		return -ENOMEM;

	bacpy(&cr->bdaddr, dst);
	cr->type = ACL_LINK;
	err = ioctl(dd, HCIGETCONNINFO, (unsigned long) cr);
	if (err < 0) {
		free(cr);
		hci_close_dev(dd);
		return err;
	}

	err = hci_encrypt_link(dd, htobs(cr->conn_info->handle), 1, 25000);

	free(cr);
	hci_close_dev(dd);

	return err;
}

static int enable_sixaxis(int csk)
{
	const unsigned char buf[] = {
		0x53 /*HIDP_TRANS_SET_REPORT | HIDP_DATA_RTYPE_FEATURE*/,
		0xf4,  0x42, 0x03, 0x00, 0x00 };

	return write(csk, buf, sizeof(buf));
}

static int create_device(int ctl, int csk, int isk, uint8_t subclass, int nosdp, int nocheck, int bootonly, int encrypt, int timeout)
{
	struct hidp_connadd_req req;
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	bdaddr_t src, dst;
	char bda[18];
	int err;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getsockname(csk, (struct sockaddr *) &addr, &addrlen) < 0)
		return -1;

	bacpy(&src, &addr.l2_bdaddr);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getpeername(csk, (struct sockaddr *) &addr, &addrlen) < 0)
		return -1;

	bacpy(&dst, &addr.l2_bdaddr);

	memset(&req, 0, sizeof(req));
	req.ctrl_sock = csk;
	req.intr_sock = isk;
	req.flags     = 0;
	req.idle_to   = timeout * 60;

	err = get_stored_device_info(&src, &dst, &req);
	if (!err)
		goto create;

	if (!nocheck) {
		ba2str(&dst, bda);
		syslog(LOG_ERR, "Rejected connection from unknown device %s", bda);
		/* Return no error to avoid run_server() complaining too */
		return 0;
	}

	if (!nosdp) {
		err = get_sdp_device_info(&src, &dst, &req);
		if (err < 0)
			goto error;
	} else {
		struct l2cap_conninfo conn;
		socklen_t size;
		uint8_t class[3];

		memset(&conn, 0, sizeof(conn));
		size = sizeof(conn);
		if (getsockopt(csk, SOL_L2CAP, L2CAP_CONNINFO, &conn, &size) < 0)
			memset(class, 0, 3);
		else
			memcpy(class, conn.dev_class, 3);

		if (class[1] == 0x25 && (class[2] == 0x00 || class[2] == 0x01))
			req.subclass = class[0];
		else
			req.subclass = 0xc0;
	}

create:
	if (subclass != 0x00)
		req.subclass = subclass;

	ba2str(&dst, bda);
	syslog(LOG_INFO, "New HID device %s (%s)", bda, req.name);

	if (encrypt && (req.subclass & 0x40)) {
		err = request_authentication(&src, &dst);
		if (err < 0) {
			syslog(LOG_ERR, "Authentication for %s failed", bda);
			goto error;
		}

		err = request_encryption(&src, &dst);
		if (err < 0)
			syslog(LOG_ERR, "Encryption for %s failed", bda);
	}

	if (bootonly) {
		req.rd_size = 0;
		req.flags |= (1 << HIDP_BOOT_PROTOCOL_MODE);
	}

	if (req.vendor == 0x054c && req.product == 0x0268)
		enable_sixaxis(csk);

	err = ioctl(ctl, HIDPCONNADD, &req);

error:
	free(req.rd_data);

	return err;
}

static void run_server(int ctl, int csk, int isk, uint8_t subclass, int nosdp, int nocheck, int bootonly, int encrypt, int timeout)
{
	struct pollfd p[2];
	sigset_t sigs;
	short events;
	int err, ncsk, nisk;

	sigfillset(&sigs);
	sigdelset(&sigs, SIGCHLD);
	sigdelset(&sigs, SIGPIPE);
	sigdelset(&sigs, SIGTERM);
	sigdelset(&sigs, SIGINT);
	sigdelset(&sigs, SIGHUP);

	p[0].fd = csk;
	p[0].events = POLLIN | POLLERR | POLLHUP;

	p[1].fd = isk;
	p[1].events = POLLIN | POLLERR | POLLHUP;

	while (!__io_canceled) {
		p[0].revents = 0;
		p[1].revents = 0;

		if (ppoll(p, 2, NULL, &sigs) < 1)
			continue;

		events = p[0].revents | p[1].revents;

		if (events & POLLIN) {
			ncsk = l2cap_accept(csk, NULL);
			nisk = l2cap_accept(isk, NULL);

			err = create_device(ctl, ncsk, nisk, subclass, nosdp, nocheck, bootonly, encrypt, timeout);
			if (err < 0)
				syslog(LOG_ERR, "HID create error %d (%s)",
						errno, strerror(errno));

			close(nisk);
			sleep(1);
			close(ncsk);
		}
	}
}

static char *hidp_state[] = {
	"unknown",
	"connected",
	"open",
	"bound",
	"listening",
	"connecting",
	"connecting",
	"config",
	"disconnecting",
	"closed"
};

static char *hidp_flagstostr(uint32_t flags)
{
	static char str[100];
	str[0] = 0;

	strcat(str, "[");

	if (flags & (1 << HIDP_BOOT_PROTOCOL_MODE))
		strcat(str, "boot-protocol");

	strcat(str, "]");

	return str;
}

static void do_show(int ctl)
{
	struct hidp_connlist_req req;
	struct hidp_conninfo ci[16];
	char addr[18];
	unsigned int i;

	req.cnum = 16;
	req.ci   = ci;

	if (ioctl(ctl, HIDPGETCONNLIST, &req) < 0) {
		perror("Can't get connection list");
		close(ctl);
		exit(1);
	}

	for (i = 0; i < req.cnum; i++) {
		ba2str(&ci[i].bdaddr, addr);
		printf("%s %s [%04x:%04x] %s %s\n", addr, ci[i].name,
			ci[i].vendor, ci[i].product, hidp_state[ci[i].state],
			ci[i].flags ? hidp_flagstostr(ci[i].flags) : "");
	}
}

static void do_connect(int ctl, bdaddr_t *src, bdaddr_t *dst, uint8_t subclass, int fakehid, int bootonly, int encrypt, int timeout)
{
	struct hidp_connadd_req req;
	uint16_t uuid = HID_SVCLASS_ID;
	uint8_t channel = 0;
	char name[256];
	int csk, isk, err;

	memset(&req, 0, sizeof(req));
	name[0] = '\0';

	err = get_sdp_device_info(src, dst, &req);
	if (err < 0 && fakehid)
		err = get_alternate_device_info(src, dst,
				&uuid, &channel, name, sizeof(name) - 1);

	if (err < 0) {
		perror("Can't get device information");
		close(ctl);
		exit(1);
	}

	switch (uuid) {
	case HID_SVCLASS_ID:
		goto connect;

	case SERIAL_PORT_SVCLASS_ID:
		if (subclass == 0x40 || !strcmp(name, "Cable Replacement")) {
			if (epox_presenter(src, dst, channel) < 0) {
				close(ctl);
				exit(1);
			}
			break;
		}
		if (subclass == 0x1f || !strcmp(name, "SPP slave")) {
			if (jthree_keyboard(src, dst, channel) < 0) {
				close(ctl);
				exit(1);
			}
			break;
		}
		if (subclass == 0x02 || !strcmp(name, "Serial Port")) {
			if (celluon_keyboard(src, dst, channel) < 0) {
				close(ctl);
				exit(1);
			}
			break;
		}
		break;

	case HEADSET_SVCLASS_ID:
	case HANDSFREE_SVCLASS_ID:
		if (headset_presenter(src, dst, channel) < 0) {
			close(ctl);
			exit(1);
		}
		break;
	}

	return;

connect:
	csk = l2cap_connect(src, dst, L2CAP_PSM_HIDP_CTRL);
	if (csk < 0) {
		perror("Can't create HID control channel");
		close(ctl);
		exit(1);
	}

	isk = l2cap_connect(src, dst, L2CAP_PSM_HIDP_INTR);
	if (isk < 0) {
		perror("Can't create HID interrupt channel");
		close(csk);
		close(ctl);
		exit(1);
	}

	err = create_device(ctl, csk, isk, subclass, 1, 1, bootonly, encrypt, timeout);
	if (err < 0) {
		fprintf(stderr, "HID create error %d (%s)\n",
						errno, strerror(errno));
		close(isk);
		sleep(1);
		close(csk);
		close(ctl);
		exit(1);
	}
}

static void do_search(int ctl, bdaddr_t *bdaddr, uint8_t subclass, int fakehid, int bootonly, int encrypt, int timeout)
{
	inquiry_info *info = NULL;
	bdaddr_t src, dst;
	int i, dev_id, num_rsp, length, flags;
	char addr[18];
	uint8_t class[3];

	ba2str(bdaddr, addr);
	dev_id = hci_devid(addr);
	if (dev_id < 0) {
		dev_id = hci_get_route(NULL);
		hci_devba(dev_id, &src);
	} else
		bacpy(&src, bdaddr);

	length  = 8;	/* ~10 seconds */
	num_rsp = 0;
	flags   = IREQ_CACHE_FLUSH;

	printf("Searching ...\n");

	num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);

	for (i = 0; i < num_rsp; i++) {
		memcpy(class, (info+i)->dev_class, 3);
		if (class[1] == 0x25 && (class[2] == 0x00 || class[2] == 0x01)) {
			bacpy(&dst, &(info+i)->bdaddr);
			ba2str(&dst, addr);

			printf("\tConnecting to device %s\n", addr);
			do_connect(ctl, &src, &dst, subclass, fakehid, bootonly, encrypt, timeout);
		}
	}

	if (!fakehid)
		goto done;

	for (i = 0; i < num_rsp; i++) {
		memcpy(class, (info+i)->dev_class, 3);
		if ((class[0] == 0x00 && class[2] == 0x00 &&
				(class[1] == 0x40 || class[1] == 0x1f)) ||
				(class[0] == 0x10 && class[1] == 0x02 && class[2] == 0x40)) {
			bacpy(&dst, &(info+i)->bdaddr);
			ba2str(&dst, addr);

			printf("\tConnecting to device %s\n", addr);
			do_connect(ctl, &src, &dst, subclass, 1, bootonly, 0, timeout);
		}
	}

done:
	bt_free(info);

	if (!num_rsp) {
		fprintf(stderr, "\tNo devices in range or visible\n");
		close(ctl);
		exit(1);
	}
}

static void do_kill(int ctl, bdaddr_t *bdaddr, uint32_t flags)
{
	struct hidp_conndel_req req;
	struct hidp_connlist_req cl;
	struct hidp_conninfo ci[16];
	unsigned int i;

	if (!bacmp(bdaddr, BDADDR_ALL)) {
		cl.cnum = 16;
		cl.ci   = ci;

		if (ioctl(ctl, HIDPGETCONNLIST, &cl) < 0) {
			perror("Can't get connection list");
			close(ctl);
			exit(1);
		}

		for (i = 0; i < cl.cnum; i++) {
			bacpy(&req.bdaddr, &ci[i].bdaddr);
			req.flags = flags;

			if (ioctl(ctl, HIDPCONNDEL, &req) < 0) {
				perror("Can't release connection");
				close(ctl);
				exit(1);
			}
		}

	} else {
		bacpy(&req.bdaddr, bdaddr);
		req.flags = flags;

		if (ioctl(ctl, HIDPCONNDEL, &req) < 0) {
			perror("Can't release connection");
			close(ctl);
			exit(1);
		}
	}
}

static void usage(void)
{
	printf("hidd - Bluetooth HID daemon version %s\n\n", VERSION);

	printf("Usage:\n"
		"\thidd [options] [commands]\n"
		"\n");

	printf("Options:\n"
		"\t-i <hciX|bdaddr>     Local HCI device or BD Address\n"
		"\t-t <timeout>         Set idle timeout (in minutes)\n"
		"\t-b <subclass>        Overwrite the boot mode subclass\n"
		"\t-n, --nodaemon       Don't fork daemon to background\n"
		"\t-h, --help           Display help\n"
		"\n");

	printf("Commands:\n"
		"\t--server             Start HID server\n"
		"\t--search             Search for HID devices\n"
		"\t--connect <bdaddr>   Connect remote HID device\n"
		"\t--unplug <bdaddr>    Unplug the HID connection\n"
		"\t--kill <bdaddr>      Terminate HID connection\n"
		"\t--killall            Terminate all connections\n"
		"\t--show               List current HID connections\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "nodaemon",	0, 0, 'n' },
	{ "subclass",	1, 0, 'b' },
	{ "timeout",	1, 0, 't' },
	{ "device",	1, 0, 'i' },
	{ "master",	0, 0, 'M' },
	{ "encrypt",	0, 0, 'E' },
	{ "nosdp",	0, 0, 'D' },
	{ "nocheck",	0, 0, 'Z' },
	{ "bootonly",	0, 0, 'B' },
	{ "hidonly",	0, 0, 'H' },
	{ "show",	0, 0, 'l' },
	{ "list",	0, 0, 'l' },
	{ "server",	0, 0, 'd' },
	{ "listen",	0, 0, 'd' },
	{ "search",	0, 0, 's' },
	{ "create",	1, 0, 'c' },
	{ "connect",	1, 0, 'c' },
	{ "disconnect",	1, 0, 'k' },
	{ "terminate",	1, 0, 'k' },
	{ "release",	1, 0, 'k' },
	{ "kill",	1, 0, 'k' },
	{ "killall",	0, 0, 'K' },
	{ "unplug",	1, 0, 'u' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	bdaddr_t bdaddr, dev;
	uint32_t flags = 0;
	uint8_t subclass = 0x00;
	char addr[18];
	int log_option = LOG_NDELAY | LOG_PID;
	int opt, ctl, csk, isk;
	int mode = SHOW, detach = 1, nosdp = 0, nocheck = 0, bootonly = 0;
	int fakehid = 1, encrypt = 0, timeout = 30, lm = 0;

	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt = getopt_long(argc, argv, "+i:nt:b:MEDZBHldsc:k:Ku:h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;
		case 'n':
			detach = 0;
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'b':
			if (!strncasecmp(optarg, "0x", 2))
				subclass = (uint8_t) strtol(optarg, NULL, 16);
			else
				subclass = atoi(optarg);
			break;
		case 'M':
			lm |= L2CAP_LM_MASTER;
			break;
		case 'E':
			encrypt = 1;
			break;
		case 'D':
			nosdp = 1;
			break;
		case 'Z':
			nocheck = 1;
			break;
		case 'B':
			bootonly = 1;
			break;
		case 'H':
			fakehid = 0;
			break;
		case 'l':
			mode = SHOW;
			break;
		case 'd':
			mode = SERVER;
			break;
		case 's':
			mode = SEARCH;
			break;
		case 'c':
			str2ba(optarg, &dev);
			mode = CONNECT;
			break;
		case 'k':
			str2ba(optarg, &dev);
			mode = KILL;
			break;
		case 'K':
			bacpy(&dev, BDADDR_ALL);
			mode = KILL;
			break;
		case 'u':
			str2ba(optarg, &dev);
			flags = (1 << HIDP_VIRTUAL_CABLE_UNPLUG);
			mode = KILL;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			exit(0);
		}
	}

	ba2str(&bdaddr, addr);

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		perror("Can't open HIDP control socket");
		exit(1);
	}

	switch (mode) {
	case SERVER:
		csk = l2cap_listen(&bdaddr, L2CAP_PSM_HIDP_CTRL, lm, 10);
		if (csk < 0) {
			perror("Can't listen on HID control channel");
			close(ctl);
			exit(1);
		}

		isk = l2cap_listen(&bdaddr, L2CAP_PSM_HIDP_INTR, lm, 10);
		if (isk < 0) {
			perror("Can't listen on HID interrupt channel");
			close(ctl);
			close(csk);
			exit(1);
		}
		break;

	case SEARCH:
		do_search(ctl, &bdaddr, subclass, fakehid, bootonly, encrypt, timeout);
		close(ctl);
		exit(0);

	case CONNECT:
		do_connect(ctl, &bdaddr, &dev, subclass, fakehid, bootonly, encrypt, timeout);
		close(ctl);
		exit(0);

	case KILL:
		do_kill(ctl, &dev, flags);
		close(ctl);
		exit(0);

	default:
		do_show(ctl);
		close(ctl);
		exit(0);
	}

        if (detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
        	        exit(1);
		}
	} else
		log_option |= LOG_PERROR;

	openlog("hidd", log_option, LOG_DAEMON);

	if (bacmp(&bdaddr, BDADDR_ANY))
		syslog(LOG_INFO, "Bluetooth HID daemon (%s)", addr);
	else
		syslog(LOG_INFO, "Bluetooth HID daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	run_server(ctl, csk, isk, subclass, nosdp, nocheck, bootonly, encrypt, timeout);

	syslog(LOG_INFO, "Exit");

	close(csk);
	close(isk);
	close(ctl);

	return 0;
}
