/*
 *
 *  RFCOMM configuration utility
 *
 *  Copyright (C) 2002  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>

#include "kword.h"

static char *rfcomm_config_file = NULL;

extern int optind, opterr, optopt;
extern char *optarg;

static char *rfcomm_state[] = {
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

static volatile sig_atomic_t __io_canceled = 0;

static void sig_hup(int sig)
{
	return;
}

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static char *rfcomm_flagstostr(uint32_t flags)
{
	static char str[100];
	str[0] = 0;

	strcat(str, "[");

	if (flags & (1 << RFCOMM_REUSE_DLC))
		strcat(str, "reuse-dlc ");

	if (flags & (1 << RFCOMM_RELEASE_ONHUP))
		strcat(str, "release-on-hup ");

	if (flags & (1 << RFCOMM_TTY_ATTACHED))
		strcat(str, "tty-attached");
	
	strcat(str, "]");
	return str;
}

static void print_dev_info(struct rfcomm_dev_info *di)
{
	char src[18], dst[18], addr[100];

	ba2str(&di->src, src); ba2str(&di->dst, dst);

	if (bacmp(&di->src, BDADDR_ANY) == 0)
		sprintf(addr, "%s", dst);
	else
		sprintf(addr, "%s -> %s", src, dst);

	printf("rfcomm%d: %s channel %d %s %s\n",
		di->id, addr, di->channel,
		rfcomm_state[di->state], 
		di->flags ? rfcomm_flagstostr(di->flags) : "");
}

static void print_dev_list(int ctl, int flags)
{
	struct rfcomm_dev_list_req *dl;
	struct rfcomm_dev_info *di;
	int i;

	dl = malloc(sizeof(*dl) + RFCOMM_MAX_DEV * sizeof(*di));
	if (!dl) {
		perror("Can't allocate memory");
		exit(1);
	}

	dl->dev_num = RFCOMM_MAX_DEV;
	di = dl->dev_info;

	if (ioctl(ctl, RFCOMMGETDEVLIST, (void *) dl) < 0) {
		perror("Can't get device list");
		exit(1);
	}

	for (i = 0; i < dl->dev_num; i++)
		print_dev_info(di + i);
}

static int create_dev(int ctl, int dev, int flags, bdaddr_t *bdaddr, int argc, char **argv)
{
	struct rfcomm_dev_req req;
	int err;

	memset(&req, 0, sizeof(req));
	req.dev_id = dev;
	req.flags = flags;
	bacpy(&req.src, bdaddr);

	if (argc < 2) {
		if ((err = rfcomm_read_config(rfcomm_config_file)) < 0) {
			perror("Can't open RFCOMM config file");
			return err;
		}

		bacpy(&req.dst, &rfcomm_opts[dev].bdaddr);
		req.channel = rfcomm_opts[dev].channel;

		if (bacmp(&req.dst, BDADDR_ANY) == 0) {
			fprintf(stderr, "Can't find a config entry for rfcomm%d\n", dev);
			return -EFAULT;
		}
		
	} else {
		str2ba(argv[1], &req.dst);

		if (argc > 2)
			req.channel = atoi(argv[2]);
		else
			req.channel = 1;
	}

	if ((err = ioctl(ctl, RFCOMMCREATEDEV, &req)) < 0 )
		perror("Can't create device");

	return err;
}

static int create_all(int ctl)
{
	struct rfcomm_dev_req req;
	int i, err;

	if ((err = rfcomm_read_config(rfcomm_config_file)) < 0) {
		perror("Can't open RFCOMM config file");
		return err;
	}

	for (i = 0; i < RFCOMM_MAX_DEV; i++) {
		memset(&req, 0, sizeof(req));
		req.dev_id = i;
		req.flags = 0;
		bacpy(&req.src, BDADDR_ANY);
		bacpy(&req.dst, &rfcomm_opts[i].bdaddr);
		req.channel = rfcomm_opts[i].channel;

		if (bacmp(&req.dst, BDADDR_ANY) != 0)
			ioctl(ctl, RFCOMMCREATEDEV, &req);
	}

	return 0;
}

static int release_dev(int ctl, int dev, int flags)
{
	struct rfcomm_dev_req req;
	int err;

	memset(&req, 0, sizeof(req));
	req.dev_id = dev;

	if ((err = ioctl(ctl, RFCOMMRELEASEDEV, &req)) < 0 )
		perror("Can't release device");

	return err;
}

static int release_all(int ctl)
{
	struct rfcomm_dev_list_req *dl;
	struct rfcomm_dev_info *di;
	int i;

	dl = malloc(sizeof(*dl) + RFCOMM_MAX_DEV * sizeof(*di));
	if (!dl) {
		perror("Can't allocate memory");
		exit(1);
	}

	dl->dev_num = RFCOMM_MAX_DEV;
	di = dl->dev_info;

	if (ioctl(ctl, RFCOMMGETDEVLIST, (void *) dl) < 0) {
		perror("Can't get device list");
		exit(1);
	}

	for (i = 0; i < dl->dev_num; i++)
		release_dev(ctl, (di + i)->id, 0);

	return 0;
}

static void cmd_connect(int ctl, int dev, bdaddr_t *bdaddr, int argc, char **argv)
{
	struct sigaction sa;
	struct pollfd p;
	char devname[MAXPATHLEN];
	int fd;

	if (create_dev(ctl, dev, 0, bdaddr, argc, argv) < 0)
		return;

	snprintf(devname, MAXPATHLEN - 1, "/dev/rfcomm%d", dev);
	if ((fd = open(devname, O_RDONLY | O_NOCTTY)) < 0) {
		perror("Can't open RFCOMM device");
		goto release;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	p.fd = fd;
	p.events = POLLHUP;

	while (!__io_canceled) {
		p.revents = 0;
		poll(&p, 1, 100);
	}

	close(fd);

release:
	release_dev(ctl, dev, 0);
}

static void cmd_create(int ctl, int dev, bdaddr_t *bdaddr, int argc, char **argv)
{
	if (strcmp(argv[0], "all") == 0)
		create_all(ctl);
	else
		create_dev(ctl, dev, 0, bdaddr, argc, argv);
}

static void cmd_release(int ctl, int dev, bdaddr_t *bdaddr, int argc, char **argv)
{
	if (strcmp(argv[0], "all") == 0)
		release_all(ctl);
	else
		release_dev(ctl, dev, 0);
}

static void cmd_show(int ctl, int dev, bdaddr_t *bdaddr, int argc, char **argv)
{
	if (strcmp(argv[0], "all") == 0)
		print_dev_list(ctl, 0);
	else {
		struct rfcomm_dev_info di = { id: atoi(argv[0]) };
		if (ioctl(ctl, RFCOMMGETDEVINFO, &di) < 0) {
			perror("Get info failed");
			exit(1);
		}

		print_dev_info(&di);
	}
}

struct {
	char *cmd;
	char *alt;
	void (*func)(int ctl, int dev, bdaddr_t *bdaddr, int argc, char **argv);
	char *opt;
	char *doc;
} command[] = {
	{ "bind",    "create", cmd_create,  "<dev> <bdaddr> [channel]", "Bind device"    },
	{ "release", "unbind", cmd_release, "<dev>",                    "Release device" },
	{ "connect", "conn",   cmd_connect, "<dev> <bdaddr> [channel]", "Connect device" },
	{ "show",    "info",   cmd_show,    0,                          "Show device"    },
	{ NULL, NULL, NULL, 0, 0 }
};

static void usage(void)
{
	int i;

	printf("RFCOMM configuration utility ver %s\n", VERSION);

	printf("Usage:\n"
		"\trfcomm [options] <command> <dev>\n"
		"\n");

	printf("Options:\n"
		"\t-i [hciX|bdaddr]   Local HCI device or BD Address\n"
		"\t-h, --help         Display help\n"
		"\t-a                 Show all devices (default)\n"
		"\n");

	printf("Commands:\n");
        for (i = 0; command[i].cmd; i++)
		printf("\t%-8s %-24s\t%s\n",
			command[i].cmd,
			command[i].opt ? command[i].opt : " ",
			command[i].doc);
	printf("\n");
}


static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ "config",	1, 0, 'f' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[]) 
{

	bdaddr_t bdaddr;
	int i, opt, ctl, dev_id, show_all = 0;

	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt = getopt_long(argc, argv, "+i:f:ah", main_options, NULL)) != -1) {
		switch(opt) {
		case 'i':
			if (strncmp(optarg, "hci", 3) == 0)
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;
			
		case 'f':
			rfcomm_config_file = strdup(optarg);
			break;

		case 'a':
			show_all = 1;
			break;

		case 'h':
			usage();
			exit(0);

		default:
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 2)
		show_all = 1;

	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM)) < 0 ) {
		perror("Can't open RFCOMM control socket");
		exit(1);
	}

	if (show_all) {
		print_dev_list(ctl, 0);
		close(ctl);
		exit(0);
	}

	if (strncmp(argv[1], "rfcomm", 6) == 0)
		dev_id = atoi(argv[1] + 6);
	else
		dev_id = atoi(argv[1]);

	for (i = 0; command[i].cmd; i++) {
		if (strncmp(command[i].cmd, argv[0], 4) && strncmp(command[i].alt, argv[0], 4))
			continue;
		argc--;
		argv++;
		command[i].func(ctl, dev_id, &bdaddr, argc, argv);
		close(ctl);
		exit(0);
	}

	usage();

	close(ctl);

	return 0;
}
