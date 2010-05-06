/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>

#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hidp.h>

#include "sdp.h"
#include "dund.h"
#include "lib.h"

volatile sig_atomic_t __io_canceled;

/* MS dialup networking support (i.e. CLIENT / CLIENTSERVER thing) */
static int msdun = 0;

static char *pppd = "/usr/sbin/pppd";
static char *pppd_opts[DUN_MAX_PPP_OPTS] =
	{
		/* First 3 are reserved */
		"", "", "",
		"noauth",
		"noipdefault",
		NULL
	};

static int  detach = 1;
static int  persist;
static int  use_sdp = 1;
static int  auth;
static int  encrypt;
static int  secure;
static int  master;
static int  type = LANACCESS;
static int  search_duration = 10;
static uint use_cache;

static int  channel;

static struct {
	uint     valid;
	char     dst[40];
	bdaddr_t bdaddr;
	int      channel;
} cache;

static bdaddr_t src_addr = *BDADDR_ANY;
static int src_dev = -1;

volatile int terminate;

enum {
	NONE,
	SHOW,
	LISTEN,
	CONNECT,
	KILL
} modes;

static int create_connection(char *dst, bdaddr_t *bdaddr, int mrouter);

static int do_listen(void)
{
	struct sockaddr_rc sa;
	int sk, lm;

	if (type == MROUTER) {
		if (!cache.valid)
			return -1;

		if (create_connection(cache.dst, &cache.bdaddr, type) < 0) {
			syslog(LOG_ERR, "Cannot connect to mRouter device. %s(%d)",
								strerror(errno), errno);
			return -1;
		}
	}

	if (!channel)
		channel = DUN_DEFAULT_CHANNEL;

	if (use_sdp)
		dun_sdp_register(&src_addr, channel, type);

	if (type == MROUTER)
		syslog(LOG_INFO, "Waiting for mRouter callback on channel %d", channel);

	/* Create RFCOMM socket */
	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		syslog(LOG_ERR, "Cannot create RFCOMM socket. %s(%d)",
				strerror(errno), errno);
		return -1;
	}

	sa.rc_family  = AF_BLUETOOTH;
	sa.rc_channel = channel;
	sa.rc_bdaddr  = src_addr;

	if (bind(sk, (struct sockaddr *) &sa, sizeof(sa))) {
		syslog(LOG_ERR, "Bind failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	/* Set link mode */
	lm = 0;
	if (master)
		lm |= RFCOMM_LM_MASTER;
	if (auth)
		lm |= RFCOMM_LM_AUTH;
	if (encrypt)
		lm |= RFCOMM_LM_ENCRYPT;
	if (secure)
		lm |= RFCOMM_LM_SECURE;

	if (lm && setsockopt(sk, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
		syslog(LOG_ERR, "Failed to set link mode. %s(%d)", strerror(errno), errno);
		return -1;
	}

	listen(sk, 10);

	while (!terminate) {
		socklen_t alen = sizeof(sa);
		int nsk;
		char ba[40];
		char ch[10];

		nsk = accept(sk, (struct sockaddr *) &sa, &alen);
		if (nsk < 0) {
			syslog(LOG_ERR, "Accept failed. %s(%d)", strerror(errno), errno);
			continue;
		}

		switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "Fork failed. %s(%d)", strerror(errno), errno);
		default:
			close(nsk);
			if (type == MROUTER) {
				close(sk);
				terminate = 1;
			}
			continue;
		}

		close(sk);

		if (msdun && ms_dun(nsk, 1, msdun) < 0) {
			syslog(LOG_ERR, "MSDUN failed. %s(%d)", strerror(errno), errno);
			exit(0);
		}

		ba2str(&sa.rc_bdaddr, ba);
		snprintf(ch, sizeof(ch), "%d", channel);

		/* Setup environment */
		setenv("DUN_BDADDR",  ba, 1);
		setenv("DUN_CHANNEL", ch, 1);

		if (!dun_open_connection(nsk, pppd, pppd_opts, 0))
			syslog(LOG_INFO, "New connection from %s", ba);

		close(nsk);
		exit(0);
	}

	if (use_sdp)
		dun_sdp_unregister();
	return 0;
}

/* Connect and initiate RFCOMM session
 * Returns:
 *   -1 - critical error (exit persist mode)
 *   1  - non critical error
 *   0  - success
 */
static int create_connection(char *dst, bdaddr_t *bdaddr, int mrouter)
{
	struct sockaddr_rc sa;
	int sk, err = 0, ch;

	if (use_cache && cache.valid && cache.channel) {
		/* Use cached channel */
		ch = cache.channel;

	} else if (!channel) {
		syslog(LOG_INFO, "Searching for %s on %s", mrouter ? "SP" : "LAP", dst);

		if (dun_sdp_search(&src_addr, bdaddr, &ch, mrouter) <= 0)
			return 0;
	} else
		ch = channel;

	syslog(LOG_INFO, "Connecting to %s channel %d", dst, ch);

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		syslog(LOG_ERR, "Cannot create RFCOMM socket. %s(%d)",
		     strerror(errno), errno);
		return -1;
	}

	sa.rc_family  = AF_BLUETOOTH;
	sa.rc_channel = 0;
	sa.rc_bdaddr  = src_addr;

	if (bind(sk, (struct sockaddr *) &sa, sizeof(sa)))
		syslog(LOG_ERR, "Bind failed. %s(%d)",
			strerror(errno), errno);

	sa.rc_channel = ch;
	sa.rc_bdaddr  = *bdaddr;

	if (!connect(sk, (struct sockaddr *) &sa, sizeof(sa)) ) {
		if (mrouter) {
			sleep(1);
			close(sk);
			return 0;
		}

		syslog(LOG_INFO, "Connection established");

		if (msdun && ms_dun(sk, 0, msdun) < 0) {
			syslog(LOG_ERR, "MSDUN failed. %s(%d)", strerror(errno), errno);
			err = 1;
			goto out;
		}

		if (!dun_open_connection(sk, pppd, pppd_opts, (persist > 0)))
			err = 0;
		else
			err = 1;
	} else {
		syslog(LOG_ERR, "Connect to %s failed. %s(%d)",
				dst, strerror(errno), errno);
		err = 1;
	}

out:
	if (use_cache) {
		if (!err) {
			/* Succesesful connection, validate cache */
			strcpy(cache.dst, dst);
			bacpy(&cache.bdaddr, bdaddr);
			cache.channel = ch;
			cache.valid   = use_cache;
		} else {
			cache.channel = 0;
			cache.valid--;
		}
	}

	close(sk);
	return err;
}

/* Search and connect
 * Returns:
 *   -1 - critical error (exit persist mode)
 *   1  - non critical error
 *   0  - success
 */
static int do_connect(void)
{
	inquiry_info *ii;
	int reconnect = 0;
	int i, n, r = 0;

	do {
		if (reconnect)
			sleep(persist);
		reconnect = 1;

		if (cache.valid) {
			/* Use cached bdaddr */
			r = create_connection(cache.dst, &cache.bdaddr, 0);
			if (r < 0) {
				terminate = 1;
				break;
			}
			continue;
		}

		syslog(LOG_INFO, "Inquiring");

		/* FIXME: Should we use non general LAP here ? */

		ii = NULL;
		n  = hci_inquiry(src_dev, search_duration, 0, NULL, &ii, 0);
		if (n < 0) {
			syslog(LOG_ERR, "Inquiry failed. %s(%d)", strerror(errno), errno);
			continue;
		}

		for (i = 0; i < n; i++) {
			char dst[40];
			ba2str(&ii[i].bdaddr, dst);

			r = create_connection(dst, &ii[i].bdaddr, 0);
			if (r < 0) {
				terminate = 1;
				break;
			}
		}
		bt_free(ii);
	} while (!terminate && persist);

	return r;
}

static void do_show(void)
{
	dun_show_connections();
}

static void do_kill(char *dst)
{
	if (dst) {
		bdaddr_t ba;
		str2ba(dst, &ba);
		dun_kill_connection((void *) &ba);
	} else
		dun_kill_all_connections();
}

static void sig_hup(int sig)
{
	return;
}

static void sig_term(int sig)
{
	io_cancel();
	terminate = 1;
}

static struct option main_lopts[] = {
	{ "help",	0, 0, 'h' },
	{ "listen",	0, 0, 's' },
	{ "connect",	1, 0, 'c' },
	{ "search",	2, 0, 'Q' },
	{ "kill",	1, 0, 'k' },
	{ "killall",	0, 0, 'K' },
	{ "channel",	1, 0, 'P' },
	{ "device",	1, 0, 'i' },
	{ "nosdp",	0, 0, 'D' },
	{ "list",	0, 0, 'l' },
	{ "show",	0, 0, 'l' },
	{ "nodetach",	0, 0, 'n' },
	{ "persist",	2, 0, 'p' },
	{ "auth",	0, 0, 'A' },
	{ "encrypt",	0, 0, 'E' },
	{ "secure",	0, 0, 'S' },
	{ "master",	0, 0, 'M' },
	{ "cache",	0, 0, 'C' },
	{ "pppd",	1, 0, 'd' },
	{ "msdun",	2, 0, 'X' },
	{ "activesync",	0, 0, 'a' },
	{ "mrouter",	1, 0, 'm' },
	{ "dialup",	0, 0, 'u' },
	{ 0, 0, 0, 0 }
};

static const char *main_sopts = "hsc:k:Kr:i:lnp::DQ::AESMP:C::P:Xam:u";

static const char *main_help =
	"Bluetooth LAP (LAN Access over PPP) daemon version %s\n"
	"Usage:\n"
	"\tdund <options> [pppd options]\n"
	"Options:\n"
	"\t--show --list -l          Show active LAP connections\n"
	"\t--listen -s               Listen for LAP connections\n"
	"\t--dialup -u               Pretend to be a dialup/telephone\n"
	"\t--connect -c <bdaddr>     Create LAP connection\n"
	"\t--mrouter -m <bdaddr>     Create mRouter connection\n"
	"\t--search -Q[duration]     Search and connect\n"
	"\t--kill -k <bdaddr>        Kill LAP connection\n"
	"\t--killall -K              Kill all LAP connections\n"
	"\t--channel -P <channel>    RFCOMM channel\n"
	"\t--device -i <bdaddr>      Source bdaddr\n"
	"\t--nosdp -D                Disable SDP\n"
	"\t--auth -A                 Enable authentication\n"
	"\t--encrypt -E              Enable encryption\n"
	"\t--secure -S               Secure connection\n"
	"\t--master -M               Become the master of a piconet\n"
	"\t--nodetach -n             Do not become a daemon\n"
	"\t--persist -p[interval]    Persist mode\n"
	"\t--pppd -d <pppd>          Location of the PPP daemon (pppd)\n"
	"\t--msdun -X[timeo]         Enable Microsoft dialup networking support\n"
	"\t--activesync -a           Enable Microsoft ActiveSync networking\n"
	"\t--cache -C[valid]         Enable address cache\n";

int main(int argc, char *argv[])
{
	char *dst = NULL, *src = NULL;
	struct sigaction sa;
	int mode = NONE;
	int opt;

	while ((opt=getopt_long(argc, argv, main_sopts, main_lopts, NULL)) != -1) {
		switch(opt) {
		case 'l':
			mode = SHOW;
			detach = 0;
			break;

		case 's':
			mode = LISTEN;
			type = LANACCESS;
			break;

		case 'c':
			mode = CONNECT;
			dst  = strdup(optarg);
			break;

		case 'Q':
			mode = CONNECT;
			dst  = NULL;
			if (optarg)
				search_duration = atoi(optarg);
			break;

		case 'k':
			mode = KILL;
			detach = 0;
			dst  = strdup(optarg);
			break;

		case 'K':
			mode = KILL;
			detach = 0;
			dst  = NULL;
			break;

		case 'P':
			channel = atoi(optarg);
			break;

		case 'i':
			src = strdup(optarg);
			break;

		case 'D':
			use_sdp = 0;
			break;

		case 'A':
			auth = 1;
			break;

		case 'E':
			encrypt = 1;
			break;

		case 'S':
			secure = 1;
			break;

		case 'M':
			master = 1;
			break;

		case 'n':
			detach = 0;
			break;

		case 'p':
			if (optarg)
				persist = atoi(optarg);
			else
				persist = 5;
			break;

		case 'C':
			if (optarg)
				use_cache = atoi(optarg);
			else
				use_cache = 2;
			break;

		case 'd':
			pppd  = strdup(optarg);
			break;

		case 'X':
			if (optarg)
				msdun = atoi(optarg);
			else
				msdun = 10;
			break;

		case 'a':
			msdun = 10;
			type = ACTIVESYNC;
			break;

		case 'm':
			mode = LISTEN;
			dst  = strdup(optarg);
			type = MROUTER;
			break;

		case 'u':
			mode = LISTEN;
			type = DIALUP;
			break;

		case 'h':
		default:
			printf(main_help, VERSION);
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;

	/* The rest is pppd options */
	if (argc > 0) {
		for (opt = 3; argc && opt < DUN_MAX_PPP_OPTS - 1;
							argc--, opt++)
			pppd_opts[opt] = *argv++;
		pppd_opts[opt] = NULL;
	}

	io_init();

	if (dun_init()) {
		free(dst);
		return -1;
	}

	/* Check non daemon modes first */
	switch (mode) {
	case SHOW:
		do_show();
		free(dst);
		return 0;

	case KILL:
		do_kill(dst);
		free(dst);
		return 0;

	case NONE:
		printf(main_help, VERSION);
		free(dst);
		return 0;
	}

	/* Initialize signals */
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

	if (detach && daemon(0, 0)) {
		perror("Can't start daemon");
		exit(1);
	}

	openlog("dund", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Bluetooth DUN daemon version %s", VERSION);

	if (src) {
		src_dev = hci_devid(src);
		if (src_dev < 0 || hci_devba(src_dev, &src_addr) < 0) {
			syslog(LOG_ERR, "Invalid source. %s(%d)", strerror(errno), errno);
			free(dst);
			return -1;
		}
	}

	if (dst) {
		strncpy(cache.dst, dst, sizeof(cache.dst) - 1);
		str2ba(dst, &cache.bdaddr);

		/* Disable cache invalidation */
		use_cache = cache.valid = ~0;
	}

	switch (mode) {
	case CONNECT:
		do_connect();
		break;

	case LISTEN:
		do_listen();
		break;
	}

	free(dst);
	return 0;
}
