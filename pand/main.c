/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include "pand.h"

static uint16_t role = BNEP_SVC_PANU;	/* Local role (ie service) */
static uint16_t service = BNEP_SVC_NAP;	/* Remote service */

static int  detach = 1;
static int  persist;
static int  use_sdp = 1;
static int  use_cache;
static int  auth;
static int  encrypt;
static int  secure;
static int  master;
static int  cleanup;
static int  search_duration = 10;

static struct {
	int      valid;
	char     dst[40];
	bdaddr_t bdaddr;
} cache;

static char netdev[16] = "bnep%d";
static char *pidfile = NULL;
static bdaddr_t src_addr = *BDADDR_ANY;
static int src_dev = -1;

volatile int terminate;

static void do_kill(char *dst);

enum {
	NONE,
	SHOW,
	LISTEN,
	CONNECT,
	KILL
} modes;

static void run_devup(char *dev, char *dst, int sk, int nsk)
{
	char *argv[4], prog[40];
	struct sigaction sa;

	sprintf(prog, "%s/%s", PAND_CONFIG_DIR, PAND_DEVUP_CMD);

	if (access(prog, R_OK | X_OK))
		return;

	if (fork())
		return;

	if (sk >= 0)
		close(sk);

	if (nsk >= 0)
		close(nsk);
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	argv[0] = prog;
	argv[1] = dev;
	argv[2] = dst;
	argv[3] = NULL;
	execv(prog, argv);
	exit(1);
}

static int do_listen(void)
{
	struct l2cap_options l2o;
	struct sockaddr_l2 l2a;
	socklen_t olen;
	int sk, lm;

	if (use_sdp)
		bnep_sdp_register(&src_addr, role);

	/* Create L2CAP socket and bind it to PSM BNEP */
	sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		syslog(LOG_ERR, "Cannot create L2CAP socket. %s(%d)",
				strerror(errno), errno);
		return -1;
	}

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, &src_addr);
	l2a.l2_psm = htobs(BNEP_PSM);

	if (bind(sk, (struct sockaddr *) &l2a, sizeof(l2a))) {
		syslog(LOG_ERR, "Bind failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	/* Setup L2CAP options according to BNEP spec */
	memset(&l2o, 0, sizeof(l2o));
	olen = sizeof(l2o);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &olen) < 0) {
		syslog(LOG_ERR, "Failed to get L2CAP options. %s(%d)",
				strerror(errno), errno);
		return -1;
	}

	l2o.imtu = l2o.omtu = BNEP_MTU;
	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o)) < 0) {
		syslog(LOG_ERR, "Failed to set L2CAP options. %s(%d)",
				strerror(errno), errno);
		return -1;
	}

	/* Set link mode */
	lm = 0;
	if (master)
		lm |= L2CAP_LM_MASTER;
	if (auth)
		lm |= L2CAP_LM_AUTH;
	if (encrypt)
		lm |= L2CAP_LM_ENCRYPT;
	if (secure)
		lm |= L2CAP_LM_SECURE;

	if (lm && setsockopt(sk, SOL_L2CAP, L2CAP_LM, &lm, sizeof(lm)) < 0) {
		syslog(LOG_ERR, "Failed to set link mode. %s(%d)", strerror(errno), errno);
		return -1;
	}

	listen(sk, 10);

	while (!terminate) {
		socklen_t alen = sizeof(l2a);
		int nsk;
		nsk = accept(sk, (struct sockaddr *) &l2a, &alen);
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
			continue;
		}

		if (!bnep_accept_connection(nsk, role, netdev)) {
			char str[40];
			ba2str(&l2a.l2_bdaddr, str);

			syslog(LOG_INFO, "New connection from %s %s", str, netdev);

			run_devup(netdev, str, sk, nsk);
		} else {
			syslog(LOG_ERR, "Connection failed. %s(%d)",
					strerror(errno), errno);
		}

		close(nsk);
		exit(0);
	}

	if (use_sdp)
		bnep_sdp_unregister();
	return 0;
}

/* Wait for disconnect or error condition on the socket */
static int w4_hup(int sk)
{
	struct pollfd pf;
	int n;

	while (!terminate) {
		pf.fd = sk;
		pf.events = POLLERR | POLLHUP;
		n = poll(&pf, 1, -1);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			syslog(LOG_ERR, "Poll failed. %s(%d)",
					strerror(errno), errno);
			return 1;
		}

		if (n) {
			int err = 0;
			socklen_t olen = sizeof(err);
			getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &olen);
			syslog(LOG_INFO, "%s disconnected%s%s", netdev,
				err ? " : " : "", err ? strerror(err) : "");

			close(sk);
			return 0;
		}
	}
	return 0;
}

/* Connect and initiate BNEP session
 * Returns:
 *   -1 - critical error (exit persist mode)
 *   1  - non critical error
 *   0  - success
 */
static int create_connection(char *dst, bdaddr_t *bdaddr)
{
	struct l2cap_options l2o;
	struct sockaddr_l2 l2a;
	socklen_t olen;
	int sk, r = 0;

	syslog(LOG_INFO, "Connecting to %s", dst);

	sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		syslog(LOG_ERR, "Cannot create L2CAP socket. %s(%d)",
				strerror(errno), errno);
		return -1;
	}

	/* Setup L2CAP options according to BNEP spec */
	memset(&l2o, 0, sizeof(l2o));
	olen = sizeof(l2o);
	getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &olen);
	l2o.imtu = l2o.omtu = BNEP_MTU;
	setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o));

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, &src_addr);

	if (bind(sk, (struct sockaddr *) &l2a, sizeof(l2a)))
		syslog(LOG_ERR, "Bind failed. %s(%d)", 
				strerror(errno), errno);

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, bdaddr);
	l2a.l2_psm = htobs(BNEP_PSM);

	if (!connect(sk, (struct sockaddr *) &l2a, sizeof(l2a)) && 
			!bnep_create_connection(sk, role, service, netdev)) {

		syslog(LOG_INFO, "%s connected", netdev);

		run_devup(netdev, dst, sk, -1);

		if (persist) {
			w4_hup(sk);

			if (terminate && cleanup) {
				syslog(LOG_INFO, "Disconnecting from %s.", dst);
				do_kill(dst);
			}
		}

		r = 0;
	} else {
		syslog(LOG_ERR, "Connect to %s failed. %s(%d)",
				dst, strerror(errno), errno);
		r = 1;
	}

	close(sk);

	if (use_cache) {
		if (!r) {
			/* Succesesful connection, validate cache */
			strcpy(cache.dst, dst);
			bacpy(&cache.bdaddr, bdaddr);
			cache.valid = use_cache;
		} else
			cache.valid--;
	}

	return r;
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

		if (cache.valid > 0) {
			/* Use cached bdaddr */
			r = create_connection(cache.dst, &cache.bdaddr);
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

			if (use_sdp) {
				syslog(LOG_INFO, "Searching for %s on %s", 
						bnep_svc2str(service), dst);

				if (bnep_sdp_search(&src_addr, &ii[i].bdaddr, service) <= 0)
					continue;
			}

			r = create_connection(dst, &ii[i].bdaddr);
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
	bnep_show_connections();
}

static void do_kill(char *dst)
{
	if (dst)
		bnep_kill_connection((void *) strtoba(dst));
	else
		bnep_kill_all_connections();
}

void sig_hup(int sig)
{
	return;
}

void sig_term(int sig)
{
	terminate = 1;
}

int write_pidfile(void)
{
	int fd;
	FILE *f;
	pid_t pid;

	do { 
		fd = open(pidfile, O_WRONLY|O_TRUNC|O_CREAT|O_EXCL, 0644);
		if (fd == -1) {
			/* Try to open the file for read. */
			fd = open(pidfile, O_RDONLY);
			if(fd == -1) {
				syslog(LOG_ERR, "Could not read old pidfile: %s(%d)", strerror(errno), errno);
				return -1;
			}
			
			/* We're already running; send a SIGHUP (we presume that they
			 * are calling ifup for a reason, so they probably want to
			 * rescan) and then exit cleanly and let things go on in the
			 * background.  Muck with the filename so that we don't go
			 * deleting the pid file for the already-running instance.
			 */
			f = fdopen(fd, "r");
			if (!f) {
				syslog(LOG_ERR, "Could not fdopen old pidfile: %s(%d)", strerror(errno), errno);
				close(fd);
				return -1;
			}

			pid = 0;
			fscanf(f, "%d", &pid);
			fclose(f);

			if (pid) {
				/* Try to kill it. */
				if (kill(pid, SIGHUP) == -1) {
					/* No such pid; remove the bogus pid file. */
					syslog(LOG_INFO, "Removing stale pidfile");
					unlink(pidfile);
					fd = -1;
				} else {
					/* Got it.  Don't mess with the pid file on
					 * our way out. */
					syslog(LOG_INFO, "Signalling existing process %d and exiting\n", pid);
					pidfile = NULL;
					return -1;
				}
			}
		}
	} while(fd == -1);

	f = fdopen(fd, "w");
	if (!f) {
		syslog(LOG_ERR, "Could not fdopen new pidfile: %s(%d)", strerror(errno), errno);
		close(fd);
		unlink(pidfile);
		return -1;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return 0;
}
		


static struct option main_lopts[] = {
	{ "help",     0, 0, 'h' },
	{ "listen",   0, 0, 's' },
	{ "connect",  1, 0, 'c' },
	{ "search",   2, 0, 'Q' },
	{ "kill",     1, 0, 'k' },
	{ "killall",  0, 0, 'K' },
	{ "role",     1, 0, 'r' },
	{ "service",  1, 0, 'd' },
	{ "ethernet", 1, 0, 'e' },
	{ "device",   1, 0, 'i' },
	{ "nosdp",    0, 0, 'D' },
	{ "list",     0, 0, 'l' },
	{ "show",     0, 0, 'l' },
	{ "nodetach", 0, 0, 'n' },
	{ "persist",  2, 0, 'p' },
	{ "auth",     0, 0, 'A' },
	{ "encrypt",  0, 0, 'E' },
	{ "secure",   0, 0, 'S' },
	{ "master",   0, 0, 'M' },
	{ "cache",    0, 0, 'C' },
	{ "pidfile",  1, 0, 'P' },
	{ "autozap",  0, 0, 'z' },
	{ 0, 0, 0, 0 }
};

static char main_sopts[] = "hsc:k:Kr:d:e:i:lnp::DQ::AESMC::P:z";

static char main_help[] = 
	"Bluetooth PAN daemon version " VERSION " \n"
	"Usage:\n"
	"\tpand <options>\n"
	"Options:\n"
	"\t--show --list -l          Show active PAN connections\n"
	"\t--listen -s               Listen for PAN connections\n"
	"\t--connect -c <bdaddr>     Create PAN connection\n"
	"\t--autozap -z              Disconnect automatically on exit\n"
	"\t--search -Q[duration]     Search and connect\n"
	"\t--kill -k <bdaddr>        Kill PAN connection\n"
	"\t--killall -K              Kill all PAN connections\n"
	"\t--role -r <role>          Local PAN role (PANU, NAP, GN)\n"
	"\t--service -d <role>       Remote PAN service (PANU, NAP, GN)\n"
	"\t--ethernet -e <name>      Network interface name\n"
	"\t--device -i <bdaddr>      Source bdaddr\n"
	"\t--nosdp -D                Disable SDP\n"
	"\t--auth -A                 Enable authentication\n"
	"\t--encrypt -E              Enable encryption\n"
	"\t--secure -S               Secure connection\n"
	"\t--master -M               Become the master of a piconet\n"
	"\t--nodetach -n             Do not become a daemon\n"
	"\t--persist -p[interval]    Persist mode\n"
	"\t--cache -C[valid]         Cache addresses\n"
	"\t--pidfile -P <pidfile>    Create PID file\n";

int main(int argc, char **argv)
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
			break;

		case 'c':
			mode = CONNECT;
			dst  = strdup(optarg);
			break;

		case 'Q':
			mode = CONNECT;
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
			break;

		case 'i':
			src = strdup(optarg);
			break;

		case 'r':
			bnep_str2svc(optarg, &role);
			break;

		case 'd':
			bnep_str2svc(optarg, &service);
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

		case 'e':
			strcpy(netdev, optarg);
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

		case 'P':
			pidfile = strdup(optarg);
			break;

		case 'z':
			cleanup = 1;
			break;

		case 'h':
		default:
			printf(main_help);
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (bnep_init())
		return -1;

	/* Check non daemon modes first */
	switch (mode) {
	case SHOW:
		do_show();
		return 0;

	case KILL:
		do_kill(dst);
		return 0;

	case NONE:
		printf(main_help);
		return 0;
	}

	/* Initialize signals */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	if (detach) {
		if (fork()) exit(0);

		/* Direct stdin,stdout,stderr to '/dev/null' */
		{
			int fd = open("/dev/null", O_RDWR);
			dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
			close(fd);
		}

		setsid();
		chdir("/");
	}

	openlog("pand", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Bluetooth PAN daemon version %s", VERSION);

	if (src) {
		src_dev = hci_devid(src);
		if (src_dev < 0 || hci_devba(src_dev, &src_addr) < 0) {
			syslog(LOG_ERR, "Invalid source. %s(%d)", strerror(errno), errno);
			return -1;
		}
	}

	if (pidfile && write_pidfile())
		return -1;

	if (dst) {
		/* Disable cache invalidation */
		use_cache = 0;

		strncpy(cache.dst, dst, sizeof(cache.dst) - 1);
		str2ba(dst, &cache.bdaddr);
		cache.valid = 1;
		free(dst);
	}

	switch (mode) {
	case CONNECT:
		do_connect();
		break;

	case LISTEN:
		do_listen();
		break;
	}

	if (pidfile)
		unlink(pidfile);

	return 0;
}
