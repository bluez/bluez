/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>

/* Test modes */
enum {
	SEND,
	RECV,
	RECONNECT,
	MULTY,
	DUMP
};

unsigned char *buf;

/* Default data size */
long data_size = 672;

bdaddr_t bdaddr;

float tv2fl(struct timeval tv)
{
	return (float)tv.tv_sec + (float)(tv.tv_usec/1000000.0);
}

int do_connect(char *svr)
{
	struct sockaddr_sco rem_addr, loc_addr;
	int s;

	if( (s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0 ) {
		syslog(LOG_ERR, "Can't create socket. %s(%d)", strerror(errno), errno);
		return -1;
	}

	memset(&loc_addr, 0, sizeof(loc_addr));
	loc_addr.sco_family = AF_BLUETOOTH;
	loc_addr.sco_bdaddr = bdaddr;
	if( bind(s, (struct sockaddr *) &loc_addr, sizeof(loc_addr)) < 0 ) {
		syslog(LOG_ERR, "Can't bind socket. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	memset(&rem_addr, 0, sizeof(rem_addr));
	rem_addr.sco_family = AF_BLUETOOTH;
	baswap(&rem_addr.sco_bdaddr, strtoba(svr));
	if( connect(s, (struct sockaddr *)&rem_addr, sizeof(rem_addr)) < 0 ){
		syslog(LOG_ERR, "Can't connect. %s(%d)", strerror(errno), errno);
		return -1;
	}

	syslog(LOG_INFO, "Connected\n");

	return s;
}

void do_listen( void (*handler)(int sk) )
{
	struct sockaddr_sco loc_addr, rem_addr;
	int  s, s1, opt;
	bdaddr_t ba;

	if( (s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0 ) {
		syslog(LOG_ERR, "Can't create socket. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	loc_addr.sco_family = AF_BLUETOOTH;
	loc_addr.sco_bdaddr = bdaddr;
	if( bind(s, (struct sockaddr *) &loc_addr, sizeof(loc_addr)) < 0 ) {
		syslog(LOG_ERR, "Can't bind socket. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	if( listen(s, 10) ) {
		syslog(LOG_ERR,"Can not listen on the socket. %s(%d)", strerror(errno), errno);
		exit(1);
	}

	syslog(LOG_INFO,"Waiting for connection ...");

	while(1) {
		opt = sizeof(rem_addr);
		if( (s1 = accept(s, (struct sockaddr *)&rem_addr, &opt)) < 0 ) {
			syslog(LOG_ERR,"Accept failed. %s(%d)", strerror(errno), errno);
			exit(1);
		}
		if( fork() ) {
			/* Parent */
			close(s1);
			continue;
		}
		/* Child */

		close(s);

		baswap(&ba, &rem_addr.sco_bdaddr);
		syslog(LOG_INFO, "Connect from %s\n", batostr(&ba));

		handler(s1);

		syslog(LOG_INFO, "Disconnect\n");
		exit(0);
	}
}

void dump_mode(int s)
{
	int len;

	syslog(LOG_INFO,"Receiving ...");
	while ((len = read(s, buf, data_size)) > 0)
		syslog(LOG_INFO, "Recevied %d bytes\n", len);
}

void recv_mode(int s)
{
	struct timeval tv_beg,tv_end,tv_diff;
	long total;
	uint32_t seq;

	syslog(LOG_INFO, "Receiving ...");

	seq = 0;
	while (1) {
		gettimeofday(&tv_beg,NULL);
		total = 0;
		while (total < data_size) {
			int r;
			if ((r = recv(s, buf, data_size, 0)) <= 0) {
				if (r < 0)
					syslog(LOG_ERR, "Read failed. %s(%d)",
							strerror(errno), errno);
				return;	
			}
			total += r;
		}
		gettimeofday(&tv_end,NULL);

		timersub(&tv_end,&tv_beg,&tv_diff);

		syslog(LOG_INFO,"%ld bytes in %.2fm speed %.2f kb",total,
		       tv2fl(tv_diff) / 60.0,
		       (float)( total / tv2fl(tv_diff) ) / 1024.0 );
	}
}

void send_mode(char *svr)
{
	struct sco_options so;
	uint32_t seq;
	int s, i, opt;

	if ((s = do_connect(svr)) < 0) {
		syslog(LOG_ERR, "Can't connect to the server. %s(%d)", 
				strerror(errno), errno);
		exit(1);
	}

	opt = sizeof(so);
	if (getsockopt(s, SOL_SCO, SCO_OPTIONS, &so, &opt) < 0) {
		syslog(LOG_ERR, "Can't get SCO options. %s(%d)", 
				strerror(errno), errno);
		exit(1);
	}	

	
	syslog(LOG_INFO,"Sending ...");

	for (i=6; i < so.mtu; i++)
		buf[i]=0x7f;

	seq = 0;
	while (1) {
		*(uint32_t *)buf = htobl(seq);
		*(uint16_t *)(buf+4) = htobs(data_size);
		seq++;
		
		if (send(s, buf, so.mtu, 0) <= 0) {
			syslog(LOG_ERR, "Send failed. %s(%d)", 
					strerror(errno), errno);
			exit(1);
		}
		usleep(1);
	}
}

void reconnect_mode(char *svr)
{
	while(1){
		int s;
		if( (s = do_connect(svr)) < 0 ){
			syslog(LOG_ERR, "Can't connect to the server. %s(%d)", strerror(errno), errno);
			exit(1);
		}
		close(s);

		sleep(5);
	}
}

void multy_connect_mode(char *svr)
{
	while(1){
		int i, s;
		for(i=0; i<10; i++){
			if( fork() ) continue;

			/* Child */
			if( (s = do_connect(svr)) < 0 ){
				syslog(LOG_ERR, "Can't connect to the server. %s(%d)", strerror(errno), errno);
			}
			close(s);
			exit(0);
		}
		sleep(19);
	}
}

void usage(void)
{
	printf("scotest - SCO testing\n"
		"Usage:\n");
	printf("\tscotest <mode> [-b bytes] [bd_addr]\n");
	printf("Modes:\n"
		"\t-d dump (server)\n"
		"\t-c reconnect (client)\n"
		"\t-m multiple connects (client)\n"
		"\t-r receive (server)\n"
		"\t-s send (client)\n");
}

extern int optind,opterr,optopt;
extern char *optarg;

int main(int argc ,char *argv[])
{
	struct sigaction sa;
	int opt, mode = RECV;

	while ((opt=getopt(argc,argv,"rdscmb:")) != EOF) {
		switch(opt) {
		case 'r':
			mode = RECV;
			break;
		
		case 's':
			mode = SEND;
			break;

		case 'd':
			mode = DUMP;
			break;

		case 'c':
			mode = RECONNECT;
			break;

		case 'm':
			mode = MULTY;
			break;

		case 'b':
			data_size = atoi(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (!(argc - optind) && (mode!=RECV && mode !=DUMP)) {
		usage();
		exit(1);
	}

	if (!(buf = malloc(data_size))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags   = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	openlog("scotest", LOG_PERROR | LOG_PID, LOG_LOCAL0);

	switch( mode ){
		case RECV:
			do_listen(recv_mode);
			break;

		case DUMP:
			do_listen(dump_mode);
			break;

		case SEND:
			send_mode(argv[optind]);
			break;

		case RECONNECT:
			reconnect_mode(argv[optind]);
			break;

		case MULTY:
			multy_connect_mode(argv[optind]);
			break;
	}
	syslog(LOG_INFO, "Exit");

	closelog();

	return 0;
}
