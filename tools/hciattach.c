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
#include <termios.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <asm/types.h>

#include <bluetooth.h>
#include <hci.h>
#include <hci_uart.h>
#include <hci_lib.h>

struct uart_t {
	char *type;
	int  m_id;
	int  p_id;
	int  proto;
	int  speed;
	int  flags;
	int  (*init) (int fd, struct uart_t *u, struct termios *ti);
};

#define FLOW_CTL	0x0001

static int uart_speed(int s)
{
	switch (s) {
	case 9600:
		return B9600;
	case 19200:
		return B19200;
	case 38400:
		return B38400;
	case 57600:
		return B57600;
	case 115200:
		return B115200;
	case 230400:
		return B230400;
	case 460800:
		return B460800;
	case 921600:
		return B921600;
	default:
		return B57600;
	}
}

static int set_speed(int fd, struct termios *ti, int speed)
{
	cfsetospeed(ti, uart_speed(speed));
	return tcsetattr(fd, TCSANOW, ti);
}

static void sig_alarm(int sig)
{
	fprintf(stderr, "Initialization timed out.\n");
	exit(1);
}

/* 
 * Read an HCI event from the given file descriptor.
 */
static int read_hci_event(int fd, unsigned char* buf, int size) 
{
	int remain, r;
	int count = 0;

	if (size <= 0)
		return -1;

	/* The first byte identifies the packet type. For HCI event packets, it
	 * should be 0x04, so we read until we get to the 0x04. */
	while (1) {
		r = read(fd, buf, 1);
		if (r <= 0)
			return -1;
		if (buf[0] == 0x04)
			break;
	}
	count++;

	/* The next two bytes are the event code and parameter total length. */
	while (count < 3) {
		r = read(fd, buf + count, 3 - count);
		if (r <= 0)
			return -1;
		count += r;
	}

	/* Now we read the parameters. */
	if (buf[2] < (size - 3)) 
		remain = buf[2];
	else 
		remain = size - 3;

	while ((count - 3) < remain) {
		r = read(fd, buf + count, remain - (count - 3));
		if (r <= 0)
			return -1;
		count += r;
	}
	return count;
}

/* 
 * Ericsson specific initialization 
 */
static int ericsson(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 50000};
	char cmd[10];

	/* Switch to default Ericsson baudrate*/
	if (set_speed(fd, ti, 57600) < 0) {
		perror("Can't set default baud rate");
		return -1;
	}

	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = 0x09;
	cmd[2] = 0xfc;
	cmd[3] = 0x01;

	switch (u->speed) {
	case 57600:
		cmd[4] = 0x03;
		break;
	case 115200:
		cmd[4] = 0x02;
		break;
	case 230400:
		cmd[4] = 0x01;
		break;
	case 460800:
		cmd[4] = 0x00;
		break;
	default:
		cmd[4] = 0x03;
		u->speed = 57600;
		break;
	}

	/* Send initialization command */
	if (write(fd, cmd, 5) != 5) {
		perror("Failed to write init command");
		return -1;
	}
	nanosleep(&tm, NULL);
	return 0;
}

/* 
 * Digianswer specific initialization 
 */
static int digi(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 50000};
	char cmd[10];

	/* Switch to default Digi baudrate*/
	if (set_speed(fd, ti, 9600) < 0) {
		perror("Can't set default baud rate");
		return -1;
	}

	/* DigiAnswer set baud rate command */
	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = 0x07;
	cmd[2] = 0xfc;
	cmd[3] = 0x01;

	switch (u->speed) {
	case 57600:
		cmd[4] = 0x08;
		break;
	case 115200:
		cmd[4] = 0x09;
		break;
	default:
		cmd[4] = 0x09;
		u->speed = 115200;
		break;
	}

	/* Send initialization command */
	if (write(fd, cmd, 5) != 5) {
		perror("Failed to write init command");
		return -1;
	}
	nanosleep(&tm, NULL);
	return 0;
}

/* 
 * CSR specific initialization 
 * Inspired strongly by code in OpenBT and experimentations with Brainboxes
 * Pcmcia card.
 * Jean Tourrilhes <jt@hpl.hp.com> - 14.11.01
 */
static int csr(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 10000000};	/* 10ms - be generous */
	unsigned char cmd[30];		/* Command */
	unsigned char resp[30];		/* Response */
	int  clen = 0;		/* Command len */
	static int csr_seq = 0;	/* Sequence number of command */
	int  divisor;

	/* Switch to default CSR baudrate */
	if (set_speed(fd, ti, 115200) < 0) {
		perror("Can't set default baud rate");
		return -1;
	}

	/* It seems that if we set the CSR UART speed straight away, it
	 * won't work, the CSR UART gets into a state where we can't talk
	 * to it anymore.
	 * On the other hand, doing a read before setting the CSR speed
	 * seems to be ok.
	 * Therefore, the strategy is to read the build ID (useful for
	 * debugging) and only then set the CSR UART speed. Doing like
	 * this is more complex but at least it works ;-)
	 * The CSR UART control may be slow to wake up or something because
	 * every time I read its speed, its bogus...
	 * Jean II */

	/* Try to read the build ID of the CSR chip */
	clen = 5 + (5 + 6) * 2;
	/* HCI header */
	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = 0x00;		/* CSR command */
	cmd[2] = 0xfc;		/* MANUFACTURER_SPEC */
	cmd[3] = 1 + (5 + 6) * 2;	/* len */
	/* CSR MSG header */
	cmd[4] = 0xC2;		/* first+last+channel=BCC */
	/* CSR BCC header */
	cmd[5] = 0x00;		/* type = GET-REQ */
	cmd[6] = 0x00;		/* - msB */
	cmd[7] = 5 + 4;		/* len */
	cmd[8] = 0x00;		/* - msB */
	cmd[9] = csr_seq & 0xFF;/* seq num */
	cmd[10] = (csr_seq >> 8) & 0xFF;	/* - msB */
	csr_seq++;
	cmd[11] = 0x19;		/* var_id = CSR_CMD_BUILD_ID */
	cmd[12] = 0x28;		/* - msB */
	cmd[13] = 0x00;		/* status = STATUS_OK */
	cmd[14] = 0x00;		/* - msB */
	/* CSR BCC payload */
	memset(cmd + 15, 0, 6 * 2);

	/* Send command */
	do {
		if (write(fd, cmd, clen) != clen) {
			perror("Failed to write init command (GET_BUILD_ID)");
			return -1;
		}

		/* Read reply. */
		if (read_hci_event(fd, resp, 100) < 0) {
			perror("Failed to read init response (GET_BUILD_ID)");
			return -1;
		}

	/* Event code 0xFF is for vendor-specific events, which is 
	 * what we're looking for. */
	} while (resp[1] != 0xFF);

#ifdef CSR_DEBUG
	{
	char temp[512];
	int i;
	for (i=0; i < rlen; i++)
		sprintf(temp + (i*3), "-%02X", resp[i]);
	fprintf(stderr, "Reading CSR build ID %d [%s]\n", rlen, temp + 1);
	// In theory, it should look like :
	// 04-FF-13-FF-01-00-09-00-00-00-19-28-00-00-73-00-00-00-00-00-00-00
	}
#endif
	/* Display that to user */
	fprintf(stderr, "CSR build ID 0x%02X-0x%02X\n", 
		resp[15] & 0xFF, resp[14] & 0xFF);
	
	/* Try to read the current speed of the CSR chip */
	clen = 5 + (5 + 4)*2;
	/* -- HCI header */
	cmd[3] = 1 + (5 + 4)*2;	/* len */
	/* -- CSR BCC header -- */
	cmd[9] = csr_seq & 0xFF;	/* seq num */
	cmd[10] = (csr_seq >> 8) & 0xFF;	/* - msB */
	csr_seq++;
	cmd[11] = 0x02;		/* var_id = CONFIG_UART */
	cmd[12] = 0x68;		/* - msB */

#ifdef CSR_DEBUG
	/* Send command */
	do {
		if (write(fd, cmd, clen) != clen) {
			perror("Failed to write init command (GET_BUILD_ID)");
			return -1;
		}

		/* Read reply. */
		if (read_hci_event(fd, resp, 100) < 0) {
			perror("Failed to read init response (GET_BUILD_ID)");
			return -1;
		}

	/* Event code 0xFF is for vendor-specific events, which is 
	 * what we're looking for. */
	} while (resp[1] != 0xFF);

	{
	char temp[512];
	int i;
	for (i=0; i < rlen; i++)
		sprintf(temp + (i*3), "-%02X", resp[i]);
	fprintf(stderr, "Reading CSR UART speed %d [%s]\n", rlen, temp+1);
	}
#endif

	/* Now, create the command that will set the UART speed */
	/* CSR BCC header */
	cmd[5] = 0x02;			/* type = SET-REQ */
	cmd[6] = 0x00;			/* - msB */
	cmd[9] = csr_seq & 0xFF;	/* seq num */
	cmd[10] = (csr_seq >> 8) & 0xFF;/* - msB */
	csr_seq++;

	switch (u->speed) {
	case 9600:
		divisor = 0x0027;
		break;
	/* Various speeds ommited */ 
	case 57600:
		divisor = 0x00EC;
		break;
	case 115200:
		divisor = 0x01D8;
		break;
	/* For Brainbox Pcmcia cards */
	case 460800:
		divisor = 0x075F;
		break;
	case 921600:
		divisor = 0x0EBF;
		break;
	default:
		/* Safe default */
		divisor = 0x01D8;
		u->speed = 115200;
		break;
	}
	/* No parity, one stop bit -> divisor |= 0x0000; */
	cmd[15] = (divisor) & 0xFF;		/* divider */
	cmd[16] = (divisor >> 8) & 0xFF;	/* - msB */
	/* The rest of the payload will be 0x00 */

#ifdef CSR_DEBUG
	{
	char temp[512];
	int i;
	for(i = 0; i < clen; i++)
		sprintf(temp + (i*3), "-%02X", cmd[i]);
	fprintf(stderr, "Writing CSR UART speed %d [%s]\n", clen, temp + 1);
	// In theory, it should look like :
	// 01-00-FC-13-C2-02-00-09-00-03-00-02-68-00-00-BF-0E-00-00-00-00-00-00
	// 01-00-FC-13-C2-02-00-09-00-01-00-02-68-00-00-D8-01-00-00-00-00-00-00
	}
#endif

	/* Send the command to set the CSR UART speed */
	if (write(fd, cmd, clen) != clen) {
		perror("Failed to write init command (SET_UART_SPEED)");
		return -1;
	}
	nanosleep(&tm, NULL);
	return 0;
}

/* 
 * Silicon Wave specific initialization 
 * Thomas Moser <Thomas.Moser@tmoser.ch>
 */
static int swave(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 500000};
	char cmd[10], rsp[100];
	int r;

	/* Switch to default Silicon Wave baudrate*/
	if (set_speed(fd, ti, 115200) < 0) {
		perror("Can't set default baud rate");
		return -1;
	}

	// Silicon Wave set baud rate command
	// see HCI Vendor Specific Interface from Silicon Wave
	// first send a "param access set" command to set the
	// appropriate data fields in RAM. Then send a "HCI Reset
	// Subcommand", e.g. "soft reset" to make the changes effective.

	cmd[0] = HCI_COMMAND_PKT;	// it's a command packet
	cmd[1] = 0x0B;			// OCF 0x0B	= param access set	
	cmd[2] = 0xfc;			// OGF bx111111 = vendor specific
	cmd[3] = 0x06;			// 6 bytes of data following
	cmd[4] = 0x01;			// param sub command
	cmd[5] = 0x11;			// tag 17 = 0x11 = HCI Transport Params
	cmd[6] = 0x03;			// length of the parameter following
	cmd[7] = 0x01;			// HCI Transport flow control enable
	cmd[8] = 0x01;			// HCI Transport Type = UART

	switch (u->speed) {
	case 19200:
		cmd[9] = 0x03;
		break;
	case 38400:
		cmd[9] = 0x02;
		break;
	case 57600:
		cmd[9] = 0x01;
		break;
	case 115200:
		cmd[9] = 0x00;
		break;
	default:
		u->speed = 115200;
		cmd[9] = 0x00;
		break;
	}

	/* Send initialization command */
	if (write(fd, cmd, 10) != 5) {
		perror("Failed to write init command");
		return -1;
	}

	// We should wait for a "GET Event" to confirm the success of 
	// the baud rate setting. Wait some time before reading. Better:  
	// read with timeout, parse data 
	// until correct answer, else error handling ... todo ...

	nanosleep(&tm, NULL);

	r = read(fd, rsp, sizeof(rsp));
	if (r > 0) {
		// guess it's okay, but we should parse the reply. But since
		// I don't react on an error anyway ... todo
		// Response packet format:
		//  04	Event
		//  FF	Vendor specific
		//  07	Parameter length
		//  0B	Subcommand
		//  01	Setevent
		//  11	Tag specifying HCI Transport Layer Parameter
		//  03	length
		//  01	flow on
		//  01 	Hci Transport type = Uart
		//  xx	Baud rate set (see above)
	} else {	
		// ups, got error.
		return -1;
	}

	// we probably got the reply. Now we must send the "soft reset":
	cmd[0] = HCI_COMMAND_PKT;	// it's a command packet
	cmd[1] = 0x0B;			// OCF 0x0B	= param access set	
	cmd[2] = 0xfc;			// OGF bx111111 = vendor specific
	cmd[3] = 0x01;			// 1 byte of data following 
	cmd[4] = 0x03;			// HCI Reset Subcommand
			
	// Send initialization command
	if (write(fd, cmd, 5) != 5) {
		perror("Can't write Silicon Wave reset cmd.");
		return -1;
	}

	nanosleep(&tm, NULL);
			
	// now the uart baud rate on the silicon wave module is set and effective.
	// change our own baud rate as well. Then there is a reset event comming in
 	// on the *new* baud rate. This is *undocumented*! The packet looks like this:
	// 04 FF 01 0B (which would make that a confirmation of 0x0B = "Param 
	// subcommand class". So: change to new baud rate, read with timeout, parse
	// data, error handling. BTW: all param access in Silicon Wave is done this way.
	// Maybe this code would belong in a seperate file, or at least code reuse...

	return 0;
}

struct uart_t uart[] = {
	{ "any",      0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, NULL },
	{ "ericsson", 0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, ericsson },
	{ "digi",     0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, digi },

	/* Xircom PCMCIA cards: Credit Card Adapter and Real Port Adapter */
	{ "xircom",   0x0105, 0x080a, HCI_UART_H4, 115200, FLOW_CTL, NULL },

	/* CSR Casira serial adapter or BrainBoxes serial dongle (BL642) */
	{ "csr",      0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, csr },

	/* BrainBoxes PCMCIA card (BL620) */
	{ "bboxes",   0x0160, 0x0002, HCI_UART_H4, 460800, FLOW_CTL, csr },

	/* Silicon Wave kits */
	{ "swave",    0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, swave },

	/* Sphinx Electronics PICO Card */
	{ "picocard", 0x025e, 0x1000, HCI_UART_H4, 115200, FLOW_CTL, NULL },

	/* Inventel BlueBird Module */
	{ "inventel", 0x0000, 0x0000, HCI_UART_H4, 115200, FLOW_CTL, NULL },

        { NULL, 0 }
};

struct uart_t * get_by_id(int m_id, int p_id)
{
	int i;
	for (i = 0; uart[i].type; i++) {
		if (uart[i].m_id == m_id && uart[i].p_id == p_id)
			return &uart[i];
	}
	return NULL;
}

struct uart_t * get_by_type(char *type)
{
	int i;
	for (i = 0; uart[i].type; i++) {
		if (!strcmp(uart[i].type, type))
			return &uart[i];
	}
	return NULL;
}

/* Initialize UART driver */
int init_uart(char *dev, struct uart_t *u)
{
	struct termios ti;
	int  fd, i;

	fd = open(dev, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		perror("Can't open serial port");
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (tcgetattr(fd, &ti) < 0) {
		perror("Can't get port settings");
		return -1;
	}

	cfmakeraw(&ti);

	ti.c_cflag |= CLOCAL;
	if (u->flags & FLOW_CTL)
		ti.c_cflag |= CRTSCTS;
	else
		ti.c_cflag &= ~CRTSCTS;

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		perror("Can't set port settings");
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (u->init && u->init(fd, u, &ti) < 0)
		return -1;

	tcflush(fd, TCIOFLUSH);

	/* Set actual baudrate */
	if (set_speed(fd, &ti, u->speed) < 0) {
		perror("Can't set baud rate");
		return -1;
	}

	/* Set TTY to N_HCI line discpline */
	i = N_HCI;
	if (ioctl(fd, TIOCSETD, &i) < 0) {
		perror("Can't set line disc");
		return -1;
	}

	if (ioctl(fd, HCIUARTSETPROTO, u->proto) < 0) {
		perror("Can't set device");
		return -1;
	}

	return fd;
}

static void usage(void)
{
	printf("hciattach - HCI UART driver initialization utility\n");
	printf("Usage:\n");
	printf("\thciattach <tty> <type | id> [speed] [flow]\n");
	printf("\thciattach -l\n");
}

extern int optind, opterr, optopt;
extern char *optarg;

int main(int argc, char *argv[])
{
	struct uart_t *u = NULL;
	int detach, opt, i, n;
	int to = 5; 
	struct sigaction sa;
	char dev[20];

	detach = 1;
	
	while ((opt=getopt(argc, argv, "nt:l")) != EOF) {
		switch(opt) {
		case 'n':
			detach = 0;
			break;
		
		case 't':
			to = atoi(optarg);
			break;
		
		case 'l':
			for (i = 0; uart[i].type; i++) {
				printf("%-10s0x%04x,0x%04x\n", uart[i].type,
							uart[i].m_id, uart[i].p_id);
			}
			exit(0);
	
		default:
			usage();
			exit(1);
		}
	}

	n = argc - optind;
	if (n < 2) {
		usage();
		exit(1);
	}

	for (n = 0; optind < argc; n++, optind++) {
		char *opt;
	
		opt = argv[optind];
		
		switch(n) {
		case 0:
			dev[0] = 0;
			if (!strchr(opt, '/'))
				strcpy(dev, "/dev/");
			strcat(dev, opt);
			break;

		case 1:
			if (strchr(argv[optind], ',')) {
				int m_id, p_id;
				sscanf(argv[optind], "%x,%x", &m_id, &p_id);
				u = get_by_id(m_id, p_id);
			} else {
				u = get_by_type(opt);
			}

			if (!u) {
				fprintf(stderr, "Unknow device type or id\n");
				exit(1);
			}
			
			break;

		case 2:
			u->speed = atoi(argv[optind]);
			break;

		case 3:
			if (!strcmp("flow", argv[optind]))
				u->flags |=  FLOW_CTL;
			else
				u->flags &= ~FLOW_CTL;
			break;
		}
	}

	if (!u) {
		fprintf(stderr, "Unknow device type or id\n");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	/* 5 seconds should be enought for intialization */
	alarm(to);
	
	n = init_uart(dev, u);
	if (n < 0) {
		perror("Can't init device"); 
		exit(1);
	}

	alarm(0);

	if (detach) {
	       	if (fork()) return 0;
		for (i=0; i<20; i++)
			if (i != n) close(i);
	}

	while (1) sleep(999999999);
	return 0;
}
