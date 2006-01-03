/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
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
#include <signal.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#ifndef N_HCI
#define N_HCI	15
#endif

#define HCIUARTSETPROTO _IOW('U', 200, int)
#define HCIUARTGETPROTO _IOR('U', 201, int)

#define HCI_UART_H4	0
#define HCI_UART_BCSP	1
#define HCI_UART_3WIRE	2
#define HCI_UART_H4DS	3

struct uart_t {
	char *type;
	int  m_id;
	int  p_id;
	int  proto;
	int  init_speed;
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
	case 500000:
		return B500000;
	case 576000:
		return B576000;
	case 921600:
		return B921600;
	case 1000000:
		return B1000000;
	case 1152000:
		return B1152000;
	case 1500000:
		return B1500000;
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
	char cmd[5];

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
	case 921600:
		cmd[4] = 0x20;
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
	char cmd[5];

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

static int texas(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 50000};
	char cmd[4];
	unsigned char resp[100];		/* Response */
	int n;

	memset(resp,'\0', 100);

	/* It is possible to get software version with manufacturer specific 
	   HCI command HCI_VS_TI_Version_Number. But the only thing you get more
	   is if this is point-to-point or point-to-multipoint module */

	/* Get Manufacturer and LMP version */
	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = 0x01;
	cmd[2] = 0x10;
	cmd[3] = 0x00;

	do {
		n = write(fd, cmd, 4);
		if (n < 0) {
			perror("Failed to write init command (READ_LOCAL_VERSION_INFORMATION)");
			return -1;
		}
		if (n < 4) {
			fprintf(stderr, "Wanted to write 4 bytes, could only write %d. Stop\n", n);
			return -1;
		}

		/* Read reply. */
		if (read_hci_event(fd, resp, 100) < 0) {
			perror("Failed to read init response (READ_LOCAL_VERSION_INFORMATION)");
			return -1;
		}

		/* Wait for command complete event for our Opcode */
	} while (resp[4] != cmd[1] && resp[5] != cmd[2]);

	/* Verify manufacturer */
	if ((resp[11] & 0xFF) != 0x0d)
		fprintf(stderr,"WARNING : module's manufacturer is not Texas Instrument\n");

	/* Print LMP version */
	fprintf(stderr, "Texas module LMP version : 0x%02x\n", resp[10] & 0xFF);

	/* Print LMP subversion */
	fprintf(stderr, "Texas module LMP sub-version : 0x%02x%02x\n", resp[14] & 0xFF, resp[13] & 0xFF);
	
	nanosleep(&tm, NULL);
	return 0;
}

static int read_check(int fd, void *buf, int count)
{
	int res;
	
	do {
		res = read(fd, buf, count);
		if (res != -1) {
			buf += res; 
			count -= res;
		}
	} while (count && (errno == 0 || errno == EINTR));
	
	if (count)
		return -1;
	
	return 0;
}

/*
 * BCSP specific initialization
 */
int serial_fd;

static void bcsp_tshy_sig_alarm(int sig)
{
	static int retries=0;
	unsigned char bcsp_sync_pkt[10] = {0xc0,0x00,0x41,0x00,0xbe,0xda,0xdc,0xed,0xed,0xc0};
	
	if (retries < 10) {
		retries++;
		write(serial_fd, &bcsp_sync_pkt, 10);
		alarm(1);
		return;
	}
	tcflush(serial_fd, TCIOFLUSH);
	fprintf(stderr, "BCSP initialization timed out\n");
	exit(1);
}

static void bcsp_tconf_sig_alarm(int sig)
{
	static int retries=0;
	unsigned char bcsp_conf_pkt[10] = {0xc0,0x00,0x41,0x00,0xbe,0xad,0xef,0xac,0xed,0xc0};
	if (retries < 10){
		retries++;
		write(serial_fd, &bcsp_conf_pkt, 10);
		alarm(1);
		return;
	}
	tcflush(serial_fd, TCIOFLUSH);
	fprintf(stderr, "BCSP initialization timed out\n");
	exit(1);
}

static int bcsp(int fd, struct uart_t *u, struct termios *ti)
{
	unsigned char byte, bcsph[4], bcspp[4],
		bcsp_sync_resp_pkt[10] = {0xc0,0x00,0x41,0x00,0xbe,0xac,0xaf,0xef,0xee,0xc0},
		bcsp_conf_resp_pkt[10] = {0xc0,0x00,0x41,0x00,0xbe,0xde,0xad,0xd0,0xd0,0xc0},
		bcspsync[4]     = {0xda, 0xdc, 0xed, 0xed},
		bcspsyncresp[4] = {0xac,0xaf,0xef,0xee},
		bcspconf[4]     = {0xad,0xef,0xac,0xed},
		bcspconfresp[4] = {0xde,0xad,0xd0,0xd0};
	struct sigaction sa;

	if (set_speed(fd, ti, u->speed) < 0) {
		perror("Can't set default baud rate");
		return -1;
	}

	ti->c_cflag |= PARENB;
	ti->c_cflag &= ~(PARODD);

	if (tcsetattr(fd, TCSANOW, ti) < 0) {
		perror("Can't set port settings");
		return -1;
	}

	alarm(0);

	serial_fd = fd;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = bcsp_tshy_sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	/* State = shy */

	bcsp_tshy_sig_alarm(0);
	while (1) {
		do {
			if (read_check(fd, &byte, 1) == -1){
				perror("Failed to read");
				return -1;
			}
		} while (byte != 0xC0);
		
		do {
			if ( read_check(fd, &bcsph[0], 1) == -1){
				perror("Failed to read");
				return -1;
			}
		  
		} while (bcsph[0] == 0xC0);
		
		if ( read_check(fd, &bcsph[1], 3) == -1){
			perror("Failed to read");
			return -1;
		}
		
		if (((bcsph[0] + bcsph[1] + bcsph[2]) & 0xFF) != (unsigned char)~bcsph[3])
			continue;
		if (bcsph[1] != 0x41 || bcsph[2] != 0x00)
			continue;

		if (read_check(fd, &bcspp, 4) == -1){
			perror("Failed to read");
			return -1;
		}

		if (!memcmp(bcspp, bcspsync, 4)) {
			write(fd, &bcsp_sync_resp_pkt,10);
		} else if (!memcmp(bcspp, bcspsyncresp, 4))
			break;
	}

	/* State = curious */

	alarm(0);
	sa.sa_handler = bcsp_tconf_sig_alarm;
	sigaction(SIGALRM, &sa, NULL);
	alarm(1);

	while (1) {
		do {
			if (read_check(fd, &byte, 1) == -1){
				perror("Failed to read");
				return -1;
			}
		} while (byte != 0xC0);

		do {
			if (read_check(fd, &bcsph[0], 1) == -1){
			      perror("Failed to read");
			      return -1;
			}
		} while (bcsph[0] == 0xC0);

		if (read_check(fd, &bcsph[1], 3) == -1){
			perror("Failed to read");
			return -1;
		}
		
		if (((bcsph[0] + bcsph[1] + bcsph[2]) & 0xFF) != (unsigned char)~bcsph[3])
			continue;

		if (bcsph[1] != 0x41 || bcsph[2] != 0x00)
			continue;

		if (read_check(fd, &bcspp, 4) == -1){
			perror("Failed to read");
			return -1;
		}

		if (!memcmp(bcspp, bcspsync, 4))
			write(fd, &bcsp_sync_resp_pkt, 10);
		else if (!memcmp(bcspp, bcspconf, 4))
			write(fd, &bcsp_conf_resp_pkt, 10);
		else if (!memcmp(bcspp, bcspconfresp,  4))
			break;
	}

	/* State = garrulous */

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

	if (u->speed > 1500000) {
		fprintf(stderr, "Speed %d too high. Remaining at %d baud\n", 
			u->speed, u->init_speed);
		u->speed = u->init_speed;
	} else if (u->speed != 57600 && uart_speed(u->speed) == B57600) {
		/* Unknown speed. Why oh why can't we just pass an int to the kernel? */
		fprintf(stderr, "Speed %d unrecognised. Remaining at %d baud\n",
			u->speed, u->init_speed);
		u->speed = u->init_speed;
	}
	if (u->speed == u->init_speed)
		return 0;

	/* Now, create the command that will set the UART speed */
	/* CSR BCC header */
	cmd[5] = 0x02;			/* type = SET-REQ */
	cmd[6] = 0x00;			/* - msB */
	cmd[9] = csr_seq & 0xFF;	/* seq num */
	cmd[10] = (csr_seq >> 8) & 0xFF;/* - msB */
	csr_seq++;

	divisor = (u->speed*64+7812)/15625;

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
 * Thomas Moser <thomas.moser@tmoser.ch>
 */
static int swave(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = { 0, 500000 };
	char cmd[10], rsp[100];
	int r;

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
	if (write(fd, cmd, 10) != 10) {
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

	// we probably got the reply. Now we must send the "soft reset"
	// which is standard HCI RESET.

	cmd[0] = HCI_COMMAND_PKT;	// it's a command packet
	cmd[1] = 0x03;
	cmd[2] = 0x0c;
	cmd[3] = 0x00;

	/* Send reset command */
	if (write(fd, cmd, 4) != 4) {
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

/*
 * ST Microelectronics specific initialization
 * Marcel Holtmann <marcel@holtmann.org>
 */
static int st(int fd, struct uart_t *u, struct termios *ti)
{
	struct timespec tm = {0, 50000};
	char cmd[5];

	/* ST Microelectronics set baud rate command */
	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = 0x46;			// OCF = Hci_Cmd_ST_Set_Uart_Baud_Rate
	cmd[2] = 0xfc;			// OGF = Vendor specific
	cmd[3] = 0x01;

	switch (u->speed) {
	case 9600:
		cmd[4] = 0x09;
		break;
	case 19200:
		cmd[4] = 0x0b;
		break;
	case 38400:
		cmd[4] = 0x0d;
		break;
	case 57600:
		cmd[4] = 0x0e;
		break;
	case 115200:
		cmd[4] = 0x10;
		break;
	case 230400:
		cmd[4] = 0x12;
		break;
	case 460800:
		cmd[4] = 0x13;
		break;
	case 921600:
		cmd[4] = 0x14;
		break;
	default:
		cmd[4] = 0x10;
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

struct uart_t uart[] = {
	{ "any",        0x0000, 0x0000, HCI_UART_H4,   115200, 115200, FLOW_CTL, NULL     },
	{ "ericsson",   0x0000, 0x0000, HCI_UART_H4,   57600,  115200, FLOW_CTL, ericsson },
	{ "digi",       0x0000, 0x0000, HCI_UART_H4,   9600,   115200, FLOW_CTL, digi     },
	{ "texas",      0x0000, 0x0000, HCI_UART_H4,   115200, 115200, FLOW_CTL, texas    },

	{ "bcsp",       0x0000, 0x0000, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

	/* Xircom PCMCIA cards: Credit Card Adapter and Real Port Adapter */
	{ "xircom",     0x0105, 0x080a, HCI_UART_H4,   115200, 115200, FLOW_CTL, NULL     },

	/* CSR Casira serial adapter or BrainBoxes serial dongle (BL642) */
	{ "csr",        0x0000, 0x0000, HCI_UART_H4,   115200, 115200, FLOW_CTL, csr      },

	/* BrainBoxes PCMCIA card (BL620) */
	{ "bboxes",     0x0160, 0x0002, HCI_UART_H4,   115200, 460800, FLOW_CTL, csr      },

	/* Silicon Wave kits */
	{ "swave",      0x0000, 0x0000, HCI_UART_H4,   115200, 115200, FLOW_CTL, swave    },

	/* ST Microelectronics minikits based on STLC2410/STLC2415 */
	{ "st",         0x0000, 0x0000, HCI_UART_H4,    57600, 115200, FLOW_CTL, st       },

	/* Sphinx Electronics PICO Card */
	{ "picocard",   0x025e, 0x1000, HCI_UART_H4,   115200, 115200, FLOW_CTL, NULL     },

	/* Inventel BlueBird Module */
	{ "inventel",   0x0000, 0x0000, HCI_UART_H4,   115200, 115200, FLOW_CTL, NULL     },

	/* COM One Platinium Bluetooth PC Card */
	{ "comone",     0xffff, 0x0101, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

	/* TDK Bluetooth PC Card and IBM Bluetooth PC Card II */
	{ "tdk",        0x0105, 0x4254, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

	/* Socket Bluetooth CF Card (Rev G) */
	{ "socket",     0x0104, 0x0096, HCI_UART_BCSP, 230400, 230400, 0,        bcsp     },

	/* 3Com Bluetooth Card (Version 3.0) */
	{ "3com",       0x0101, 0x0041, HCI_UART_H4,   115200, 115200, FLOW_CTL, csr      },

	/* AmbiCom BT2000C Bluetooth PC/CF Card */
	{ "bt2000c",    0x022d, 0x2000, HCI_UART_H4,    57600, 460800, FLOW_CTL, csr      },

	/* Zoom Bluetooth PCMCIA Card */
	{ "zoom",       0x0279, 0x950b, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

	/* Sitecom CN-504 PCMCIA Card */
	{ "sitecom",    0x0279, 0x950b, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

	/* Billionton PCBTC1 PCMCIA Card */
	{ "billionton", 0x0279, 0x950b, HCI_UART_BCSP, 115200, 115200, 0,        bcsp     },

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
int init_uart(char *dev, struct uart_t *u, int send_break)
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

	/* Set initial baudrate */
	if (set_speed(fd, &ti, u->init_speed) < 0) {
		perror("Can't set initial baud rate");
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	if (send_break) {
		tcsendbreak(fd, 0);
		usleep(500000);
	}

	if (u->init && u->init(fd, u, &ti) < 0)
		return -1;

	tcflush(fd, TCIOFLUSH);

	/* Set actual baudrate */
	if (set_speed(fd, &ti, u->speed) < 0) {
		perror("Can't set baud rate");
		return -1;
	}

	/* Set TTY to N_HCI line discipline */
	i = N_HCI;
	if (ioctl(fd, TIOCSETD, &i) < 0) {
		perror("Can't set line discipline");
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
	printf("\thciattach [-n] [-p] [-b] [-t timeout] [-s initial_speed] <tty> <type | id> [speed] [flow|noflow]\n");
	printf("\thciattach -l\n");
}

extern int optind, opterr, optopt;
extern char *optarg;

int main(int argc, char *argv[])
{
	struct uart_t *u = NULL;
	int detach, printpid, opt, i, n;
	int to = 5; 
	int init_speed = 0;
	int send_break = 0;
	pid_t pid;
	struct sigaction sa;
	char dev[PATH_MAX];

	detach = 1;
	printpid = 0;
	
	while ((opt=getopt(argc, argv, "bnpt:s:l")) != EOF) {
		switch(opt) {
		case 'b':
			send_break = 1;
			break;

		case 'n':
			detach = 0;
			break;

		case 'p':
			printpid = 1;
			break;

		case 't':
			to = atoi(optarg);
			break;

		case 's':
			init_speed = atoi(optarg);
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
				fprintf(stderr, "Unknown device type or id\n");
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
		fprintf(stderr, "Unknown device type or id\n");
		exit(1);
	}

	/* If user specified a initial speed, use that instead of
	   the hardware's default */
	if (init_speed)
		u->init_speed = init_speed;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	/* 5 seconds should be enough for initialization */
	alarm(to);
	
	n = init_uart(dev, u, send_break);
	if (n < 0) {
		perror("Can't initialize device"); 
		exit(1);
	}

	alarm(0);

	if (detach) {
		if ((pid = fork())) {
			if (printpid)
				printf("%d\n", pid);
			return 0;
		}
		for (i=0; i<20; i++)
			if (i != n) close(i);
	}

	while (1) sleep(999999999);
	return 0;
}
