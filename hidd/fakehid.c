/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hidp.h>

#include "hidd.h"
#include "uinput.h"

#include <math.h>

static void event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;

	if (fd <= fileno(stderr))
		return;

	memset(&event, 0, sizeof(event));
	event.type = type;
	event.code = code;
	event.value = value;

	write(fd, &event, sizeof(event));
}

static void func(int fd)
{
}

static void back(int fd)
{
}

static void next(int fd)
{
}

static void button(int fd, unsigned int button, int is_press)
{
	switch (button) {
	case 1:
		event(fd, EV_KEY, BTN_LEFT, is_press);
		break;
	case 3:
		event(fd, EV_KEY, BTN_RIGHT, is_press);
		break;
	}

	event(fd, EV_SYN, SYN_REPORT, 0);
}

static void move(int fd, unsigned int direction)
{
	double angle;
	int32_t x, y;

	angle = (direction * 22.5) * 3.1415926 / 180;
	x = (int) (sin(angle) * 8);
	y = (int) (cos(angle) * -8);

	event(fd, EV_REL, REL_X, x);
	event(fd, EV_REL, REL_Y, y);

	event(fd, EV_SYN, SYN_REPORT, 0);
}

static void epox_decode(int fd, unsigned char event)
{
	switch (event) {
	case 48:
		func(fd); break;
	case 55:
		back(fd); break;
	case 56:
		next(fd); break;
	case 53:
		button(fd, 1, 1); break;
	case 121:
		button(fd, 1, 0); break;
	case 113:
		break;
	case 54:
		button(fd, 3, 1); break;
	case 120:
		button(fd, 3, 0); break;
	case 112:
		break;
	case 51:
		move(fd, 0); break;
	case 97:
		move(fd, 1); break;
	case 65:
		move(fd, 2); break;
	case 98:
		move(fd, 3); break;
	case 50:
		move(fd, 4); break;
	case 99:
		move(fd, 5); break;
	case 67:
		move(fd, 6); break;
	case 101:
		move(fd, 7); break;
	case 52:
		move(fd, 8); break;
	case 100:
		move(fd, 9); break;
	case 66:
		move(fd, 10); break;
	case 102:
		move(fd, 11); break;
	case 49:
		move(fd, 12); break;
	case 103:
		move(fd, 13); break;
	case 57:
		move(fd, 14); break;
	case 104:
		move(fd, 15); break;
	case 69:
		break;
	default:
		printf("Unknown event code %d\n", event);
		break;
	}
}

static int uinput_create(char *name, int keyboard, int mouse)
{
	struct uinput_dev dev;
	int fd, aux;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				fprintf(stderr, "Can't open input device: %s (%d)",
							strerror(errno), errno);
				return -1;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));

	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		fprintf(stderr, "Can't write device information: %s (%d)",
							strerror(errno), errno);
		close(fd);
		return -1;
	}

	if (mouse) {
		ioctl(fd, UI_SET_EVBIT, EV_REL);

		for (aux = REL_X; aux <= REL_MISC; aux++)
			ioctl(fd, UI_SET_RELBIT, aux);
	}

	if (keyboard) {
		ioctl(fd, UI_SET_EVBIT, EV_KEY);
		ioctl(fd, UI_SET_EVBIT, EV_LED);
		ioctl(fd, UI_SET_EVBIT, EV_REP);

		for (aux = KEY_RESERVED; aux <= KEY_UNKNOWN; aux++)
			ioctl(fd, UI_SET_KEYBIT, aux);

		//for (aux = LED_NUML; aux <= LED_MISC; aux++)
		//	ioctl(fd, UI_SET_LEDBIT, aux);
	}

	if (mouse) {
		ioctl(fd, UI_SET_EVBIT, EV_KEY);

		for (aux = BTN_LEFT; aux <= BTN_BACK; aux++)
			ioctl(fd, UI_SET_KEYBIT, aux);
	}

	ioctl(fd, UI_DEV_CREATE);

	return fd;
}

static int rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		fprintf(stderr, "Can't create socket: %s (%d)\n",
							strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't bind socket: %s (%d)\n",
							strerror(errno), errno);
		close(sk);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Can't connect: %s (%d)\n",
							strerror(errno), errno);
		close(sk);
		return -1;
	}

	return sk;
}

static volatile sig_atomic_t __io_canceled = 0;

static void sig_hup(int sig)
{
}

static void sig_term(int sig)
{
	__io_canceled = 1;
}

void epox_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	unsigned char buf[16];
	struct sigaction sa;
	struct pollfd p;
	char addr[18];
	int i, fd, sk, len;

	sk = rfcomm_connect(src, dst, channel);
	if (sk < 0)
		return;

	fd = uinput_create("Bluetooth Presenter", 0, 1);
	if (fd < 0) {
		close(sk);
		return;
	}

	ba2str(dst, addr);

	printf("Connected to %s on channel %d\n", addr, channel);
	printf("Press CTRL-C for hangup\n");

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

	p.fd = sk;
	p.events = POLLIN | POLLERR | POLLHUP;

	while (!__io_canceled) {
		p.revents = 0;
		if (poll(&p, 1, 100) < 1)
			continue;

		len = read(sk, buf, sizeof(buf));
		if (len < 0)
			break;

		for (i = 0; i < len; i++)
			epox_decode(fd, buf[i]);
	}

	printf("Disconnected\n");

	ioctl(fd, UI_DEV_DESTROY);

	close(fd);
	close(sk);
}

void headset_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	printf("Not implemented\n");
}
