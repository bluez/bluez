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

#ifdef NEED_PPOLL
#include "ppoll.h"
#endif

static volatile sig_atomic_t __io_canceled = 0;

static void sig_hup(int sig)
{
}

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;

	if (fd <= fileno(stderr))
		return -EINVAL;

	memset(&event, 0, sizeof(event));
	event.type = type;
	event.code = code;
	event.value = value;

	return write(fd, &event, sizeof(event));
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
				fprintf(stderr, "Can't open input device: %s (%d)\n",
							strerror(errno), errno);
				return -1;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));

	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		fprintf(stderr, "Can't write device information: %s (%d)\n",
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
		/*
		 *for (aux = LED_NUML; aux <= LED_MISC; aux++)
		 *	ioctl(fd, UI_SET_LEDBIT, aux);
		 */
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
		send_event(fd, EV_KEY, BTN_LEFT, is_press);
		break;
	case 3:
		send_event(fd, EV_KEY, BTN_RIGHT, is_press);
		break;
	}

	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static void move(int fd, unsigned int direction)
{
	double angle;
	int32_t x, y;

	angle = (direction * 22.5) * 3.1415926 / 180;
	x = (int) (sin(angle) * 8);
	y = (int) (cos(angle) * -8);

	send_event(fd, EV_REL, REL_X, x);
	send_event(fd, EV_REL, REL_Y, y);

	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static inline void epox_decode(int fd, unsigned char event)
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

int epox_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	unsigned char buf[16];
	struct sigaction sa;
	struct pollfd p;
	sigset_t sigs;
	char addr[18];
	int i, fd, sk, len;

	sk = rfcomm_connect(src, dst, channel);
	if (sk < 0)
		return -1;

	fd = uinput_create("Bluetooth Presenter", 0, 1);
	if (fd < 0) {
		close(sk);
		return -1;
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

	sigfillset(&sigs);
	sigdelset(&sigs, SIGCHLD);
	sigdelset(&sigs, SIGPIPE);
	sigdelset(&sigs, SIGTERM);
	sigdelset(&sigs, SIGINT);
	sigdelset(&sigs, SIGHUP);

	p.fd = sk;
	p.events = POLLIN | POLLERR | POLLHUP;

	while (!__io_canceled) {
		p.revents = 0;
		if (ppoll(&p, 1, NULL, &sigs) < 1)
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

	return 0;
}

int headset_presenter(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	printf("Not implemented\n");
	return -1;
}

/* The strange meta key close to Ctrl has been assigned to Esc,
   Fn key to CtrlR and the left space to Alt*/

static unsigned char jthree_keycodes[63] = {
	KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6,
	KEY_Q, KEY_W, KEY_E, KEY_R, KEY_T,
	KEY_A, KEY_S, KEY_D, KEY_F, KEY_G,
	KEY_Z, KEY_X, KEY_C, KEY_V, KEY_B,
	KEY_LEFTALT, KEY_TAB, KEY_CAPSLOCK, KEY_ESC,
	KEY_7, KEY_8, KEY_9, KEY_0, KEY_MINUS, KEY_EQUAL, KEY_BACKSPACE,
	KEY_Y, KEY_U, KEY_I, KEY_O, KEY_P, KEY_LEFTBRACE, KEY_RIGHTBRACE,
	KEY_H, KEY_J, KEY_K, KEY_L, KEY_SEMICOLON, KEY_APOSTROPHE, KEY_ENTER,
	KEY_N, KEY_M, KEY_COMMA, KEY_DOT, KEY_SLASH, KEY_UP,
	KEY_SPACE, KEY_COMPOSE, KEY_LEFT, KEY_DOWN, KEY_RIGHT,
	KEY_LEFTCTRL, KEY_RIGHTSHIFT, KEY_LEFTSHIFT, KEY_DELETE, KEY_RIGHTCTRL, KEY_RIGHTALT,
};

static inline void jthree_decode(int fd, unsigned char event)
{
	if (event > 63)
		send_event(fd, EV_KEY, jthree_keycodes[event & 0x3f], 0);
	else
		send_event(fd, EV_KEY, jthree_keycodes[event - 1], 1);
}

int jthree_keyboard(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	unsigned char buf[16];
	struct sigaction sa;
	struct pollfd p;
	sigset_t sigs;
	char addr[18];
	int i, fd, sk, len;

	sk = rfcomm_connect(src, dst, channel);
	if (sk < 0)
		return -1;

	fd = uinput_create("J-Three Keyboard", 1, 0);
	if (fd < 0) {
		close(sk);
		return -1;
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

	sigfillset(&sigs);
	sigdelset(&sigs, SIGCHLD);
	sigdelset(&sigs, SIGPIPE);
	sigdelset(&sigs, SIGTERM);
	sigdelset(&sigs, SIGINT);
	sigdelset(&sigs, SIGHUP);

	p.fd = sk;
	p.events = POLLIN | POLLERR | POLLHUP;

	while (!__io_canceled) {
		p.revents = 0;
		if (ppoll(&p, 1, NULL, &sigs) < 1)
			continue;

		len = read(sk, buf, sizeof(buf));
		if (len < 0)
			break;

		for (i = 0; i < len; i++)
			jthree_decode(fd, buf[i]);
	}

	printf("Disconnected\n");

	ioctl(fd, UI_DEV_DESTROY);

	close(fd);
	close(sk);

	return 0;
}

static const int celluon_xlate_num[10] = {
	KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9
};

static const int celluon_xlate_char[26] = {
	KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I, KEY_J,
	KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T,
	KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z
};

static int celluon_xlate(int c)
{
	if (c >= '0' && c <= '9')
		return celluon_xlate_num[c - '0'];

	if (c >= 'A' && c <= 'Z')
		return celluon_xlate_char[c - 'A'];

	switch (c) {
	case 0x08:
		return KEY_BACKSPACE;
	case 0x09:
		return KEY_TAB;
	case 0x0d:
		return KEY_ENTER;
	case 0x11:
		return KEY_LEFTCTRL;
	case 0x14:
		return KEY_CAPSLOCK;
	case 0x20:
		return KEY_SPACE;
	case 0x25:
		return KEY_LEFT;
	case 0x26:
		return KEY_UP;
	case 0x27:
		return KEY_RIGHT;
	case 0x28:
		return KEY_DOWN;
	case 0x2e:
		return KEY_DELETE;
	case 0x5b:
		return KEY_MENU;
	case 0xa1:
		return KEY_RIGHTSHIFT;
	case 0xa0:
		return KEY_LEFTSHIFT;
	case 0xba:
		return KEY_SEMICOLON;
	case 0xbd:
		return KEY_MINUS;
	case 0xbc:
		return KEY_COMMA;
	case 0xbb:
		return KEY_EQUAL;
	case 0xbe:
		return KEY_DOT;
	case 0xbf:
		return KEY_SLASH;
	case 0xc0:
		return KEY_GRAVE;
	case 0xdb:
		return KEY_LEFTBRACE;
	case 0xdc:
		return KEY_BACKSLASH;
	case 0xdd:
		return KEY_RIGHTBRACE;
	case 0xde:
		return KEY_APOSTROPHE;
	case 0xff03:
		return KEY_HOMEPAGE;
	case 0xff04:
		return KEY_TIME;
	case 0xff06:
		return KEY_OPEN;
	case 0xff07:
		return KEY_LIST;
	case 0xff08:
		return KEY_MAIL;
	case 0xff30:
		return KEY_CALC;
	case 0xff1a: /* Map FN to ALT */
		return KEY_LEFTALT;
	case 0xff2f:
		return KEY_INFO;
	default:
		printf("Unknown key %x\n", c);
		return c;
	}
}

struct celluon_state {
	int len;	/* Expected length of current packet */
	int count;	/* Number of bytes received */
	int action;
	int key;
};

static void celluon_decode(int fd, struct celluon_state *s, uint8_t c)
{
	if (s->count < 2 && c != 0xa5) {
		/* Lost Sync */
		s->count = 0;
		return;
	}

	switch (s->count) {
	case 0:
		/* New packet - Reset state */
		s->len = 30;
		s->key = 0;
		break;
	case 1:
		break;
	case 6:
		s->action = c;
		break;
	case 28:
		s->key = c;
		if (c == 0xff)
			s->len = 31;
		break;
	case 29:
	case 30:
		if (s->count == s->len - 1) {
			/* TODO: Verify checksum */
			if (s->action < 2) {
				send_event(fd, EV_KEY, celluon_xlate(s->key),
								s->action);
			}
			s->count = -1;
		} else {
			s->key = (s->key << 8) | c;
		}
		break;
	}

	s->count++;

	return;
}

int celluon_keyboard(const bdaddr_t *src, const bdaddr_t *dst, uint8_t channel)
{
	unsigned char buf[16];
	struct sigaction sa;
	struct pollfd p;
	sigset_t sigs;
	char addr[18];
	int i, fd, sk, len;
	struct celluon_state s;

	sk = rfcomm_connect(src, dst, channel);
	if (sk < 0)
		return -1;

	fd = uinput_create("Celluon Keyboard", 1, 0);
	if (fd < 0) {
		close(sk);
		return -1;
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

	sigfillset(&sigs);
	sigdelset(&sigs, SIGCHLD);
	sigdelset(&sigs, SIGPIPE);
	sigdelset(&sigs, SIGTERM);
	sigdelset(&sigs, SIGINT);
	sigdelset(&sigs, SIGHUP);

	p.fd = sk;
	p.events = POLLIN | POLLERR | POLLHUP;

	memset(&s, 0, sizeof(s));

	while (!__io_canceled) {
		p.revents = 0;
		if (ppoll(&p, 1, NULL, &sigs) < 1)
			continue;

		len = read(sk, buf, sizeof(buf));
		if (len < 0)
			break;

		for (i = 0; i < len; i++)
			celluon_decode(fd, &s, buf[i]);
	}

	printf("Disconnected\n");

	ioctl(fd, UI_DEV_DESTROY);

	close(fd);
	close(sk);

	return 0;
}
