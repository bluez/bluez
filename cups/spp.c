/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2004  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

int spp_print(bdaddr_t *src, bdaddr_t *dst, uint8_t channel, int fd, int copies)
{
	struct sockaddr_rc addr;
	unsigned char buf[2048];
	int i, sk, len;

	if ((sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		perror("ERROR: Can't create socket");
		return 1;
	}

	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);
	addr.rc_channel = 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("ERROR: Can't bind socket");
		close(sk);
		return 1;
	}

	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("ERROR: Can't connect to device");
		close(sk);
		return 1;
	}

	/* Ignore SIGTERM signals if printing from stdin */
	if (fd == 0) {
#ifdef HAVE_SIGSET
		sigset(SIGTERM, SIG_IGN);
#elif defined(HAVE_SIGACTION)
		memset(&action, 0, sizeof(action));
		sigemptyset(&action.sa_mask);
		action.sa_handler = SIG_IGN;
		sigaction(SIGTERM, &action, NULL);
#else
		signal(SIGTERM, SIG_IGN);
#endif /* HAVE_SIGSET */
	}

	for (i = 0; i < copies; i++) {

		if (fd != 0) {
			fprintf(stderr, "PAGE: 1 1\n");
			lseek(fd, 0, SEEK_SET);
		}

		while ((len = read(fd, buf, sizeof(buf))) > 0) {
			write(sk, buf, len);
		}

	}

	close(sk);

	return 0;
}
