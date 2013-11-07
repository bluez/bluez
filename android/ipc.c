/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include "hal-msg.h"
#include "ipc.h"
#include "log.h"

void ipc_send(int sk, uint8_t service_id, uint8_t opcode, uint16_t len,
							void *param, int fd)
{
	struct msghdr msg;
	struct iovec iv[2];
	struct hal_hdr m;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	memset(&m, 0, sizeof(m));

	m.service_id = service_id;
	m.opcode = opcode;
	m.len = len;

	iv[0].iov_base = &m;
	iv[0].iov_len = sizeof(m);

	iv[1].iov_base = param;
	iv[1].iov_len = len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	if (fd >= 0) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		/* Initialize the payload */
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	}

	if (sendmsg(sk, &msg, 0) < 0) {
		error("IPC send failed, terminating :%s", strerror(errno));
		raise(SIGTERM);
	}
}

void ipc_send_rsp(int sk, uint8_t service_id, uint8_t status)
{
	struct hal_status s;

	s.code = status;

	ipc_send(sk, service_id, HAL_OP_STATUS, sizeof(s), &s, -1);
}
