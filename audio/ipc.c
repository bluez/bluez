/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "ipc.h"

/* This table contains the string representation for messages */
static const char *strmsg[] = {
	"BT_GETCAPABILITIES_REQ",
	"BT_GETCAPABILITIES_RSP",
	"BT_SETCONFIGURATION_REQ",
	"BT_SETCONFIGURATION_RSP",
	"BT_STREAMSTART_REQ",
	"BT_STREAMSTART_RSP",
	"BT_STREAMSTOP_REQ",
	"BT_STREAMSTOP_RSP",
	"BT_STREAMSUSPEND_IND",
	"BT_STREAMRESUME_IND",
	"BT_CONTROL_REQ",
	"BT_CONTROL_RSP",
	"BT_CONTROL_IND",
	"BT_STREAMFD_IND",
};

int bt_audio_service_open()
{
	int sk;
	int err;
	struct sockaddr_un addr = {
		AF_UNIX, BT_IPC_SOCKET_NAME
	};

	sk = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		fprintf(stderr, "%s: Cannot open socket: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		errno = err;
		return -1;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		fprintf(stderr, "%s: connect() failed: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		close(sk);
		errno = err;
		return -1;
	}

	return sk;
}

int bt_audio_service_close(int sk)
{
	return close(sk);
}

int bt_audio_service_get_data_fd(int sk)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))], m;
	int err, ret;
	struct iovec iov = { &m, sizeof(m) };
	struct msghdr msgh;
	struct cmsghdr *cmsg;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	ret = recvmsg(sk, &msgh, 0);
	if (ret < 0) {
		err = errno;
		fprintf(stderr, "%s: Unable to receive fd: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		errno = err;
		return -1;
	}

	/* Receive auxiliary data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type == SCM_RIGHTS)
			return (*(int *) CMSG_DATA(cmsg));
	}

	errno = EINVAL;
	return -1;
}

const char *bt_audio_strmsg(int type)
{
	if (type < 0 || type > (sizeof(strmsg) / sizeof(strmsg[0])))
		return NULL;

	return strmsg[type];
}

