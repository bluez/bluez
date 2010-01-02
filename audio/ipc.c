/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* This table contains the string representation for messages types */
static const char *strtypes[] = {
	"BT_REQUEST",
	"BT_RESPONSE",
	"BT_INDICATION",
	"BT_ERROR",
};

/* This table contains the string representation for messages names */
static const char *strnames[] = {
	"BT_GET_CAPABILITIES",
	"BT_OPEN",
	"BT_SET_CONFIGURATION",
	"BT_NEW_STREAM",
	"BT_START_STREAM",
	"BT_STOP_STREAM",
	"BT_SUSPEND_STREAM",
	"BT_RESUME_STREAM",
	"BT_CONTROL",
};

int bt_audio_service_open(void)
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
				&& cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&ret, CMSG_DATA(cmsg), sizeof(int));
			return ret;
		}
	}

	errno = EINVAL;
	return -1;
}

const char *bt_audio_strtype(uint8_t type)
{
	if (type >= ARRAY_SIZE(strtypes))
		return NULL;

	return strtypes[type];
}

const char *bt_audio_strname(uint8_t name)
{
	if (name >= ARRAY_SIZE(strnames))
		return NULL;

	return strnames[name];
}
