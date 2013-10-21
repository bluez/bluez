/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <stdint.h>

#include <cutils/properties.h>

#include "hal-msg.h"
#include "hal-log.h"
#include "hal-ipc.h"

#define CONNECT_TIMEOUT (5 * 1000)
#define SERVICE_NAME "bluetoothd"

static int cmd_sk = -1;
static int notif_sk = -1;

static int accept_connection(int sk)
{
	int err;
	struct pollfd pfd;
	int new_sk;

	memset(&pfd, 0 , sizeof(pfd));
	pfd.fd = sk;
	pfd.events = POLLIN;

	err = poll(&pfd, 1, CONNECT_TIMEOUT);
	if (err < 0) {
		err = errno;
		error("Failed to poll: %d (%s)", err, strerror(err));
		return -1;
	}

	if (err == 0) {
		error("bluetoothd connect timeout");
		return -1;
	}

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		err = errno;
		error("Failed to accept socket: %d (%s)", err, strerror(err));
		return -1;
	}

	return new_sk;
}

bool hal_ipc_init(void)
{
	struct sockaddr_un addr;
	int sk;
	int err;

	sk = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		err = errno;
		error("Failed to create socket: %d (%s)", err,
							strerror(err));
		return false;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_HAL_SK_PATH, sizeof(BLUEZ_HAL_SK_PATH));

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("Failed to bind socket: %d (%s)", err, strerror(err));
		close(sk);
		return false;
	}

	if (listen(sk, 2) < 0) {
		err = errno;
		error("Failed to listen on socket: %d (%s)", err,
								strerror(err));
		close(sk);
		return false;
	}

	/* Start Android Bluetooth daemon service */
	property_set("ctl.start", SERVICE_NAME);

	cmd_sk = accept_connection(sk);
	if (cmd_sk < 0) {
		close(sk);
		return false;
	}

	notif_sk = accept_connection(sk);
	if (notif_sk < 0) {
		close(sk);
		close(cmd_sk);
		cmd_sk = -1;
		return false;
	}

	info("bluetoothd connected");

	close(sk);

	return true;
}

void hal_ipc_cleanup(void)
{
	close(cmd_sk);
	cmd_sk = -1;

	close(notif_sk);
	notif_sk = -1;
}
