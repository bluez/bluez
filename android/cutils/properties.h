/*
 * Copyright (C) 2006 The Android Open Source Project
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
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

/* property_set: returns 0 on success, < 0 on failure
*/
static inline int property_set(const char *key, const char *value)
{
	static const char SYSTEM_SOCKET_PATH[] = "\0android_system";

	struct sockaddr_un addr;
	char msg[256];
	int fd, len;

	fd = socket(PF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SYSTEM_SOCKET_PATH, sizeof(SYSTEM_SOCKET_PATH));

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		return 0;
	}

	len = snprintf(msg, sizeof(msg), "%s=%s", key, value);

	if (send(fd, msg, len + 1, 0) < 0) {
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}
