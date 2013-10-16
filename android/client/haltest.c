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

#include <stdlib.h>
#include <poll.h>
#include <unistd.h>

#include "pollhandler.h"


/* called when there is something on stdin */
static void stdin_handler(struct pollfd *pollfd)
{
	char buf[10];

	if (pollfd->revents & POLLIN) {
		int count = read(0, buf, 10);

		if (count > 0) {
			int i;

			for (i = 0; i < count; ++i) {
				/* TODO: process input */
			}
		}
	}
}

int main(int argc, char **argv)
{
	/* Register command line handler */
	poll_register_fd(0, POLLIN, stdin_handler);

	poll_dispatch_loop();

	return 0;
}
