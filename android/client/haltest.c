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

#include "terminal.h"
#include "pollhandler.h"

/*
 * This function changes input parameter line_buffer so it has
 * null termination after each token (due to strtok)
 * Output argv is filled with pointers to arguments
 * returns number of tokens parsed - argc
 */
static int command_line_to_argv(char *line_buffer,
				char *argv[], int argv_size)
{
	static const char *token_breaks = "\r\n\t ";
	char *token;
	int argc = 0;

	token = strtok(line_buffer, token_breaks);
	while (token != NULL && argc < (int) argv_size) {
		argv[argc++] = token;
		token = strtok(NULL, token_breaks);
	}

	return argc;
}

static void process_line(char *line_buffer)
{
	char *argv[10];
	int argc;

	argc = command_line_to_argv(line_buffer, argv, 10);

	/* TODO: process command line */
}

/* called when there is something on stdin */
static void stdin_handler(struct pollfd *pollfd)
{
	char buf[10];

	if (pollfd->revents & POLLIN) {
		int count = read(0, buf, 10);

		if (count > 0) {
			int i;

			for (i = 0; i < count; ++i)
				terminal_process_char(buf[i], process_line);
		}
	}
}

int main(int argc, char **argv)
{
	terminal_setup();

	/* Register command line handler */
	poll_register_fd(0, POLLIN, stdin_handler);

	poll_dispatch_loop();

	return 0;
}
