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
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <poll.h>
#include <unistd.h>

#include "if-main.h"
#include "terminal.h"
#include "pollhandler.h"
#include "history.h"

const struct interface *interfaces[] = {
	&bluetooth_if,
	NULL
};

int haltest_error(const char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = terminal_vprint(format, args);
	va_end(args);
	return ret;
}

int haltest_info(const char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = terminal_vprint(format, args);
	va_end(args);
	return ret;
}

int haltest_warn(const char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = terminal_vprint(format, args);
	va_end(args);
	return ret;
}

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
	int i = 0;
	int j;

	argc = command_line_to_argv(line_buffer, argv, 10);
	if (argc < 1)
		return;

	while (interfaces[i] != NULL) {
		if (strcmp(interfaces[i]->name, argv[0])) {
			i++;
			continue;
		}
		if (argc < 2 || strcmp(argv[1], "?") == 0) {
			j = 0;
			while (strcmp(interfaces[i]->methods[j].name, "")) {
				haltest_info("%s %s\n", argv[0],
						interfaces[i]->methods[j].name);
				++j;
			}
			return;
		}
		j = 0;
		while (strcmp(interfaces[i]->methods[j].name, "")) {
			if (strcmp(interfaces[i]->methods[j].name, argv[1])) {
				j++;
				continue;
			}
			interfaces[i]->methods[j].func(argc,
							(const char **)argv);
			break;
		}
		if (strcmp(interfaces[i]->methods[j].name, "") == 0)
			printf("No function %s found\n", argv[1]);
		break;
	}

	if (interfaces[i] == NULL)
		printf("No such interface %s\n", argv[0]);
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
	history_restore(".haltest_history");

	/* Register command line handler */
	poll_register_fd(0, POLLIN, stdin_handler);

	poll_dispatch_loop();

	return 0;
}
