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

#include <stdio.h>
#include <ctype.h>
#include "if-main.h"
#include "terminal.h"

/* how many times tab was hit */
static int tab_hit_count;

typedef struct split_arg {
	struct split_arg *next; /* next argument in buffer */
	const char *origin; /* pointer to original argument */
	char ntcopy[1]; /* null terminated copy of argument */
} split_arg_t;

/* function returns interface of given name or NULL if not found */
static const struct interface *get_interface(const char *name)
{
	int i;

	for (i = 0; interfaces[i] != NULL; ++i) {
		if (strcmp(interfaces[i]->name, name) == 0)
			break;
	}

	return interfaces[i];
}

/* function returns method of given name or NULL if not found */
static const struct method *get_method(const char *iname, const char *mname)
{
	int i;
	const struct interface *iface = get_interface(iname);

	if (iface == NULL)
		return NULL;

	for (i = 0; iface->methods[i].name[0]; ++i) {
		if (0 == strcmp(iface->methods[i].name, mname))
			return &iface->methods[i];
	}
	return NULL;
}

/* prints matching elements */
static void print_matches(enum_func f, void *user, const char *prefix, int len)
{
	int i;
	const char *enum_name;

	putchar('\n');
	for (i = 0; NULL != (enum_name = f(user, i)); ++i) {
		if (strncmp(enum_name, prefix, len) == 0)
			printf("%s\t", enum_name);
	}
	putchar('\n');
	terminal_draw_command_line();
}

/*
 * This function splits command line into linked list of arguments.
 * line_buffer - pointer to input comman line
 * size - size of command line to parse
 * buf - output buffer to keep splited arguments list
 * buf_size_in_bytes - size of buf
 */
static int split_command(const char *line_buffer, int size,
					split_arg_t *buf, int buf_size_in_bytes)
{
	split_arg_t *prev = NULL;
	split_arg_t *arg = buf;
	int argc = 0;
	const char *p = line_buffer;
	const char *e = p + (size > 0 ? size : (int) strlen(p));
	int len;

	do {
		while (p < e && isspace(*p))
			p++;
		arg->origin = p;
		arg->next = NULL;
		while (p < e && !isspace(*p))
			p++;
		len = p - arg->origin;
		if (&arg->ntcopy[0] + len + 1 >
			(const char *) buf + buf_size_in_bytes)
			break;
		strncpy(arg->ntcopy, arg->origin, len);
		arg->ntcopy[len] = 0;
		if (prev != NULL)
			prev->next = arg;
		prev = arg;
		arg += (2 * sizeof(*arg) + len) / sizeof(*arg);
		argc++;
	} while (p < e);

	return argc;
}

/* Function to enumerate interface names */
static const char *interface_name(void *v, int i)
{
	return interfaces[i] ? interfaces[i]->name : NULL;
}

/* Function to enumerate method names */
static const char *methods_name(void *v, int i)
{
	const struct interface *iface = v;

	return iface->methods[i].name[0] ? iface->methods[i].name : NULL;
}

struct command_completion_args;
typedef void (*short_help)(struct command_completion_args *args);

struct command_completion_args {
	const split_arg_t *arg; /* list of arguments */
	const char *typed; /* last typed element */
	enum_func func; /* enumerating function */
	void *user; /* argument to enumerating function */
	short_help help; /* help function */
	void *user_help; /* additional data (used by short_help) */
};

/*
 * complete command line
 */
static void command_completion(struct command_completion_args *args)
{
	const char *name = args->typed;
	const int len = strlen(name);
	int i;
	int j;
	char prefix[128] = {0};
	int prefix_len = 0;
	int count = 0;
	const char *enum_name;

	for (i = 0; NULL != (enum_name = args->func(args->user, i)); ++i) {
		/* prefix does not match */
		if (strncmp(enum_name, name, len) != 0)
			continue;
		/* prefix matches first time */
		if (count++ == 0) {
			strcpy(prefix, enum_name);
			prefix_len = strlen(prefix);
			continue;
		}
		/*
		 * Prefix matches next time
		 * reduce prefix to common part
		 */
		for (j = 0; prefix[j] != 0
			&& prefix[j] == enum_name[j];)
			++j;
		prefix_len = j;
		prefix[j] = 0;
	}

	if (count == 0) {
		/* no matches */
		if (args->help != NULL)
			args->help(args);
		tab_hit_count = 0;
		return;
	}
	/* len == prefix_len => nothing new was added */
	if (len == prefix_len) {
		if (count != 1) {
			if (tab_hit_count == 1)
				putchar('\a');
			else if (tab_hit_count == 2 ||
					args->help == NULL) {
				print_matches(args->func,
						args->user, name, len);
			} else {
				args->help(args);
				tab_hit_count = 1;
			}
		} else if (count == 1) {
			/* nothing to add, exact match add space */
			terminal_insert_into_command_line(" ");
		}
	} else {
		/* new chars can be added from some interface name(s) */
		if (count == 1) {
			/* exact match, add space */
			prefix[prefix_len++] = ' ';
			prefix[prefix_len] = '\0';
		}
		terminal_insert_into_command_line(prefix + len);
		tab_hit_count = 0;
	}
}

/* interface completion */
static void interface_completion(split_arg_t *arg)
{
	struct command_completion_args args = {
		.arg = arg,
		.typed = arg->ntcopy,
		.func = interface_name
	};

	command_completion(&args);
}

/* method completion */
static void method_completion(const struct interface *iface, split_arg_t *arg)
{
	struct command_completion_args args = {
		.arg = arg,
		.typed = arg->next->ntcopy,
		.func = methods_name,
		.user = (void *) iface
	};

	if (iface == NULL)
		return;

	command_completion(&args);
}

/* prints short help on method for interface */
static void method_help(struct command_completion_args *args)
{
	if (args->user_help == NULL)
		return;

	haltest_info("%s %s %s\n", args->arg->ntcopy,
		args->arg->next->ntcopy, args->user_help);
}

/* So we have empty enumeration */
static const char *return_null(void *user, int i)
{
	return NULL;
}

/* parameter completion function */
static void param_completion(int argc, const split_arg_t *arg)
{
	const struct method *method;
	int i;
	const char *argv[argc];
	const split_arg_t *tmp = arg;
	struct command_completion_args args = {
		.arg = arg,
		.func = return_null
	};

	/* prepare standard argv from arg */
	for (i = 0; i < argc; ++i) {
		argv[i] = tmp->ntcopy;
		tmp = tmp->next;
	}

	/* Find method for <interface, name> pair */
	method = get_method(argv[0], argv[1]);

	if (method != NULL && method->complete != NULL) {
		/* ask method for completion function */
		method->complete(argc, argv, &args.func, &args.user);
	}

	/* If method provided enumeration function call try to complete */
	if (args.func != NULL) {
		args.typed = argv[argc - 1];
		args.help = method_help;
		args.user_help = (void *) method->help;

		command_completion(&args);
	}
}

/*
 * This methd gets called when user tapped tab key.
 * line - points to comman line
 * len - size of line that should be used for comletions. This should be
 *   cursor position during tab hit.
 */
void process_tab(const char *line, int len)
{
	int argc;
	static split_arg_t buf[(LINE_BUF_MAX * 2) / sizeof(split_arg_t)];

	argc = split_command(line, len, buf, sizeof(buf));
	tab_hit_count++;

	if (argc == 1)
		interface_completion(buf);
	else if (argc == 2)
		method_completion(get_interface(buf[0].ntcopy), buf);
	else if (argc > 2)
		param_completion(argc, buf);
}
