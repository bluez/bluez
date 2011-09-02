/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2010-2011  Nokia Corporation
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "messages.h"

static char *root_folder = NULL;

struct session {
	char *cwd;
	char *cwd_absolute;
};

int messages_init(void)
{
	char *tmp;

	if (root_folder)
		return 0;

	tmp = getenv("MAP_ROOT");
	if (tmp) {
		root_folder = g_strdup(tmp);
		return 0;
	}

	tmp = getenv("HOME");
	if (!tmp)
		return -ENOENT;

	root_folder = g_build_filename(tmp, "map-messages", NULL);

	return 0;
}

void messages_exit(void)
{
	g_free(root_folder);
	root_folder = NULL;
}

int messages_connect(void **s)
{
	struct session *session;

	session = g_new0(struct session, 1);
	session->cwd = g_strdup("");
	session->cwd_absolute = g_strdup(root_folder);

	*s = session;

	return 0;
}

void messages_disconnect(void *s)
{
	struct session *session = s;

	g_free(session->cwd);
	g_free(session->cwd_absolute);
	g_free(session);
}

int messages_set_notification_registration(void *session,
		void (*send_event)(void *session,
			const struct messages_event *event, void *user_data),
		void *user_data)
{
	return -EINVAL;
}

int messages_set_folder(void *s, const char *name, gboolean cdup)
{
	struct session *session = s;
	char *newrel = NULL;
	char *newabs;
	char *tmp;

	if (name && (strchr(name, '/') || strcmp(name, "..") == 0))
		return -EBADR;

	if (cdup) {
		if (session->cwd[0] == 0)
			return -ENOENT;

		newrel = g_path_get_dirname(session->cwd);

		/* We use empty string for indication of the root directory */
		if (newrel[0] == '.' && newrel[1] == 0)
			newrel[0] = 0;
	}

	tmp = newrel;
	if (!cdup && (!name || name[0] == 0))
		newrel = g_strdup("");
	else
		newrel = g_build_filename(newrel ? newrel : session->cwd, name,
				NULL);
	g_free(tmp);

	newabs = g_build_filename(root_folder, newrel, NULL);

	if (!g_file_test(newabs, G_FILE_TEST_IS_DIR)) {
		g_free(newrel);
		g_free(newabs);
		return -ENOENT;
	}

	g_free(session->cwd);
	session->cwd = newrel;

	g_free(session->cwd_absolute);
	session->cwd_absolute = newabs;

	return 0;
}

int messages_get_folder_listing(void *session,
		const char *name,
		uint16_t max, uint16_t offset,
		messages_folder_listing_cb callback,
		void *user_data)
{
	return -EINVAL;
}

int messages_get_messages_listing(void *session,
		const char *name,
		uint16_t max, uint16_t offset,
		const struct messages_filter *filter,
		messages_get_messages_listing_cb callback,
		void *user_data)
{
	return -EINVAL;
}

int messages_get_message(void *session,
		const char *handle,
		unsigned long flags,
		messages_get_message_cb callback,
		void *user_data)
{
	return -EINVAL;
}

void messages_abort(void *session)
{
}
