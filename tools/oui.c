/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>

#include "oui.h"

/* http://standards.ieee.org/regauth/oui/oui.txt */

#define OUIFILE "/usr/share/misc/oui.txt"

#define AWKCMD "/usr/bin/awk"
#define TRCMD  "/usr/bin/tr"

char *ouitocomp(const char *oui)
{
	struct stat st;
	FILE *input;
	char cmd[512];
	char *str;
	size_t len;

	if (stat(OUIFILE, &st) < 0)
		return NULL;

	if (stat(AWKCMD, &st) < 0)
		return NULL;

	if (stat(TRCMD, &st) < 0)
		return NULL;

	str = malloc(128);
	if (!str)
		return NULL;

	memset(str, 0, 128);

	snprintf(cmd, sizeof(cmd) - 1, "%s -F'\\t' '/^"
		"%s.*\\(hex\\).*/{ print $3 }' %s"
		" | %s -d '\\n\\r'", AWKCMD, oui, OUIFILE, TRCMD);

	input = popen(cmd, "r");
	if (!input) {
		free(str);
		return NULL;
	}

	len = fread(str, 127, 1, input);
	pclose(input);

	return str;
}

int oui2comp(const char *oui, char *comp, size_t size)
{
	char *tmp;

	tmp = ouitocomp(oui);
	if (!tmp)
		return -1;

	snprintf(comp, size, "%s", tmp);

	free(tmp);

	return 0;
}
