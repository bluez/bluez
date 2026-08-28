// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>

#include <glib.h>

#include "phonebook.h"

static unsigned int refcount = 0;

int phonebook_init(void)
{
	int err;

	if (refcount > 0) {
		refcount++;
		return 0;
	}

	err = phonebook_driver_init();
	if (err < 0)
		return err;

	refcount = 1;

	return 0;
}

void phonebook_exit(void)
{
	if (refcount == 0 || --refcount > 0)
		return;

	phonebook_driver_exit();
}
