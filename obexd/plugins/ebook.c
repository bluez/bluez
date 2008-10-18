/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <plugin.h>
#include <logging.h>
#include <phonebook.h>

#include <libebook/e-book.h>

static int ebook_create(struct phonebook_context *context)
{
	DBG("context %p", context);

	return 0;
}

static void ebook_destroy(struct phonebook_context *context)
{
	DBG("context %p", context);
}

static struct phonebook_driver ebook_driver = {
	.name		= "ebook",
	.create		= ebook_create,
	.destroy	= ebook_destroy,
};

static int ebook_init(void)
{
	return phonebook_driver_register(&ebook_driver);
}

static void ebook_exit(void)
{
	phonebook_driver_unregister(&ebook_driver);
}

OBEX_PLUGIN_DEFINE("ebook", ebook_init, ebook_exit)
