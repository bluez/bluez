/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009  Intel Corporation
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "phonebook.h"

int phonebook_pullphonebook(obex_t *obex, obex_object_t *obj,
				struct apparam_field params)
{
	return 0;
}

int phonebook_pullvcardlisting(obex_t *obex, obex_object_t *obj,
				struct apparam_field params)
{
	return 0;
}

int phonebook_pullvcardentry(obex_t *obex, obex_object_t *obj,
				struct apparam_field params)
{
	return 0;
}
