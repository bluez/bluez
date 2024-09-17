/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2024  Collabora Ltd.
 *
 *
 */

#include <glib.h>
#include "gdbus/gdbus.h"

struct prop_object;

struct prop_object *parse_properties(char *data, unsigned int length,
							int *err);
gboolean verify_properties(struct prop_object *obj);
void append_properties(DBusMessageIter *args, struct prop_object *obj);
