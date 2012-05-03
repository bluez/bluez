/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2011 Intel Corporation
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

#include <gdbus.h>

#include "log.h"

#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "opp.h"

#define OPP_UUID "00001105-0000-1000-8000-00805f9b34fb"

static struct obc_driver opp = {
	.service = "OPP",
	.uuid = OPP_UUID,
};

int opp_init(void)
{
	DBG("");

	return obc_driver_register(&opp);
}

void opp_exit(void)
{
	DBG("");

	obc_driver_unregister(&opp);
}
