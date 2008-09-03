/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <stdio.h>

#include "telephony.h"

static struct indicator indicators[] =
{
	{ "battchg",	"0-5",	5 },
	{ "signal",	"0-5",	5 },
	{ "service",	"0,1",	1 },
	{ "sounder",	"0,1",	0 },
	{ "message",	"0,1",	0 },
	{ "call",	"0,1",	0 },
	{ "callsetup",	"0-3",	0 },
	{ "vox",	"0,1",	0 },
	{ "roam",	"0,1",	0 },
	{ "smsfull",	"0,1",	0 },
	{ NULL }
};

int telephony_features_req(void)
{
	uint32_t features = 0;

	telephony_features_rsp(features);

	return 0;
}

struct indicator *telephony_indicators_req(void)
{
	return indicators;
}

int telephony_init(void)
{
	return 0;
}

void telephony_exit(void)
{
}
