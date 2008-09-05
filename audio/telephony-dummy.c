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
#include <stdint.h>
#include <glib.h>

#include "telephony.h"

static gboolean events_enabled = FALSE;

/* Response and hold state
 * -1 = none
 *  0 = incoming call is put on hold in the AG
 *  1 = held incoming call is accepted in the AG
 *  2 = held incoming call is rejected in the AG
 */
static int response_and_hold = -1;

static struct indicator dummy_indicators[] =
{
	{ "battchg",	"0-5",	5 },
	{ "signal",	"0-5",	5 },
	{ "service",	"0,1",	1 },
	{ "call",	"0,1",	0 },
	{ "callsetup",	"0-3",	0 },
	{ "callheld",	"0-2",	0 },
	{ "roam",	"0,1",	0 },
	{ NULL }
};

int telephony_event_reporting_req(int ind)
{
	events_enabled = ind == 1 ? TRUE : FALSE;

	return 0;
}

int telephony_response_and_hold_req(int rh)
{
	response_and_hold = rh;

	telephony_response_and_hold_ind(response_and_hold);

	return 0;
}

int telephony_last_dialed_number(void)
{
	/* Notify outgoing call set-up successfully initiated */
	telephony_update_indicator(dummy_indicators, "callsetup",
					EV_CALLSETUP_OUTGOING);
	return 0;
}

int telephony_terminate_call(void)
{
	if (telephony_get_indicator(dummy_indicators, "callsetup") > 0)
		telephony_update_indicator(dummy_indicators, "callsetup",
						EV_CALLSETUP_INACTIVE);
	else
		telephony_update_indicator(dummy_indicators, "call",
						EV_CALL_INACTIVE);
	return 0;
}

int telephony_answer_call(void)
{
	telephony_update_indicator(dummy_indicators, "call", EV_CALL_ACTIVE);
	telephony_update_indicator(dummy_indicators, "callsetup",
					EV_CALLSETUP_INACTIVE);
	return 0;
}

int telephony_init(void)
{
	uint32_t features = 0;

	telephony_ready(features, dummy_indicators, response_and_hold);

	return 0;
}

void telephony_exit(void)
{
}
