/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#ifndef __MCAP_INTERNAL_H
#define __MCAP_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

struct mcap_instance {
	bdaddr_t		src;			/* Source address */
	GIOChannel		*ccio;			/* Control Channel IO */
	GIOChannel		*dcio;			/* Data Channel IO */
	GSList			*mcls;			/* MCAP instance list */
	GSList			*cached;		/* List with all cached MCLs (MAX_CACHED macro) */
	BtIOSecLevel		sec;			/* Security level */
	mcap_mcl_event_cb	mcl_connected_cb;	/* New MCL connected */
	mcap_mcl_event_cb	mcl_reconnected_cb;	/* Old MCL has been reconnected */
	mcap_mcl_event_cb	mcl_disconnected_cb;	/* MCL disconnected */
	mcap_mcl_event_cb	mcl_uncached_cb;	/* MCL has been removed from MCAP cache */
	gpointer		user_data;		/* Data to be provided in callbacks */
};

#ifdef __cplusplus
}
#endif

#endif /* __MCAP_INTERNAL_H */
