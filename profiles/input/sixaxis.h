/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2009,2017  Bastien Nocera <hadess@hadess.net>
 *  Copyright (C) 2011  Antonio Ospite <ospite@studenti.unina.it>
 *  Copyright (C) 2013  Szymon Janc <szymon.janc@gmail.com>
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

#ifndef _SIXAXIS_H_
#define _SIXAXIS_H_

typedef enum {
	CABLE_PAIRING_UNSUPPORTED = 0,
	CABLE_PAIRING_SIXAXIS,
	CABLE_PAIRING_DS4,
} CablePairingType;

struct cable_pairing {
	const char *name;
	uint16_t source;
	uint16_t vid;
	uint16_t pid;
	uint16_t version;
	CablePairingType type;
};

static inline const struct cable_pairing *
get_pairing(uint16_t vid, uint16_t pid)
{
	static const struct cable_pairing devices[] = {
		{
			.name = "Sony PLAYSTATION(R)3 Controller",
			.source = 0x0002,
			.vid = 0x054c,
			.pid = 0x0268,
			.version = 0x0000,
			.type = CABLE_PAIRING_SIXAXIS,
		},
		{
			.name = "Navigation Controller",
			.source = 0x0002,
			.vid = 0x054c,
			.pid = 0x042f,
			.version = 0x0000,
			.type = CABLE_PAIRING_SIXAXIS,
		},
		{
			.name = "Wireless Controller",
			.source = 0x0002,
			.vid = 0x054c,
			.pid = 0x05c4,
			.version = 0x0001,
			.type = CABLE_PAIRING_DS4,
		},
		{
			.name = "Wireless Controller",
			.source = 0x0002,
			.vid = 0x054c,
			.pid = 0x09cc,
			.version = 0x0001,
			.type = CABLE_PAIRING_DS4,
		},
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS(devices); i++) {
		if (devices[i].vid != vid)
			continue;
		if (devices[i].pid != pid)
			continue;

		return &devices[i];
	}

	return NULL;
}

#endif /* _SIXAXIS_H_ */
