/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct rtp_header {
	uint8_t cc:4;
	uint8_t x:1;
	uint8_t p:1;
	uint8_t v:2;

	uint8_t pt:7;
	uint8_t m:1;

	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} __attribute__ ((packed));

struct rtp_payload {
	uint8_t frame_count:4;
	uint8_t rfa0:1;
	uint8_t is_last_fragment:1;
	uint8_t is_first_fragment:1;
	uint8_t is_fragmented:1;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct rtp_header {
	uint8_t v:2;
	uint8_t p:1;
	uint8_t x:1;
	uint8_t cc:4;

	uint8_t m:1;
	uint8_t pt:7;

	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} __attribute__ ((packed));

struct rtp_payload {
	uint8_t is_fragmented:1;
	uint8_t is_first_fragment:1;
	uint8_t is_last_fragment:1;
	uint8_t rfa0:1;
	uint8_t frame_count:4;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif
