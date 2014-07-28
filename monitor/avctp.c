/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <bluetooth/bluetooth.h>

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "uuid.h"
#include "keys.h"
#include "sdp.h"
#include "avctp.h"

void avctp_packet(const struct l2cap_frame *frame)
{
        uint8_t hdr;
        uint16_t pid;
        const char *pdu_color;

        if (frame->size < 3) {
                print_text(COLOR_ERROR, "frame too short");
                packet_hexdump(frame->data, frame->size);
                return;
        }

        hdr = *((uint8_t *) frame->data);

        pid = get_be16(frame->data + 1);

        if (frame->in)
                pdu_color = COLOR_MAGENTA;
        else
                pdu_color = COLOR_BLUE;

        print_indent(6, pdu_color, "AVCTP", "", COLOR_OFF,
                        " %s: %s: type 0x%02x label %d PID 0x%04x",
                        frame->psm == 23 ? "Control" : "Browsing",
                        hdr & 0x02 ? "Response" : "Command",
                        hdr & 0x0c, hdr >> 4, pid);

	packet_hexdump(frame->data + 3, frame->size - 3);
}
