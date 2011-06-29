/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#include <stdint.h>

#include <gobex/gobex-packet.h>

#include "util.h"

static void test_pkt(void)
{
	GObexPacket *pkt;

	pkt = g_obex_packet_new(G_OBEX_OP_PUT, TRUE);

	g_assert(pkt != NULL);

	g_obex_packet_free(pkt);
}

static void test_decode_pkt(void)
{
	GObexPacket *pkt;
	uint8_t buf[] = { G_OBEX_OP_PUT, 0x00, 0x03 };
	GError *err = NULL;

	pkt = g_obex_packet_decode(buf, sizeof(buf), 0, G_OBEX_DATA_REF, &err);
	g_assert_no_error(err);

	g_obex_packet_free(pkt);
}

static void test_decode_pkt_header(void)
{
	GObexPacket *pkt;
	GObexHeader *header;
	GError *err = NULL;
	gboolean ret;
	uint8_t buf[] = { G_OBEX_OP_PUT, 0x00, 0x05,
					G_OBEX_HDR_ID_ACTION, 0xab };
	guint8 val;

	pkt = g_obex_packet_decode(buf, sizeof(buf), 0, G_OBEX_DATA_REF, &err);
	g_assert_no_error(err);

	header = g_obex_packet_get_header(pkt, G_OBEX_HDR_ID_ACTION);
	g_assert(header != NULL);

	ret = g_obex_header_get_uint8(header, &val);
	g_assert(ret == TRUE);
	g_assert(val == 0xab);

	g_obex_packet_free(pkt);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gobex/test_pkt", test_pkt);
	g_test_add_func("/gobex/test_decode_pkt", test_decode_pkt);
	g_test_add_func("/gobex/test_decode_pkt_header",
						test_decode_pkt_header);

	g_test_run();

	return 0;
}
