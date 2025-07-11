// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <stdbool.h>

#include <ell/dbus.h>
#include <ell/log.h>
#include <ell/util.h>			// l_get_be16(), l_put_be16()

#include "src/shared/ad.h"

#include "mesh/crypto.h"		// mesh_crypto_network_header_parse()
#include "mesh/mesh-io.h"		// mesh_io_recv_func_t, required by gatt-proxy-svc.h
#include "mesh/gatt-proxy-svc.h"	// gatt_proxy_svc_filter_set_type(),
					// gatt_proxy_svc_filter_add(),
					// gatt_proxy_svc_filter_remove(),
					// gatt_proxy_svc_filter_count(),
					// gatt_proxy_svc_send()
#include "mesh/mesh-defs.h"		// UNASSIGNED_ADDRESS
#include "mesh/net.h"			// PROXY_OP_SET_FILTER_TYPE,
					// PROXY_OP_FILTER_ADD,
					// PROXY_OP_FILTER_DEL,
					// PROXY_OP_FILTER_STATUS,
					// mesh_net_next_seq_num(),
					// mesh_net_get_address()
#include "mesh/net-keys.h"		// net_key_encrypt(),
					// net_key_decrypt_proxy_cfg_msg()
#include "mesh/util.h"			// print_packet()
#include "mesh/proxy-cfg.h"

void proxy_cfg_msg_received(struct gatt_proxy_svc *gatt_proxy,
					struct mesh_net *net,
					uint32_t net_key_id, uint32_t iv_index,
					const uint8_t *data, uint8_t size)
{
	const uint8_t *msg;
	uint8_t cfg_msg_len;
	uint8_t net_ttl;
	uint32_t net_seq;
	uint16_t net_src, net_dst;
	bool net_ctl;
	uint8_t rsp[4];  // length of PROXY_OP_FILTER_STATUS
	uint8_t rsp_len = 0;

	print_packet("RX: ProxyCfg [clr] :", data, size);

	if (!mesh_crypto_network_header_parse(data, size, &net_ctl, &net_ttl,
					&net_seq, &net_src, &net_dst)) {
		l_error("Failed to parse packet content");
		return;
	}

	/*
	 * MshPRT_v1.1, section 6.6:
	 * - The CTL field shall be set to 1. [already checked]
	 * - The TTL field shall be set to 0.
	 * - The DST field shall be set to the unassigned address.
	 */
	if (net_dst != UNASSIGNED_ADDRESS || net_ttl) {
		l_error("illegal parms: DST: %4.4x Ctl: %d TTL: %2.2x",
						net_dst, net_ctl, net_ttl);
		return;
	}

	l_debug("RX: ProxyCfg %04x -> %04x : TTL 0x%02x : IV : %8.8x SEQ 0x%06x",
			net_src, net_dst, net_ttl, iv_index, net_seq);

	msg = data + 9;
	cfg_msg_len = size - 9 - 8 /* NetMIC */;

	if (!cfg_msg_len)
		return;

	/* process request */
	switch (msg[0]) {
		case PROXY_OP_SET_FILTER_TYPE:
			if (cfg_msg_len >= 2) {
				uint8_t filter_type;

				filter_type = msg[1];
				gatt_proxy_svc_filter_set_type(gatt_proxy,
								filter_type);
			}
			break;

		case PROXY_OP_FILTER_ADD:
			if (cfg_msg_len & 0x1) {
				int num_filters = (cfg_msg_len - 1) / 2, i;
				uint16_t addr;

				for (i = 0; i < num_filters; i++) {
					addr = l_get_be16(msg + 2 * i + 1);
					gatt_proxy_svc_filter_add(gatt_proxy,
									addr);
				}
			}
			break;

		case PROXY_OP_FILTER_DEL:
			if (cfg_msg_len & 0x1) {
				int num_filters = (cfg_msg_len - 1) / 2, i;
				uint16_t addr;

				for (i = 0; i < num_filters; i++) {
					addr = l_get_be16(msg + 2 * i + 1);
					gatt_proxy_svc_filter_remove(gatt_proxy,
									addr);
				}
			}
			break;

		default:
			break;
	}

	/* prepare response */
	switch (msg[0]) {
		case PROXY_OP_SET_FILTER_TYPE:
		case PROXY_OP_FILTER_ADD:
		case PROXY_OP_FILTER_DEL: {
			uint8_t filter_type;
			uint16_t num_filters =
				gatt_proxy_svc_filter_count(gatt_proxy,
								&filter_type);
			rsp[0] = PROXY_OP_FILTER_STATUS;
			rsp[1] = filter_type;
			l_put_be16(num_filters, &rsp[2]);
			rsp_len = 4;
			break;
		}

		/*
		 * MshPRT_v1.1, section 6.7:
		 * Upon receiving a proxy configuration message with the Opcode
		 * field set to a value that is Reserved for Future Use, the
		 * Proxy Server shall ignore this message.
		 */
		default:
			break;
	}

	if (rsp_len) {
		uint8_t pkt[MESH_NET_MAX_PDU_LEN];
		uint8_t pkt_len;

		net_seq = mesh_net_next_seq_num(net);
		if (!mesh_crypto_packet_build(true, 0/*TTL*/, net_seq,
					mesh_net_get_address(net)/*src*/,
					UNASSIGNED_ADDRESS/*dst*/, rsp[0],
					false, 0, false, 0, 0, 0,
					rsp + 1, rsp_len - 1, pkt, &pkt_len))
			return;

		if (!net_key_encrypt(net_key_id, iv_index, pkt, pkt_len)) {
			l_error("Failed to encode packet");
			return;
		}

		gatt_proxy_svc_send_proxy_cfg(pkt, pkt_len);
	}
}
