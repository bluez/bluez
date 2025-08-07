// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *  Copyright 2023-2024 NXP
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <time.h>

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/iso.h"
#include "bluetooth/mgmt.h"
#include "bluetooth/uuid.h"

#include "monitor/bt.h"
#include "emulator/vhci.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#include "tester.h"

#define EIR_SERVICE_DATA_16	0x16

#define QOS_IO(_interval, _latency, _sdu, _phy, _rtn) \
{ \
	.interval = _interval, \
	.latency = _latency, \
	.sdu = _sdu, \
	.phy = _phy, \
	.rtn = _rtn, \
}

#define QOS_FULL(_cig, _cis, _in, _out) \
{ \
	.ucast = { \
		.cig = _cig, \
		.cis = _cis, \
		.sca = 0x07, \
		.packing = 0x00, \
		.framing = 0x00, \
		.in = _in, \
		.out = _out, \
	},\
}

#define QOS(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_2(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x02, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_1_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x01, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_1_2(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x02, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, \
		{}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, BT_ISO_QOS_CIS_UNSET, \
		{}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT_1_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x01, \
		{}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT_1_2(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x02, \
		{}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT_1_EF(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0xEF, \
		{}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_IN(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(BT_ISO_QOS_CIG_UNSET, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})
#define QOS_IN_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})
#define QOS_IN_2(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x02, BT_ISO_QOS_CIS_UNSET, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})
#define QOS_IN_1_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x01, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})
#define QOS_IN_1_2(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(0x01, 0x02, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})

/* QoS Configuration settings for low latency audio data */
#define QOS_8_1_1 QOS(7500, 8, 26, 0x02, 2)
#define QOS_8_2_1 QOS(10000, 10, 30, 0x02, 2)
#define QOS_16_1_1 QOS(7500, 8, 30, 0x02, 2)
#define QOS_16_2_1 QOS(10000, 10, 40, 0x02, 2)
#define QOS_1_16_2_1 QOS_1(10000, 10, 40, 0x02, 2)
#define QOS_2_16_2_1 QOS_2(10000, 10, 40, 0x02, 2)
#define QOS_1_1_16_2_1 QOS_1_1(10000, 10, 40, 0x02, 2)
#define QOS_24_1_1 QOS(7500, 8, 45, 0x02, 2)
#define QOS_24_2_1 QOS(10000, 10, 60, 0x02, 2)
#define QOS_32_1_1 QOS(7500, 8, 60, 0x02, 2)
#define QOS_32_2_1 QOS(10000, 10, 80, 0x02, 2)
#define QOS_44_1_1 QOS_OUT(8163, 24, 98, 0x02, 5)
#define QOS_44_2_1 QOS_OUT(10884, 31, 130, 0x02, 5)
#define QOS_48_1_1 QOS_OUT(7500, 15, 75, 0x02, 5)
#define QOS_48_2_1 QOS_OUT(10000, 20, 100, 0x02, 5)
#define QOS_48_3_1 QOS_OUT(7500, 15, 90, 0x02, 5)
#define QOS_48_4_1 QOS_OUT(10000, 20, 120, 0x02, 5)
#define QOS_48_5_1 QOS_OUT(7500, 15, 117, 0x02, 5)
#define QOS_48_6_1 QOS_OUT(10000, 20, 155, 0x02, 5)
/* QoS Configuration settings for high reliability audio data */
#define QOS_8_1_2 QOS(7500, 75, 26, 0x02, 13)
#define QOS_8_2_2 QOS(10000, 95, 30, 0x02, 13)
#define QOS_16_1_2 QOS(7500, 75, 30, 0x02, 13)
#define QOS_16_2_2 QOS(10000, 95, 40, 0x02, 13)
#define QOS_24_1_2 QOS(7500, 75, 45, 0x02, 13)
#define QOS_24_2_2 QOS(10000, 95, 60, 0x02, 13)
#define QOS_32_1_2 QOS(7500, 65, 60, 0x02, 13)
#define QOS_32_2_2 QOS(10000, 95, 80, 0x02, 13)
#define QOS_44_1_2 QOS_OUT(8163, 80, 98, 0x02, 13)
#define QOS_44_2_2 QOS_OUT(10884, 85, 130, 0x02, 13)
#define QOS_48_1_2 QOS_OUT(7500, 75, 75, 0x02, 13)
#define QOS_48_2_2 QOS_OUT(10000, 95, 100, 0x02, 13)
#define QOS_48_3_2 QOS_OUT(7500, 75, 90, 0x02, 13)
#define QOS_48_4_2 QOS_OUT(10000, 100, 120, 0x02, 13)
#define QOS_48_5_2 QOS_OUT(7500, 75, 117, 0x02, 13)
#define QOS_48_6_2 QOS_OUT(10000, 100, 155, 0x02, 13)
/* QoS configuration support setting requirements for the UGG and UGT */
#define QOS_16_1_gs QOS(7500, 15, 30, 0x02, 1)
#define QOS_16_2_gs QOS(10000, 20, 40, 0x02, 1)
#define QOS_32_1_gs QOS(7500, 15, 60, 0x02, 1)
#define QOS_32_2_gs QOS(10000, 20, 80, 0x02, 1)
#define QOS_48_1_gs QOS(7500, 15, 75, 0x02, 1)
#define QOS_48_2_gs QOS(10000, 20, 100, 0x02, 1)
#define QOS_32_1_gr QOS(7500, 15, 60, 0x02, 1)
#define QOS_32_2_gr QOS(10000, 20, 80, 0x02, 1)
#define QOS_48_1_gr QOS(7500, 15, 75, 0x02, 1)
#define QOS_48_2_gr QOS(10000, 20, 100, 0x02, 1)
#define QOS_48_3_gr QOS(7500, 15, 90, 0x02, 1)
#define QOS_48_4_gr QOS(10000, 20, 120, 0x02, 1)

/* One unidirectional CIS. Unicast Server is Audio Sink */
#define AC_1_4 QOS_OUT(10000, 10, 40, 0x02, 2)
/* One unidirectional CIS. Unicast Server is Audio Sink CIG 0x01 */
#define AC_1_4_1 QOS_OUT_1(10000, 10, 40, 0x02, 2)
/* One unidirectional CIS. Unicast Server is Audio Source. */
#define AC_2_10 QOS_IN(10000, 10, 40, 0x02, 2)
/* One unidirectional CIS. Unicast Server is Audio Source CIG 0x02 */
#define AC_2_10_2 QOS_IN_2(10000, 10, 40, 0x02, 2)
/* One bidirectional CIS. Unicast Server is Audio Sink and Audio Source. */
#define AC_3_5 QOS(10000, 10, 40, 0x02, 2)
/* Two unidirectional CISes. Unicast Server is Audio Sink.
 * #1 - CIG 1 CIS 1 (output)
 * #2 - CIG 1 CIS 2 (output)
 */
#define AC_6i_1 QOS_OUT_1_1(10000, 10, 40, 0x02, 2)
#define AC_6i_2 QOS_OUT_1_2(10000, 10, 40, 0x02, 2)
/* Two Unicast Servers. Unicast Server 1 is Audio Sink. Unicast Server 2 is
 * Audio Sink.
 * #1 - CIG 1 CIS auto (output)
 * #2 - CIG 1 CIS auto (output)
 */
#define AC_6ii_1 QOS_OUT_1(10000, 10, 40, 0x02, 2)
#define AC_6ii_2 QOS_OUT_1(10000, 10, 40, 0x02, 2)
#define AC_6ii_1_EF QOS_OUT_1_EF(10000, 10, 40, 0x02, 2)  /* different CIS ID */
/* Two unidirectional CISes. Unicast Server is Audio Sink and Audio Source.
 * #1 - CIG 1 CIS 1 (input)
 * #2 - CIG 1 CIS 2 (output)
 */
#define AC_7i_1 QOS_OUT_1_1(10000, 10, 40, 0x02, 2)
#define AC_7i_2 QOS_IN_1_2(10000, 10, 40, 0x02, 2)
/* Two Unidirectional CISes. Two Unicast Servers. Unicast Server 1 is Audio
 * Sink. Unicast Server 2 is Audio Source.
 * #1 - CIG 1 CIS auto (output)
 * #2 - CIG 1 CIS auto (output)
 */
#define AC_7ii_1 QOS_OUT_1(10000, 10, 40, 0x02, 2)
#define AC_7ii_2 QOS_IN_1(10000, 10, 40, 0x02, 2)
/* One bidirectional CIS and one unidirectional CIS. Unicast Server is Audio
 * Sink and Audio Source.
 * #1 - CIG 1 CIS 1 (output)
 * #2 - CIG 1 CIS 2 (input/output)
 */
#define AC_8i_1 QOS_OUT_1_1(10000, 10, 40, 0x02, 2)
#define AC_8i_2 QOS_1_2(10000, 10, 40, 0x02, 2)
/* One bidirectional CIS and one unidirectional CIS. Two Unicast Servers.
 * Unicast Server 1 is Audio Sink and Audio Source. Unicast Server 2 is
 * Audio Sink.
 * #1 - CIG 1 CIS auto (input/output)
 * #2 - CIG 1 CIS auto (output)
 */
#define AC_8ii_1 QOS_1(10000, 10, 40, 0x02, 2)
#define AC_8ii_2 QOS_OUT_1(10000, 10, 40, 0x02, 2)
/* Two unidirectional CISes. Unicast Server is Audio Source.
 * #1 - CIG 1 CIS 1 (input)
 * #2 - CIG 1 CIS 2 (input)
 */
#define AC_9i_1 QOS_IN_1_1(10000, 10, 40, 0x02, 2)
#define AC_9i_2 QOS_IN_1_2(10000, 10, 40, 0x02, 2)
/* Two unidirectional CISes. Two Unicast Servers. Unicast Server 1 is Audio
 * Source. Unicast Server 2 is Audio Source.
 * #1 - CIG 1 CIS auto (input)
 * #2 - CIG 1 CIS auto (input)
 */
#define AC_9ii_1 QOS_IN_1(10000, 10, 40, 0x02, 2)
#define AC_9ii_2 QOS_IN_1(10000, 10, 40, 0x02, 2)
/* Two bidirectional CISes. Unicast Server is Audio Sink and Audio Source.
 * #1 - CIG 1 CIS 1 (input/output)
 * #2 - CIG 1 CIS 2 (input/output)
 */
#define AC_11i_1 QOS_1_1(10000, 10, 40, 0x02, 2)
#define AC_11i_2 QOS_1_2(10000, 10, 40, 0x02, 2)
/* Two bidirectional CISes. Two Unicast Servers. Unicast Server 1 is Audio Sink
 * and Audio Source. Unicast Server 2 is Audio Sink and Audio Source.
 * #1 - CIG 1 CIS auto (input/output)
 * #2 - CIG 1 CIS auto (input/output)
 */
#define AC_11ii_1 QOS_1(10000, 10, 40, 0x02, 2)
#define AC_11ii_2 QOS_1(10000, 10, 40, 0x02, 2)

#define BCODE {0x01, 0x02, 0x68, 0x05, 0x53, 0xf1, 0x41, 0x5a, \
				0xa2, 0x65, 0xbb, 0xaf, 0xc6, 0xea, 0x03, 0xb8}

#define QOS_BCAST_FULL(_big, _bis, _encryption, _bcode, _in, _out) \
{ \
	.bcast = { \
		.big = _big, \
		.bis = _bis, \
		.sync_factor = 0x07, \
		.packing = 0x00, \
		.framing = 0x00, \
		.in = _in, \
		.out = _out, \
		.encryption = _encryption, \
		.bcode = _bcode, \
		.options = 0x00, \
		.skip = 0x0000, \
		.sync_timeout = BT_ISO_SYNC_TIMEOUT, \
		.sync_cte_type = 0x00, \
		.mse = 0x00, \
		.timeout = BT_ISO_SYNC_TIMEOUT, \
	}, \
}

#define BCAST_QOS_OUT(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, \
		0x00, {0x00}, {}, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define BCAST_QOS_OUT_ENC(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, \
		0x01, BCODE, {}, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define BCAST_QOS_OUT_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(0x01, BT_ISO_QOS_BIS_UNSET, \
		0x00, {0x00}, {}, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define BCAST_QOS_OUT_1_1(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(0x01, 0x01, \
		0x00, {0x00}, {}, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define BCAST_QOS_IN(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, \
		0x00, {0x00}, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})

#define BCAST_QOS_IN_ENC(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_BCAST_FULL(BT_ISO_QOS_BIG_UNSET, BT_ISO_QOS_BIS_UNSET, \
		0x01, BCODE, \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn), {})

#define QOS_OUT_16_2_1 BCAST_QOS_OUT(10000, 10, 40, 0x02, 2)
#define QOS_OUT_ENC_16_2_1 BCAST_QOS_OUT_ENC(10000, 10, 40, 0x02, 2)
#define QOS_OUT_1_16_2_1 BCAST_QOS_OUT_1(10000, 10, 40, 0x02, 2)
#define QOS_OUT_1_1_16_2_1 BCAST_QOS_OUT_1_1(10000, 10, 40, 0x02, 2)
#define QOS_IN_16_2_1 BCAST_QOS_IN(10000, 10, 40, 0x02, 2)
#define QOS_IN_ENC_16_2_1 BCAST_QOS_IN_ENC(10000, 10, 40, 0x02, 2)
#define QOS_OUT_48_1_g BCAST_QOS_OUT(7500, 8, 75, 0x02, 1)
#define QOS_OUT_48_2_g BCAST_QOS_OUT(10000, 10, 100, 0x02, 1)
#define QOS_OUT_48_3_g BCAST_QOS_OUT(7500, 8, 90, 0x02, 1)
#define QOS_OUT_48_4_g BCAST_QOS_OUT(10000, 10, 120, 0x02, 1)

#define BASE(_pd, _sgrp, _nbis, _cfg...) \
{ \
	_pd & 0xff, _pd >> 8, _pd >> 16, \
	_sgrp, \
	_nbis, \
	_cfg \
}

#define LC3_BASE(_pd, _sgrp, _nbis, _cc...) \
	BASE(_pd, _sgrp, _nbis, 0x06, 0x00, 0x00, 0x00, 0x00, _cc)

/* 16 KHZ - 10 ms - Front Left - Frame Length 40 bytes */
#define LC3_CONFIG_16_2_1 \
	0x10, \
	0x02, 0x01, 0x03, \
	0x02, 0x02, 0x01, \
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00, \
	0x03, 0x04, 0x28, 0x00

/* Audio Context: Convertional */
#define CTXT_CONVERSIONAL \
	0x04, \
	0x03, 0x02, 0x02, 0x00

static const uint8_t base_lc3_16_2_1[] =
	LC3_BASE(40000, 1, 1, LC3_CONFIG_16_2_1, CTXT_CONVERSIONAL,
		0x01, /* BIS */
		0x00  /* Codec Specific Configuration */);

#define LC3_CONFIG_G(_freq, _dur, _len) \
	0x0a, \
	0x02, 0x01, _freq, \
	0x02, 0x02, _dur, \
	0x03, 0x04, _len, _len >> 8

#define LC3_CONFIG_FRONT_LEFT \
	0x06, \
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00

/* 48 KHZ - 7.5 ms - Frame Length 75 bytes */
#define LC3_CONFIG_48_1_G \
	LC3_CONFIG_G(0x08, 0x00, 75)

static const uint8_t base_lc3_48_1_g[] =
	LC3_BASE(10000, 1, 1, LC3_CONFIG_48_1_G, CTXT_CONVERSIONAL,
			0x01, LC3_CONFIG_FRONT_LEFT);

/* 48 KHZ - 10 ms Frame Length 100 bytes */
#define LC3_CONFIG_48_2_G \
	LC3_CONFIG_G(0x08, 0x01, 100)

static const uint8_t base_lc3_48_2_g[] =
	LC3_BASE(10000, 1, 1, LC3_CONFIG_48_2_G, CTXT_CONVERSIONAL,
			0x01, LC3_CONFIG_FRONT_LEFT);

/* 48 KHZ - 7.5 ms Frame Length 90 bytes */
#define LC3_CONFIG_48_3_G \
	LC3_CONFIG_G(0x08, 0x00, 90)

static const uint8_t base_lc3_48_3_g[] =
	LC3_BASE(10000, 1, 1, LC3_CONFIG_48_3_G, CTXT_CONVERSIONAL,
			0x01, LC3_CONFIG_FRONT_LEFT);

/* 48 KHZ - 7.5 ms Frame Length 90 bytes */
#define LC3_CONFIG_48_4_G \
	LC3_CONFIG_G(0x08, 0x00, 120)

static const uint8_t base_lc3_48_4_g[] =
	LC3_BASE(10000, 1, 1, LC3_CONFIG_48_3_G, CTXT_CONVERSIONAL,
			0x01, LC3_CONFIG_FRONT_LEFT);

/* Single Audio Channel. One BIS. */
#define BCAST_AC_12 BCAST_QOS_OUT_1_1(10000, 10, 40, 0x02, 2)

static const uint8_t base_lc3_ac_12[] = {
	0x28, 0x00, 0x00, /* Presentation Delay */
	0x01, /* Number of Subgroups */
	0x01, /* Number of BIS */
	0x06, 0x00, 0x00, 0x00, 0x00, /* Code ID = LC3 (0x06) */
	0x10, /* Codec Specific Configuration */
	0x02, 0x01, 0x03, /* 16 KHZ */
	0x02, 0x02, 0x01, /* 10 ms */
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00,  /* Front Left */
	0x03, 0x04, 0x28, 0x00, /* Frame Length 40 bytes */
	0x04, /* Metadata */
	0x03, 0x02, 0x02, 0x00, /* Audio Context: Convertional */
	0x01, /* BIS */
	0x00, /* Codec Specific Configuration */
};

/* Multiple Audio Channels. Two BISes. */
#define BCAST_AC_13_1_1 BCAST_QOS_OUT_1_1(10000, 10, 40, 0x02, 2)
#define BCAST_AC_13_1 BCAST_QOS_OUT_1(10000, 10, 40, 0x02, 2)

static const uint8_t base_lc3_ac_13[] = {
	0x28, 0x00, 0x00, /* Presentation Delay */
	0x01, /* Number of Subgroups */
	0x02, /* Number of BIS */
	0x06, 0x00, 0x00, 0x00, 0x00, /* Code ID = LC3 (0x06) */
	0x10, /* Codec Specific Configuration */
	0x02, 0x01, 0x03, /* 16 KHZ */
	0x02, 0x02, 0x01, /* 10 ms */
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00,  /* Front Left */
	0x03, 0x04, 0x28, 0x00, /* Frame Length 40 bytes */
	0x04, /* Metadata */
	0x03, 0x02, 0x02, 0x00, /* Audio Context: Convertional */
	0x01, /* BIS 1 */
	0x06, /* Codec Specific Configuration */
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00, /* Audio_Channel_Allocation:
					     * Front left
					     */
	0x01, /* BIS 2 */
	0x06, /* Codec Specific Configuration */
	0x05, 0x03, 0x02, 0x00, 0x00, 0x00, /* Audio_Channel_Allocation:
					     * Front right
					     */
};

/* Multiple Audio Channels. One BIS. */
#define BCAST_AC_14 BCAST_QOS_OUT_1_1(10000, 10, 40, 0x02, 2)

static const uint8_t base_lc3_ac_14[] = {
	0x28, 0x00, 0x00, /* Presentation Delay */
	0x01, /* Number of Subgroups */
	0x01, /* Number of BIS */
	0x06, 0x00, 0x00, 0x00, 0x00, /* Code ID = LC3 (0x06) */
	0x10, /* Codec Specific Configuration */
	0x02, 0x01, 0x03, /* 16 KHZ */
	0x02, 0x02, 0x01, /* 10 ms */
	0x05, 0x03, 0x01, 0x00, 0x00, 0x00,  /* Front Left */
	0x03, 0x04, 0x28, 0x00, /* Frame Length 40 bytes */
	0x04, /* Metadata */
	0x03, 0x02, 0x02, 0x00, /* Audio Context: Convertional */
	0x01, /* BIS */
	0x06, /* Codec Specific Configuration */
	0x05, 0x03, 0x03, 0x00, 0x00, 0x00, /* Audio_Channel_Allocation:
					     * Front left, Front right
					     */
};

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	uint8_t accept_reason;
	uint16_t handle;
	uint16_t acl_handle;
	struct queue *io_queue;
	unsigned int io_id[4];
	uint8_t client_num;
	int step;
	uint8_t reconnect;
	bool suspending;
	struct tx_tstamp_data tx_ts;
	int seqnum;
};

struct iso_client_data {
	struct bt_iso_qos qos;
	struct bt_iso_qos qos_2;
	int expect_err;
	const struct iovec *send;
	const struct iovec *recv;
	bool server;
	bool bcast;
	bool defer;
	bool disconnect;
	bool ts;
	bool mconn;
	bool suspend;
	uint8_t pkt_status;
	const uint8_t *base;
	size_t base_len;
	uint8_t sid;
	bool listen_bind;
	bool pa_bind;
	bool big;

	/* Enable BT_PKT_SEQNUM for RX packet sequence numbers */
	bool pkt_seqnum;

	/* Enable SO_TIMESTAMPING with these flags */
	uint32_t so_timestamping;

	/* Enable SO_TIMESTAMPING using CMSG instead of setsockopt() */
	bool cmsg_timestamping;

	/* Number of additional packets to send, before SO_TIMESTAMPING.
	 * Used to test kernel timestamp TX queue logic.
	 */
	unsigned int repeat_send_pre_ts;

	/* Number of additional packets to send, after SO_TIMESTAMPING.
	 * Used for testing TX timestamping OPT_ID.
	 */
	unsigned int repeat_send;
};

typedef bool (*iso_defer_accept_t)(struct test_data *data, GIOChannel *io,
						uint8_t num, GIOFunc func);

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void hciemu_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new_num(HCIEMU_TYPE_BREDRLE52, data->client_num);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		hciemu_set_debug(data->hciemu, hciemu_debug, "hciemu: ", NULL);

	tester_print("New hciemu instance created");
}

static const uint8_t set_iso_socket_param[] = {
	0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6, 0x85, 0x98, /* UUID - ISO Socket */
	0x6a, 0x49, 0xe0, 0x05, 0x88, 0xf1, 0xba, 0x6f,
	0x01,						/* Action - enable */
};

static const uint8_t reset_iso_socket_param[] = {
	0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6, 0x85, 0x98, /* UUID - ISO Socket */
	0x6a, 0x49, 0xe0, 0x05, 0x88, 0xf1, 0xba, 0x6f,
	0x00,						/* Action - disable */
};

static void set_iso_socket_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_print("ISO socket feature could not be enabled");
		return;
	}

	tester_print("ISO socket feature is enabled");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, MGMT_INDEX_NONE,
		  sizeof(set_iso_socket_param), set_iso_socket_param,
		  set_iso_socket_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, MGMT_INDEX_NONE,
		  sizeof(reset_iso_socket_param), reset_iso_socket_param,
		  NULL, NULL, NULL);

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void io_free(void *data)
{
	GIOChannel *io = data;

	g_io_channel_unref(io);
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;
	unsigned int i;

	if (data->io_queue)
		queue_destroy(data->io_queue, io_free);

	for (i = 0; i < ARRAY_SIZE(data->io_id); ++i)
		if (data->io_id[i] > 0)
			g_source_remove(data->io_id[i]);

	free(data);
}

#define test_iso_full(name, data, setup, func, num, reason) \
	do { \
		struct test_data *user; \
		user = new0(struct test_data, 1); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		user->client_num = num; \
		user->accept_reason = reason; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

#define test_iso(name, data, setup, func) \
	test_iso_full(name, data, setup, func, 1, 0x00)

#define test_iso2(name, data, setup, func) \
	test_iso_full(name, data, setup, func, 2, 0x00)

#define test_iso_rej(name, data, setup, func, reason) \
	test_iso_full(name, data, setup, func, 1, reason)

static const struct iso_client_data connect_8_1_1 = {
	.qos = QOS_8_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_8_2_1 = {
	.qos = QOS_8_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_16_1_1 = {
	.qos = QOS_16_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_16_2_1 = {
	.qos = QOS_16_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_1_16_2_1 = {
	.qos = QOS_1_16_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_1_1_16_2_1 = {
	.qos = QOS_1_1_16_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_24_1_1 = {
	.qos = QOS_24_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_24_2_1 = {
	.qos = QOS_24_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_1 = {
	.qos = QOS_32_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_1 = {
	.qos = QOS_32_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_44_1_1 = {
	.qos = QOS_44_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_44_2_1 = {
	.qos = QOS_44_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_1 = {
	.qos = QOS_48_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_1 = {
	.qos = QOS_48_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_3_1 = {
	.qos = QOS_48_3_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_4_1 = {
	.qos = QOS_48_4_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_5_1 = {
	.qos = QOS_48_5_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_6_1 = {
	.qos = QOS_48_6_1,
	.expect_err = 0
};

static const struct iso_client_data connect_8_1_2 = {
	.qos = QOS_8_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_8_2_2 = {
	.qos = QOS_8_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_16_1_2 = {
	.qos = QOS_16_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_16_2_2 = {
	.qos = QOS_16_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_24_1_2 = {
	.qos = QOS_24_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_24_2_2 = {
	.qos = QOS_24_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_2 = {
	.qos = QOS_32_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_2 = {
	.qos = QOS_32_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_44_1_2 = {
	.qos = QOS_44_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_44_2_2 = {
	.qos = QOS_44_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_2 = {
	.qos = QOS_48_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_2 = {
	.qos = QOS_48_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_3_2 = {
	.qos = QOS_48_3_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_4_2 = {
	.qos = QOS_48_4_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_5_2 = {
	.qos = QOS_48_5_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_6_2 = {
	.qos = QOS_48_6_2,
	.expect_err = 0
};

static const struct iso_client_data connect_16_1_gs = {
	.qos = QOS_16_1_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_16_2_gs = {
	.qos = QOS_16_2_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_gs = {
	.qos = QOS_32_1_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_gs = {
	.qos = QOS_32_2_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_gs = {
	.qos = QOS_48_1_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_gs = {
	.qos = QOS_48_2_gs,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_gr = {
	.qos = QOS_32_1_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_gr = {
	.qos = QOS_32_2_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_gr = {
	.qos = QOS_48_1_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_gr = {
	.qos = QOS_48_2_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_48_3_gr = {
	.qos = QOS_48_3_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_48_4_gr = {
	.qos = QOS_48_4_gr,
	.expect_err = 0
};

static const struct iso_client_data connect_invalid = {
	.qos = QOS(0, 0, 0, 0, 0),
	.expect_err = -EINVAL
};

static const struct iso_client_data connect_reject = {
	.qos = QOS_16_1_2,
	.expect_err = -ENOSYS
};

static const struct iso_client_data connect_suspend = {
	.qos = QOS_16_2_1,
	.expect_err = -ECONNRESET
};

static const struct iso_client_data connect_cig_f0_invalid = {
	.qos = QOS_FULL(0xF0, 0x00, {}, QOS_IO(10000, 10, 40, 0x02, 2)),
	.expect_err = -EINVAL
};

static const struct iso_client_data connect_cis_f0_invalid = {
	.qos = QOS_FULL(0x00, 0xF0, {}, QOS_IO(10000, 10, 40, 0x02, 2)),
	.expect_err = -EINVAL
};

static const uint8_t data_16_2_1[40] = { [0 ... 39] = 0xff };
static const struct iovec send_16_2_1 = {
	.iov_base = (void *)data_16_2_1,
	.iov_len = sizeof(data_16_2_1),
};

static const uint8_t data_48_2_1[100] = { [0 ... 99] = 0xff };
static const struct iovec send_48_2_1 = {
	.iov_base = (void *)data_48_2_1,
	.iov_len = sizeof(data_48_2_1),
};

static const uint8_t data_large[512] = { [0 ... 511] = 0xff };
static const struct iovec send_large = {
	.iov_base = (void *)data_large,
	.iov_len = sizeof(data_large),
};

static const struct iso_client_data connect_16_2_1_send = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
};

static const struct iso_client_data connect_send_tx_timestamping = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_OPT_ID |
					SOF_TIMESTAMPING_TX_SOFTWARE |
					SOF_TIMESTAMPING_TX_COMPLETION),
	.repeat_send = 1,
	.repeat_send_pre_ts = 2,
};

static const struct iso_client_data connect_send_tx_cmsg_timestamping = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_OPT_TSONLY |
					SOF_TIMESTAMPING_TX_COMPLETION),
	.repeat_send = 1,
	.cmsg_timestamping = true,
};

static const struct iso_client_data listen_16_2_1_recv = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
};

static const struct iso_client_data listen_16_2_1_recv_frag = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_large,
	.server = true,
};

static const struct iso_client_data listen_16_2_1_recv_ts = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.ts = true,
};

static const struct iso_client_data listen_16_2_1_recv_pkt_status = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.pkt_status = 0x02,
};

static const struct iso_client_data listen_16_2_1_recv_pkt_seqnum = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.pkt_seqnum = true,
};

static const struct iso_client_data listen_16_2_1_recv_rx_timestamping = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_RX_SOFTWARE),
};

static const struct iso_client_data listen_16_2_1_recv_hw_timestamping = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.ts = true,
	.so_timestamping = (SOF_TIMESTAMPING_RAW_HARDWARE |
					SOF_TIMESTAMPING_RX_HARDWARE),
};

static const struct iso_client_data listen_16_2_1_recv_frag_hw_timestamping = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_large,
	.server = true,
	.ts = true,
	.so_timestamping = (SOF_TIMESTAMPING_RAW_HARDWARE |
					SOF_TIMESTAMPING_RX_HARDWARE),
};

static const struct iso_client_data defer_16_2_1 = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.defer = true,
};

static const struct iso_client_data defer_1_16_2_1 = {
	.qos = QOS_1_16_2_1,
	.expect_err = 0,
	.defer = true,
};

static const struct iso_client_data connect_16_2_1_defer_send = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.defer = true,
};

static const struct iso_client_data connect_48_2_1_defer_send = {
	.qos = QOS_48_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.defer = true,
};

static const struct iso_client_data listen_16_2_1_defer_recv = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.server = true,
	.defer = true,
};

static const struct iso_client_data listen_48_2_1_defer_recv = {
	.qos = QOS_48_2_1,
	.expect_err = 0,
	.recv = &send_48_2_1,
	.server = true,
	.defer = true,
};

static const struct iso_client_data listen_16_2_1_defer_reject = {
	.qos = QOS_16_2_1,
	.expect_err = -1,
	.recv = &send_16_2_1,
	.server = true,
	.defer = true,
};

static const struct iso_client_data connect_16_2_1_send_recv = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.recv = &send_16_2_1,
};

static const struct iso_client_data disconnect_16_2_1 = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.disconnect = true,
};

static const struct iso_client_data suspend_16_2_1 = {
	.qos = QOS_16_2_1,
	.suspend = true,
};

static const struct iso_client_data reconnect_16_2_1 = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.disconnect = true,
};

static const struct iso_client_data reconnect_16_2_1_send_recv = {
	.qos = QOS_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.recv = &send_16_2_1,
	.disconnect = true,
};

static const struct iso_client_data connect_ac_1_4 = {
	.qos = AC_1_4,
	.expect_err = 0
};

static const struct iso_client_data connect_ac_2_10 = {
	.qos = AC_2_10,
	.expect_err = 0
};

static const struct iso_client_data connect_ac_3_5 = {
	.qos = AC_3_5,
	.expect_err = 0
};

static const struct iso_client_data connect_ac_6i = {
	.qos = AC_6i_1,
	.qos_2 = AC_6i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data reconnect_ac_6i = {
	.qos = AC_6i_1,
	.qos_2 = AC_6i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
	.disconnect = true,
};

static const struct iso_client_data connect_ac_6ii = {
	.qos = AC_6ii_1,
	.qos_2 = AC_6ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data reconnect_ac_6ii = {
	.qos = AC_6ii_1,
	.qos_2 = AC_6ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
	.disconnect = true,
};

static const struct iso_client_data connect_ac_6ii_cis_ef_auto = {
	.qos = AC_6ii_1_EF,
	.qos_2 = AC_6ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_6ii_cis_ef_ef = {
	.qos = AC_6ii_1_EF,
	.qos_2 = AC_6ii_1_EF,
	.expect_err = -EINVAL,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_7i = {
	.qos = AC_7i_1,
	.qos_2 = AC_7i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_7ii = {
	.qos = AC_7ii_1,
	.qos_2 = AC_7ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_8i = {
	.qos = AC_8i_1,
	.qos_2 = AC_8i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_8ii = {
	.qos = AC_8ii_1,
	.qos_2 = AC_8ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_9i = {
	.qos = AC_9i_1,
	.qos_2 = AC_9i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_9ii = {
	.qos = AC_9ii_1,
	.qos_2 = AC_9ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_11i = {
	.qos = AC_11i_1,
	.qos_2 = AC_11i_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_11ii = {
	.qos = AC_11ii_1,
	.qos_2 = AC_11ii_2,
	.expect_err = 0,
	.mconn = true,
	.defer = true,
};

static const struct iso_client_data connect_ac_1_2 = {
	.qos = AC_1_4,
	.qos_2 = AC_2_10,
	.expect_err = 0,
	.mconn = true,
};

static const struct iso_client_data connect_ac_1_2_cig_1_2 = {
	.qos = AC_1_4_1,
	.qos_2 = AC_2_10_2,
	.expect_err = 0,
	.mconn = true,
};

static const struct iso_client_data bcast_48_1_g = {
	.qos = QOS_OUT_48_1_g,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_48_1_g,
	.base_len = sizeof(base_lc3_48_1_g),
};

static const struct iso_client_data bcast_48_2_g = {
	.qos = QOS_OUT_48_2_g,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_48_2_g,
	.base_len = sizeof(base_lc3_48_2_g),
};

static const struct iso_client_data bcast_48_3_g = {
	.qos = QOS_OUT_48_3_g,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_48_3_g,
	.base_len = sizeof(base_lc3_48_3_g),
};

static const struct iso_client_data bcast_48_4_g = {
	.qos = QOS_OUT_48_4_g,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_48_4_g,
	.base_len = sizeof(base_lc3_48_4_g),
};

static const struct iso_client_data bcast_16_2_1_send = {
	.qos = QOS_OUT_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
};

static const struct iso_client_data bcast_enc_16_2_1_send = {
	.qos = QOS_OUT_ENC_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
};

static const struct iso_client_data bcast_1_16_2_1_send = {
	.qos = QOS_OUT_1_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
};

static const struct iso_client_data bcast_1_1_16_2_1_send = {
	.qos = QOS_OUT_1_1_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
};

static const struct iso_client_data bcast_16_2_1_send_sid = {
	.qos = QOS_OUT_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
	.sid = 0xff,
};

static const struct iso_client_data bcast_16_2_1_send_sid1 = {
	.qos = QOS_OUT_16_2_1,
	.expect_err = 0,
	.send = &send_16_2_1,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
	.sid = 0x01,
};

static const struct iso_client_data bcast_16_2_1_reconnect = {
	.qos = QOS_OUT_16_2_1,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_16_2_1,
	.base_len = sizeof(base_lc3_16_2_1),
	.disconnect = true,
};

static const struct iso_client_data bcast_16_2_1_recv = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.bcast = true,
	.server = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv2 = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.bcast = true,
	.server = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_sid = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.bcast = true,
	.server = true,
	.big = true,
	.sid = 0xff,
};

static const struct iso_client_data bcast_16_2_1_recv_sid1 = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.bcast = true,
	.server = true,
	.big = true,
	.sid = 0x01,
};

static const struct iso_client_data bcast_enc_16_2_1_recv = {
	.qos = QOS_IN_ENC_16_2_1,
	.expect_err = 0,
	.recv = &send_16_2_1,
	.bcast = true,
	.server = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_defer = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.recv = &send_16_2_1,
	.bcast = true,
	.server = true,
	.listen_bind = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_defer_reconnect = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.bcast = true,
	.server = true,
	.pa_bind = true,
	.big = true,
	.disconnect = true,
};

static const struct iso_client_data bcast_16_2_1_recv2_defer = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.bcast = true,
	.server = true,
	.listen_bind = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_defer_no_bis = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.bcast = true,
	.server = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_defer_pa_bind = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.bcast = true,
	.server = true,
	.pa_bind = true,
	.big = true,
};

static const struct iso_client_data bcast_16_2_1_recv_defer_get_base = {
	.qos = QOS_IN_16_2_1,
	.expect_err = 0,
	.defer = true,
	.bcast = true,
	.server = true,
	.base = base_lc3_ac_12,
	.base_len = sizeof(base_lc3_ac_12),
};

static const struct iso_client_data bcast_ac_12 = {
	.qos = BCAST_AC_12,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_ac_12,
	.base_len = sizeof(base_lc3_ac_12),
};

static const struct iso_client_data bcast_ac_13_1_1 = {
	.qos = BCAST_AC_13_1_1,
	.expect_err = 0,
	.bcast = true,
	.mconn = true,
	.base = base_lc3_ac_13,
	.base_len = sizeof(base_lc3_ac_13),
};

static const struct iso_client_data bcast_ac_13_1_1_reconn = {
	.qos = BCAST_AC_13_1_1,
	.expect_err = 0,
	.bcast = true,
	.mconn = true,
	.base = base_lc3_ac_13,
	.base_len = sizeof(base_lc3_ac_13),
	.disconnect = true,
};

static const struct iso_client_data bcast_ac_13_1 = {
	.qos = BCAST_AC_13_1,
	.expect_err = 0,
	.bcast = true,
	.mconn = true,
	.base = base_lc3_ac_13,
	.base_len = sizeof(base_lc3_ac_13),
};

static const struct iso_client_data bcast_ac_14 = {
	.qos = BCAST_AC_14,
	.expect_err = 0,
	.bcast = true,
	.base = base_lc3_ac_14,
	.base_len = sizeof(base_lc3_ac_14),
};

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = user_data;
	static uint8_t client_num;

	if (opcode != BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE)
		return;

	tester_print("Client %u set connectable status 0x%02x", client_num,
								status);

	client_num++;

	if (status)
		tester_setup_failed();
	else if (data->client_num == client_num) {
		tester_setup_complete();
		client_num = 0;
	}
}

static void bthost_recv_data(const void *buf, uint16_t len, void *user_data)
{
	struct test_data *data = user_data;
	const struct iso_client_data *isodata = data->test_data;

	--data->step;

	tester_print("Client received %u bytes of data", len);

	if (isodata->send && (isodata->send->iov_len != len ||
			memcmp(isodata->send->iov_base, buf, len))) {
		if (!isodata->recv->iov_base)
			tester_test_failed();
	} else if (!data->step)
		tester_test_passed();
}

static void bthost_iso_disconnected(void *user_data)
{
	struct test_data *data = user_data;

	tester_print("ISO handle 0x%04x disconnected", data->handle);

	data->handle = 0x0000;
}

static void iso_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	struct bthost *host;

	tester_print("New client connection with handle 0x%04x", handle);

	data->handle = handle;

	host = hciemu_client_get_host(data->hciemu);
	bthost_add_iso_hook(host, data->handle, bthost_recv_data, data,
				bthost_iso_disconnected);
}

static uint8_t iso_accept_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;

	tester_print("Accept client connection with handle 0x%04x: 0x%02x",
		     handle, data->accept_reason);

	return data->accept_reason;
}

static void acl_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;

	tester_print("New ACL connection with handle 0x%04x", handle);

	data->acl_handle = handle;
}

static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	uint8_t i;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	for (i = 0; i < data->client_num; i++) {
		struct hciemu_client *client;
		struct bthost *host;
		uint8_t sid = 0;

		client = hciemu_get_client(data->hciemu, i);
		host = hciemu_client_host(client);
		bthost_set_cmd_complete_cb(host, client_connectable_complete,
									data);

		if (isodata)
			sid = isodata->sid;

		bthost_set_ext_adv_params(host, sid != 0xff ? sid : 0x00);
		bthost_set_ext_adv_enable(host, 0x01);

		if (!isodata)
			continue;

		if (isodata->send || isodata->recv || isodata->disconnect ||
				isodata->suspend || data->accept_reason)
			bthost_set_iso_cb(host, iso_accept_conn, iso_new_conn,
									data);

		if (isodata->bcast) {
			bthost_set_pa_params(host);
			bthost_set_pa_enable(host, 0x01);

			if (isodata->base)
				bthost_set_base(host, isodata->base,
							isodata->base_len);

			if (isodata->big)
				bthost_create_big(host, 1,
						isodata->qos.bcast.encryption,
						isodata->qos.bcast.bcode);

		} else if (!isodata->send && isodata->recv) {
			const uint8_t *bdaddr;

			bdaddr = hciemu_get_central_bdaddr(data->hciemu);
			bthost_set_connect_cb(host, acl_new_conn, data);
			bthost_hci_connect(host, bdaddr, BDADDR_LE_PUBLIC);
		}
	}
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	if (!isodata || !isodata->bcast)
		mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	if (isodata && isodata->server && !isodata->bcast)
		mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING,
				data->mgmt_index, sizeof(param), param, NULL,
				NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void test_framework(const void *test_data)
{
	tester_test_passed();
}

static void test_socket(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		return;
	}

	close(sk);

	tester_test_passed();
}

static void test_getsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_iso_qos qos;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		return;
	}

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static void test_setsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_iso_qos qos = QOS_16_1_2;
	int pkt_status = 1;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		goto end;
	}

	err = setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, sizeof(qos));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	err = setsockopt(sk, SOL_BLUETOOTH, BT_PKT_STATUS, &pkt_status,
			 sizeof(pkt_status));
	if (err < 0) {
		tester_warn("Can't set socket BT_PKT_STATUS option: "
				"%s (%d)", strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	len = sizeof(pkt_status);
	memset(&pkt_status, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_PKT_STATUS, &pkt_status, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static int create_iso_sock(struct test_data *data)
{
	const struct iso_client_data *isodata = data->test_data;
	const uint8_t *master_bdaddr;
	struct sockaddr_iso *addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_ISO);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	master_bdaddr = hciemu_get_central_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		tester_warn("No master bdaddr");
		close(sk);
		return -ENODEV;
	}

	if (isodata->bcast && isodata->sid) {
		addr = malloc(sizeof(*addr) + sizeof(*addr->iso_bc));
		memset(addr, 0, sizeof(*addr) + sizeof(*addr->iso_bc));
		addr->iso_family = AF_BLUETOOTH;
		bacpy(&addr->iso_bdaddr, (void *) master_bdaddr);
		addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;
		addr->iso_bc->bc_bdaddr_type = BDADDR_LE_PUBLIC;
		addr->iso_bc->bc_sid = isodata->sid;
		err = bind(sk, (struct sockaddr *) addr, sizeof(*addr) +
						sizeof(*addr->iso_bc));
	} else {
		addr = malloc(sizeof(*addr));
		memset(addr, 0, sizeof(*addr));
		addr->iso_family = AF_BLUETOOTH;
		bacpy(&addr->iso_bdaddr, (void *) master_bdaddr);
		addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;
		err = bind(sk, (struct sockaddr *) addr, sizeof(*addr));
	}

	if (err < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	return sk;
}

static int connect_iso_sock(struct test_data *data, uint8_t num, int sk)
{
	const struct iso_client_data *isodata = data->test_data;
	struct hciemu_client *client;
	const uint8_t *client_bdaddr = NULL;
	const struct bt_iso_qos *qos = &isodata->qos;
	struct sockaddr_iso addr;
	char str[18];
	int err;

	client = hciemu_get_client(data->hciemu, num);
	if (!client) {
		if (!isodata->mconn) {
			tester_warn("No client");
			return -ENODEV;
		}

		client = hciemu_get_client(data->hciemu, 0);
		if (!client) {
			tester_warn("No client");
			return -ENODEV;
		}
	}

	if (!isodata->bcast && num && isodata->mconn)
		qos = &isodata->qos_2;

	if (!isodata->bcast) {
		client_bdaddr = hciemu_client_bdaddr(client);
		if (!client_bdaddr) {
			tester_warn("No client bdaddr");
			return -ENODEV;
		}
	} else if (!isodata->server) {
		err = setsockopt(sk, SOL_BLUETOOTH, BT_ISO_BASE,
				isodata->base, isodata->base_len);
		if (err < 0) {
			tester_warn("Can't set socket BT_ISO_BASE option: "
					"%s (%d)", strerror(errno), errno);
			tester_test_failed();
			return -EINVAL;
		}
	}

	err = setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, qos, sizeof(*qos));
	if (err < 0) {
		tester_warn("Can't set socket BT_ISO_QOS option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		return -EINVAL;
	}

	if (isodata->defer || (isodata->bcast && isodata->mconn && !num)) {
		int opt = 1;

		if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &opt,
							sizeof(opt)) < 0) {
			tester_print("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);
			tester_test_failed();
			return -EINVAL;
		}
	}

	memset(&addr, 0, sizeof(addr));
	addr.iso_family = AF_BLUETOOTH;
	bacpy(&addr.iso_bdaddr, client_bdaddr ? (void *) client_bdaddr :
							BDADDR_ANY);
	addr.iso_bdaddr_type = BDADDR_LE_PUBLIC;

	ba2str(&addr.iso_bdaddr, str);

	tester_print("Connecting to %s...", str);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = -errno;
		tester_warn("Can't connect socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	return 0;
}

static bool check_io_qos(const struct bt_iso_io_qos *io1,
				const struct bt_iso_io_qos *io2)
{
	if (io1->interval && io2->interval && io1->interval > io2->interval) {
		tester_warn("Unexpected IO interval: %u > %u",
				io1->interval, io2->interval);
		return false;
	}

	if (io1->latency && io2->latency && io1->latency > io2->latency) {
		tester_warn("Unexpected IO latency: %u > %u",
				io1->latency, io2->latency);
		return false;
	}

	if (io1->sdu && io2->sdu && io1->sdu != io2->sdu) {
		tester_warn("Unexpected IO SDU: %u != %u", io1->sdu, io2->sdu);
		return false;
	}

	if (io1->phy && io2->phy && io1->phy != io2->phy) {
		tester_warn("Unexpected IO PHY: 0x%02x != 0x%02x",
				io1->phy, io2->phy);
		return false;
	}

	if (io1->rtn && io2->rtn && io1->rtn != io2->rtn) {
		tester_warn("Unexpected IO RTN: %u != %u", io1->rtn, io2->rtn);
		return false;
	}

	return true;
}

static bool check_ucast_qos(const struct bt_iso_qos *qos1,
				const struct bt_iso_qos *qos2,
				const struct bt_iso_qos *qos2_2)
{
	if (qos1->ucast.cig != BT_ISO_QOS_CIG_UNSET &&
			qos2->ucast.cig != BT_ISO_QOS_CIG_UNSET &&
			qos1->ucast.cig != qos2->ucast.cig) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected CIG ID: 0x%02x != 0x%02x",
				qos1->ucast.cig, qos2->ucast.cig);
		return false;
	}

	if (qos1->ucast.cis != BT_ISO_QOS_CIS_UNSET &&
			qos2->ucast.cis != BT_ISO_QOS_CIS_UNSET &&
			qos1->ucast.cis != qos2->ucast.cis) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected CIS ID: 0x%02x != 0x%02x",
				qos1->ucast.cis, qos2->ucast.cis);
		return false;
	}

	if (qos1->ucast.packing != qos2->ucast.packing) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected QoS packing: 0x%02x != 0x%02x",
				qos1->ucast.packing, qos2->ucast.packing);
		return false;
	}

	if (qos1->ucast.framing != qos2->ucast.framing) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected QoS framing: 0x%02x != 0x%02x",
				qos1->ucast.framing, qos2->ucast.framing);
		return false;
	}

	if (!check_io_qos(&qos1->ucast.in, &qos2->ucast.in)) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected Input QoS");
		return false;
	}

	if (!check_io_qos(&qos1->ucast.out, &qos2->ucast.out)) {
		if (qos2_2)
			return check_ucast_qos(qos1, qos2_2, NULL);

		tester_warn("Unexpected Output QoS");
		return false;
	}

	return true;
}

static bool check_bcast_qos(const struct bt_iso_qos *qos1,
				const struct bt_iso_qos *qos2)
{
	if (qos1->bcast.big != BT_ISO_QOS_BIG_UNSET &&
			qos2->bcast.big != BT_ISO_QOS_BIG_UNSET &&
			qos1->bcast.big != qos2->bcast.big) {
		tester_warn("Unexpected BIG ID: 0x%02x != 0x%02x",
				qos1->bcast.big, qos2->bcast.big);
		return false;
	}

	if (qos1->bcast.bis != BT_ISO_QOS_BIS_UNSET &&
			qos2->bcast.bis != BT_ISO_QOS_BIS_UNSET &&
			qos1->bcast.bis != qos2->bcast.bis) {
		tester_warn("Unexpected BIS ID: 0x%02x != 0x%02x",
				qos1->bcast.bis, qos2->bcast.bis);
		return false;
	}

	if (qos1->bcast.sync_factor != qos2->bcast.sync_factor) {
		tester_warn("Unexpected QoS sync interval: 0x%02x != 0x%02x",
			qos1->bcast.sync_factor, qos2->bcast.sync_factor);
		return false;
	}

	if (qos1->bcast.packing != qos2->bcast.packing) {
		tester_warn("Unexpected QoS packing: 0x%02x != 0x%02x",
				qos1->bcast.packing, qos2->bcast.packing);
		return false;
	}

	if (qos1->bcast.framing != qos2->bcast.framing) {
		tester_warn("Unexpected QoS framing: 0x%02x != 0x%02x",
				qos1->bcast.framing, qos2->bcast.framing);
		return false;
	}

	if (!check_io_qos(&qos1->ucast.in, &qos2->ucast.in)) {
		tester_warn("Unexpected Input QoS");
		return false;
	}

	if (!check_io_qos(&qos1->ucast.out, &qos2->ucast.out)) {
		tester_warn("Unexpected Output QoS");
		return false;
	}

	if (qos1->bcast.encryption != qos2->bcast.encryption) {
		tester_warn("Unexpected QoS encryption: 0x%02x != 0x%02x",
				qos1->bcast.encryption, qos2->bcast.encryption);
		return false;
	}

	if (memcmp(qos1->bcast.bcode, qos2->bcast.bcode,
				sizeof(qos1->bcast.bcode))) {
		tester_warn("Unexpected QoS Broadcast Code");
		return false;
	}

	if (qos1->bcast.options != qos2->bcast.options) {
		tester_warn("Unexpected QoS options: 0x%02x != 0x%02x",
				qos1->bcast.options, qos2->bcast.options);
		return false;
	}

	if (qos1->bcast.skip != qos2->bcast.skip) {
		tester_warn("Unexpected QoS skip: 0x%04x != 0x%04x",
				qos1->bcast.skip, qos2->bcast.skip);
		return false;
	}

	if (qos1->bcast.sync_timeout != qos2->bcast.sync_timeout) {
		tester_warn("Unexpected QoS sync timeout: 0x%04x != 0x%04x",
			qos1->bcast.sync_timeout, qos2->bcast.sync_timeout);
		return false;
	}

	if (qos1->bcast.sync_cte_type != qos2->bcast.sync_cte_type) {
		tester_warn("Unexpected QoS sync cte type: 0x%02x != 0x%02x",
			qos1->bcast.sync_cte_type, qos2->bcast.sync_cte_type);
		return false;
	}

	if (qos1->bcast.mse != qos2->bcast.mse) {
		tester_warn("Unexpected QoS MSE: 0x%02x != 0x%02x",
				qos1->bcast.mse, qos2->bcast.mse);
		return false;
	}

	if (qos1->bcast.timeout != qos2->bcast.timeout) {
		tester_warn("Unexpected QoS MSE: 0x%04x != 0x%04x",
				qos1->bcast.timeout, qos2->bcast.timeout);
		return false;
	}

	return true;
}

static void test_connect(const void *test_data);
static gboolean iso_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data);
static gboolean iso_accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data);
static bool iso_defer_accept_bcast(struct test_data *data, GIOChannel *io,
						uint8_t num, GIOFunc func);

static gboolean iso_disconnected(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;
	const struct iso_client_data *isodata = data->test_data;

	data->io_id[0] = 0;

	if (cond & G_IO_HUP) {
		if (!isodata->bcast && data->handle)
			tester_test_failed();

		tester_print("Successfully disconnected");

		if (data->reconnect) {
			tester_print("Reconnecting #%u...", data->reconnect);

			data->reconnect--;

			if (!isodata->server)
				test_connect(data->test_data);
			else {
				GIOChannel *parent =
					queue_peek_head(data->io_queue);

				data->step++;

				iso_defer_accept_bcast(data,
					parent, 0, iso_accept_cb);
			}

			return FALSE;
		}

		tester_test_passed();
	} else
		tester_test_failed();

	return FALSE;
}

static void iso_shutdown(struct test_data *data, GIOChannel *io)
{
	int sk;

	sk = g_io_channel_unix_get_fd(io);

	data->io_id[0] = g_io_add_watch(io, G_IO_HUP, iso_disconnected, data);

	/* Shutdown using SHUT_WR as SHUT_RDWR cause the socket to HUP
	 * immediately instead of waiting for Disconnect Complete event.
	 */
	shutdown(sk, SHUT_WR);

	tester_print("Disconnecting...");
}

static gboolean iso_recv_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;
	const struct iso_client_data *isodata = data->test_data;
	int sk = g_io_channel_unix_get_fd(io);
	unsigned char control[256];
	ssize_t ret;
	char buf[1024];
	struct msghdr msg;
	struct iovec iov;

	data->io_id[0] = 0;

	iov.iov_base = buf;
	iov.iov_len = isodata->recv->iov_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(sk, &msg, MSG_DONTWAIT);
	if (ret < 0 || isodata->recv->iov_len != (size_t) ret) {
		tester_warn("Failed to read %zu bytes: %s (%d)",
				isodata->recv->iov_len, strerror(errno), errno);
		tester_test_failed();
		return FALSE;
	}

	if (isodata->pkt_status) {
		struct cmsghdr *cmsg;
		uint8_t pkt_status = 0;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_BLUETOOTH)
				continue;

			if (cmsg->cmsg_type == BT_SCM_PKT_STATUS) {
				memcpy(&pkt_status, CMSG_DATA(cmsg),
						sizeof(pkt_status));
				tester_debug("BT_SCM_PKT_STATUS = 0x%2.2x",
							pkt_status);
				break;
			}
		}

		if (isodata->pkt_status != pkt_status) {
			tester_warn("isodata->pkt_status 0x%2.2x != 0x%2.2x "
					"pkt_status", isodata->pkt_status,
					pkt_status);
			tester_test_failed();
		} else
			tester_test_passed();

		return FALSE;
	}

	if (isodata->pkt_seqnum) {
		struct cmsghdr *cmsg;
		uint16_t pkt_seqnum = 0;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_BLUETOOTH)
				continue;

			if (cmsg->cmsg_type == BT_SCM_PKT_SEQNUM) {
				memcpy(&pkt_seqnum, CMSG_DATA(cmsg),
						sizeof(pkt_seqnum));
				tester_debug("BT_SCM_PKT_SEQNUM = 0x%2.2x",
							pkt_seqnum);
				break;
			}
		}

		if (data->seqnum < 0)
			data->seqnum = pkt_seqnum;
		else
			data->seqnum++;

		if (pkt_seqnum != data->seqnum) {
			tester_warn("isodata->pkt_seqnum 0x%2.2x != 0x%2.2x "
					"pkt_seqnum", pkt_seqnum, data->seqnum);
			tester_test_failed();
			return FALSE;
		}
	}

	if (rx_timestamp_check(&msg, isodata->so_timestamping, 1000) < 0) {
		tester_test_failed();
		return FALSE;
	}

	if (data->step) {
		data->step--;
	} else {
		tester_test_failed();
		return FALSE;
	}

	if (memcmp(buf, isodata->recv->iov_base, ret))
		tester_test_failed();
	else if (data->step)
		return TRUE;
	else if (isodata->disconnect)
		iso_shutdown(data, io);
	else
		tester_test_passed();

	return FALSE;
}

static void iso_recv(struct test_data *data, GIOChannel *io)
{
	const struct iso_client_data *isodata = data->test_data;
	struct bthost *host;
	static uint16_t sn;
	int j, count;

	tester_print("Receive %zu bytes of data", isodata->recv->iov_len);

	if (!data->handle) {
		tester_warn("ISO handle not set");
		tester_test_failed();
		return;
	}

	if (rx_timestamping_init(g_io_channel_unix_get_fd(io),
						isodata->so_timestamping))
		return;

	host = hciemu_client_get_host(data->hciemu);

	count = isodata->pkt_seqnum ? 2 : 1;
	for (j = 0; j < count; ++j) {
		bthost_send_iso(host, data->handle, isodata->ts, sn++, j + 1,
					isodata->pkt_status, isodata->recv, 1);
		data->step++;
	}

	data->io_id[0] = g_io_add_watch(io, G_IO_IN, iso_recv_data, data);
}

static gboolean iso_recv_errqueue(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;
	const struct iso_client_data *isodata = data->test_data;
	int sk = g_io_channel_unix_get_fd(io);
	int err;

	data->step--;

	err = tx_tstamp_recv(&data->tx_ts, sk, isodata->send->iov_len);
	if (err > 0)
		return TRUE;
	else if (err)
		tester_test_failed();
	else if (!data->step)
		tester_test_passed();

	data->io_id[2] = 0;
	return FALSE;
}

static void iso_tx_timestamping(struct test_data *data, GIOChannel *io)
{
	const struct iso_client_data *isodata = data->test_data;
	int so = isodata->so_timestamping;
	int sk;
	int err;
	unsigned int count;

	if (!(isodata->so_timestamping & TS_TX_RECORD_MASK))
		return;

	tester_print("Enabling TX timestamping");

	tx_tstamp_init(&data->tx_ts, isodata->so_timestamping, false);

	for (count = 0; count < isodata->repeat_send + 1; ++count)
		data->step += tx_tstamp_expect(&data->tx_ts, 0);

	sk = g_io_channel_unix_get_fd(io);

	data->io_id[2] = g_io_add_watch(io, G_IO_ERR, iso_recv_errqueue, data);

	if (isodata->cmsg_timestamping)
		so &= ~TS_TX_RECORD_MASK;

	err = setsockopt(sk, SOL_SOCKET, SO_TIMESTAMPING, &so, sizeof(so));
	if (err < 0) {
		tester_warn("setsockopt SO_TIMESTAMPING: %s (%d)",
						strerror(errno), errno);
		tester_test_failed();
		return;
	}
}

static void iso_send_data(struct test_data *data, GIOChannel *io)
{
	const struct iso_client_data *isodata = data->test_data;
	char control[CMSG_SPACE(sizeof(uint32_t))];
	struct msghdr msg = {
		.msg_iov = (struct iovec *)isodata->send,
		.msg_iovlen = 1,
	};
	struct cmsghdr *cmsg;
	ssize_t ret;
	int sk;

	tester_print("Writing %zu bytes of data", isodata->send->iov_len);

	sk = g_io_channel_unix_get_fd(io);

	if (isodata->cmsg_timestamping) {
		memset(control, 0, sizeof(control));
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SO_TIMESTAMPING;
		cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));

		*((uint32_t *)CMSG_DATA(cmsg)) = (isodata->so_timestamping &
					TS_TX_RECORD_MASK);
	}

	ret = sendmsg(sk, &msg, 0);
	if (ret < 0 || isodata->send->iov_len != (size_t) ret) {
		tester_warn("Failed to write %zu bytes: %s (%d)",
				isodata->send->iov_len, strerror(errno), errno);
		tester_test_failed();
		return;
	}

	data->step++;
}

static gboolean iso_pollout(GIOChannel *io, GIOCondition cond,
				gpointer user_data)
{
	struct test_data *data = user_data;
	const struct iso_client_data *isodata = data->test_data;
	unsigned int count;

	data->io_id[0] = 0;

	tester_print("POLLOUT event received");

	for (count = 0; count < isodata->repeat_send_pre_ts; ++count)
		iso_send_data(data, io);

	iso_tx_timestamping(data, io);

	for (count = 0; count < isodata->repeat_send + 1; ++count)
		iso_send_data(data, io);

	if (isodata->bcast) {
		tester_test_passed();
		return FALSE;
	}

	if (isodata->recv)
		iso_recv(data, io);

	return FALSE;
}

static void iso_send(struct test_data *data, GIOChannel *io)
{
	data->io_id[0] = g_io_add_watch(io, G_IO_OUT, iso_pollout, data);
}

static bool hook_set_event_mask(const void *msg, uint16_t len, void *user_data)
{
	struct test_data *data = user_data;

	tester_print("Set Event Mask");

	--data->step;
	if (!data->step)
		tester_test_passed();

	return true;
}

static void trigger_force_suspend(void *user_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Make sure suspend is only triggered once */
	if (data->suspending)
		return;

	data->suspending = true;

	/* Triggers the suspend */
	tester_print("Set the system into Suspend via force_suspend");
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		return;
	}

	data->step++;

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_CMD,
					BT_HCI_CMD_SET_EVENT_MASK,
					hook_set_event_mask, data);
}

static gboolean iso_connect(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	int err, sk_err, sk;
	socklen_t len;
	struct bt_iso_qos qos;
	bool ret = true;
	uint8_t base[BASE_MAX_LENGTH] = {0};

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		data->step = 0;
		tester_test_failed();
		return FALSE;
	}

	if (!isodata->bcast) {
		ret = check_ucast_qos(&qos, &isodata->qos,
				      isodata->mconn ? &isodata->qos_2 : NULL);
	} else if (!isodata->server)
		ret = check_bcast_qos(&qos, &isodata->qos);

	if (!ret) {
		tester_warn("Unexpected QoS parameter");
		data->step = 0;
		tester_test_failed();
		return FALSE;
	}

	if (isodata->bcast && isodata->server && isodata->base) {
		len = BASE_MAX_LENGTH;

		if (getsockopt(sk, SOL_BLUETOOTH, BT_ISO_BASE,
				base, &len) < 0) {
			tester_warn("Can't get socket option : %s (%d)",
						strerror(errno), errno);
			data->step = 0;
			tester_test_failed();
			return FALSE;
		}

		if (len != isodata->base_len ||
				memcmp(base, isodata->base, len)) {
			tester_warn("Unexpected BASE");
			data->step = 0;
			tester_test_failed();
			return FALSE;
		}
	}

	if (isodata->sid == 0xff) {
		struct {
			struct sockaddr_iso iso;
			struct sockaddr_iso_bc bc;
		} addr;
		socklen_t olen;

		olen = sizeof(addr);

		memset(&addr, 0, olen);
		if (getpeername(sk, (void *)&addr, &olen) < 0) {
			tester_warn("getpeername: %s (%d)",
					strerror(errno), errno);
			data->step = 0;
			tester_test_failed();
			return FALSE;
		}

		if (olen != sizeof(addr)) {
			tester_warn("getpeername: olen %d != %zu sizeof(addr)",
					olen, sizeof(addr));
			data->step = 0;
			tester_test_failed();
			return FALSE;
		}

		if (addr.bc.bc_sid > 0x0f) {
			tester_warn("Invalid SID: %d", addr.bc.bc_sid);
			data->step = 0;
			tester_test_failed();
			return FALSE;
		}

		tester_print("SID: 0x%02x", addr.bc.bc_sid);
	}

	len = sizeof(sk_err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0)
		tester_warn("Connect failed: %s (%d)", strerror(-err), -err);
	else
		tester_print("Successfully connected");

	if (err != isodata->expect_err) {
		tester_warn("Expect error: %s (%d) != %s (%d)",
				strerror(-isodata->expect_err),
				-isodata->expect_err, strerror(-err), -err);
		data->step = 0;
		tester_test_failed();
	} else {
		data->step--;
		if (data->step)
			tester_print("Step %u", data->step);
		else if (isodata->send)
			iso_send(data, io);
		else if (isodata->recv)
			iso_recv(data, io);
		else if (isodata->disconnect)
			iso_shutdown(data, io);
		else if (isodata->suspend)
			trigger_force_suspend(data);
		else
			tester_test_passed();
	}

	return FALSE;
}

static gboolean iso_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[0] = 0;

	return iso_connect(io, cond, user_data);
}

static gboolean iso_connect2_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[1] = 0;

	return iso_connect(io, cond, user_data);
}

static int setup_sock(struct test_data *data, uint8_t num)
{
	int sk, err;

	sk = create_iso_sock(data);
	if (sk < 0) {
		if (sk == -EPROTONOSUPPORT)
			tester_test_abort();
		else
			tester_test_failed();

		return sk;
	}

	err = connect_iso_sock(data, num, sk);
	if (err < 0) {
		const struct iso_client_data *isodata = data->test_data;

		close(sk);

		if (isodata->expect_err == err)
			tester_test_passed();
		else
			tester_test_failed();

		return err;
	}

	return sk;
}

static int connect_deferred(int sk)
{
	int defer;
	socklen_t len;
	struct pollfd pfd;
	char c;

	/* Check if socket has DEFER_SETUP set */
	len = sizeof(defer);
	if (getsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &defer,
					&len) < 0) {
		tester_warn("getsockopt: %s (%d)", strerror(errno),
				errno);
		tester_test_failed();
		return 0;
	}

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = sk;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, 0) < 0) {
		tester_warn("poll: %s (%d)", strerror(errno), errno);
		tester_test_failed();
		return -EIO;
	}

	if (!(pfd.revents & POLLOUT)) {
		if (read(sk, &c, 1) < 0) {
			tester_warn("read: %s (%d)", strerror(errno),
					errno);
			tester_test_failed();
			return -EIO;
		}
	}

	return 0;
}

static void setup_connect_many(struct test_data *data, uint8_t n, uint8_t *num,
								GIOFunc *func)
{
	const struct iso_client_data *isodata = data->test_data;
	int sk[256];
	GIOChannel *io;
	unsigned int i;

	for (i = 0; i < n; ++i) {
		sk[i] = setup_sock(data, num[i]);
		if (sk[i] < 0)
			return;
	}

	if (isodata->defer) {
		for (i = 0; i < n; ++i)
			if (connect_deferred(sk[i]) < 0)
				return;
	}

	for (i = 0; i < n; ++i) {
		io = g_io_channel_unix_new(sk[i]);
		g_io_channel_set_close_on_unref(io, TRUE);

		data->io_id[num[i]] = g_io_add_watch(io, G_IO_OUT, func[i],
									NULL);

		if (!isodata->bcast || !data->reconnect)
			g_io_channel_unref(io);
		else if (data->io_queue)
			/* For the broadcast reconnect scenario, do not
			 * unref channel here, to avoid closing the
			 * socket. All queued channels will be closed
			 * by test_data_free.
			 */
			queue_push_tail(data->io_queue, io);

		tester_print("Connect %d in progress", num[i]);

		data->step++;
	}
}

static void setup_connect(struct test_data *data, uint8_t num, GIOFunc func)
{
	return setup_connect_many(data, 1, &num, &func);
}

static void test_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = test_data;
	uint8_t n = 0;
	GIOFunc func[2];
	uint8_t num[2] = {0, 1};

	func[n++] = iso_connect_cb;

	/* Check if configuration requires multiple CIS setup */
	if (!isodata->bcast && isodata->mconn)
		func[n++] = iso_connect2_cb;

	setup_connect_many(data, n, num, func);
}

static void test_reconnect(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->reconnect = 1;
	test_connect(test_data);
}

static void test_reconnect_16(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->reconnect = 16;
	test_connect(test_data);
}

static void test_defer(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	int sk, err;

	sk = create_iso_sock(data);
	if (sk < 0) {
		if (sk == -EPROTONOSUPPORT)
			tester_test_abort();
		else
			tester_test_failed();
		return;
	}

	err = connect_iso_sock(data, 0, sk);
	if (err < 0) {
		close(sk);

		if (isodata->expect_err == err)
			tester_test_passed();
		else
			tester_test_failed();

		return;
	}

	err = close(sk);

	if (isodata->expect_err == err)
		tester_test_passed();
	else
		tester_test_failed();
}

static int listen_iso_sock(struct test_data *data, uint8_t num)
{
	const struct iso_client_data *isodata = data->test_data;
	const uint8_t *src, *dst;
	struct sockaddr_iso *addr = NULL;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_ISO);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	src = hciemu_get_central_bdaddr(data->hciemu);
	if (!src) {
		tester_warn("No source bdaddr");
		err = -ENODEV;
		goto fail;
	}

	/* Bind to local address */
	addr = malloc(sizeof(*addr) + sizeof(*addr->iso_bc));
	memset(addr, 0, sizeof(*addr) + sizeof(*addr->iso_bc));
	addr->iso_family = AF_BLUETOOTH;
	bacpy(&addr->iso_bdaddr, (void *) src);
	addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;

	if (isodata->bcast) {
		struct hciemu_client *client;

		client = hciemu_get_client(data->hciemu, num);

		/* Bind to destination address in case of broadcast */
		dst = hciemu_client_bdaddr(client);
		if (!dst) {
			tester_warn("No source bdaddr");
			err = -ENODEV;
			goto fail;
		}

		bacpy(&addr->iso_bc->bc_bdaddr, (void *) dst);
		addr->iso_bc->bc_bdaddr_type = BDADDR_LE_PUBLIC;
		addr->iso_bc->bc_sid = isodata->sid;

		if (!isodata->defer || isodata->listen_bind) {
			addr->iso_bc->bc_num_bis = 1;
			addr->iso_bc->bc_bis[0] = 1;
		}

		err = bind(sk, (struct sockaddr *) addr, sizeof(*addr) +
						   sizeof(*addr->iso_bc));
	} else
		err = bind(sk, (struct sockaddr *) addr, sizeof(*addr));


	if (err < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		goto fail;
	}

	if (isodata->defer) {
		int opt = 1;

		if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &opt,
							sizeof(opt)) < 0) {
			tester_print("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);
			goto fail;
		}
	}

	if (setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &isodata->qos,
						sizeof(isodata->qos)) < 0) {
		tester_print("Can't set socket BT_ISO_QOS option: %s (%d)",
					strerror(errno), errno);
		goto fail;
	}

	if (listen(sk, 10)) {
		err = -errno;
		tester_warn("Can't listen socket: %s (%d)", strerror(errno),
									errno);
		goto fail;
	}

	free(addr);

	return sk;

fail:
	free(addr);
	close(sk);
	return err;
}

static void setup_listen_many(struct test_data *data, uint8_t n, uint8_t *num,
								GIOFunc *func)
{
	const struct iso_client_data *isodata = data->test_data;
	int sk[256];
	GIOChannel *io;
	unsigned int i;

	for (i = 0; i < n; ++i) {
		sk[i] = listen_iso_sock(data, num[i]);
		if (sk[i] < 0) {
			if (sk[i] == -EPROTONOSUPPORT)
				tester_test_abort();
			else
				tester_test_failed();
			return;
		}

		io = g_io_channel_unix_new(sk[i]);
		g_io_channel_set_close_on_unref(io, TRUE);

		data->io_id[num[i]] = g_io_add_watch(io, G_IO_IN,
							func[i], NULL);

		g_io_channel_unref(io);

		tester_print("Listen %d in progress", num[i]);

		data->step++;
	}

	if (!isodata->bcast) {
		struct hciemu_client *client;
		struct bthost *host;

		if (!data->acl_handle) {
			tester_print("ACL handle not set");
			tester_test_failed();
			return;
		}

		client = hciemu_get_client(data->hciemu, 0);
		host = hciemu_client_host(client);

		bthost_set_cig_params(host, 0x01, 0x01, &isodata->qos);
		bthost_create_cis(host, 257, data->acl_handle);
	}
}

static void setup_listen(struct test_data *data, uint8_t num, GIOFunc func)
{
	return setup_listen_many(data, 1, &num, &func);
}

static bool iso_defer_accept_bcast(struct test_data *data, GIOChannel *io,
						uint8_t num, GIOFunc func)
{
	int sk;
	char c;
	const struct iso_client_data *isodata = data->test_data;
	struct sockaddr_iso *addr = NULL;

	sk = g_io_channel_unix_get_fd(io);

	if (isodata->pa_bind) {
		addr = malloc(sizeof(*addr) + sizeof(*addr->iso_bc));
		memset(addr, 0, sizeof(*addr) + sizeof(*addr->iso_bc));
		addr->iso_family = AF_BLUETOOTH;

		addr->iso_bc->bc_num_bis = 1;
		addr->iso_bc->bc_bis[0] = 1;

		if (bind(sk, (struct sockaddr *) addr, sizeof(*addr) +
						sizeof(*addr->iso_bc)) < 0) {
			tester_warn("bind: %s (%d)", strerror(errno), errno);
			free(addr);
			return false;
		}

		free(addr);
	}

	if (read(sk, &c, 1) < 0) {
		tester_warn("read: %s (%d)", strerror(errno), errno);
		return false;
	}

	tester_print("Accept deferred setup");

	if (!data->io_queue)
		data->io_queue = queue_new();

	if (data->io_queue)
		queue_push_tail(data->io_queue, io);

	data->io_id[num] = g_io_add_watch(io, G_IO_IN,
				func, NULL);

	return true;
}

static bool iso_defer_accept_ucast(struct test_data *data, GIOChannel *io,
						uint8_t num, GIOFunc func)
{
	int sk;
	char c;
	struct pollfd pfd;

	sk = g_io_channel_unix_get_fd(io);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = sk;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, 0) < 0) {
		tester_warn("poll: %s (%d)", strerror(errno), errno);
		return false;
	}

	if (!(pfd.revents & POLLOUT)) {
		if (read(sk, &c, 1) < 0) {
			tester_warn("read: %s (%d)", strerror(errno), errno);
			return false;
		}
	}

	tester_print("Accept deferred setup");

	data->io_queue = queue_new();
	if (data->io_queue)
		queue_push_tail(data->io_queue, io);

	data->io_id[num] = g_io_add_watch(io, G_IO_OUT,
				func, NULL);

	return true;
}

static gboolean iso_accept(GIOChannel *io, GIOCondition cond,
				gpointer user_data, uint8_t num, GIOFunc func)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	int sk, new_sk;
	gboolean ret;
	GIOChannel *new_io;
	iso_defer_accept_t iso_defer_accept = isodata->bcast ?
						iso_defer_accept_bcast :
						iso_defer_accept_ucast;

	sk = g_io_channel_unix_get_fd(io);

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		tester_test_failed();
		return false;
	}

	new_io = g_io_channel_unix_new(new_sk);
	g_io_channel_set_close_on_unref(new_io, TRUE);

	if (isodata->defer) {
		if (isodata->expect_err < 0) {
			g_io_channel_unref(new_io);
			tester_test_passed();
			return false;
		}

		if (isodata->bcast) {
			iso_connect(new_io, cond, user_data);

			if (!data->step) {
				g_io_channel_unref(new_io);
				return false;
			}

			/* Return if connection has already been accepted */
			if (queue_find(data->io_queue, NULL, io)) {
				g_io_channel_unref(new_io);
				return false;
			}
		}

		if (!iso_defer_accept(data, new_io, num, func)) {
			tester_warn("Unable to accept deferred setup");
			tester_test_failed();
		}
		return false;
	}

	if (isodata->pkt_status) {
		int opt = 1;

		if (setsockopt(new_sk, SOL_BLUETOOTH, BT_PKT_STATUS, &opt,
							sizeof(opt)) < 0) {
			tester_print("Can't set socket BT_PKT_STATUS option: "
					"%s (%d)", strerror(errno), errno);
			tester_test_failed();
			return false;
		}
	}

	if (isodata->pkt_seqnum) {
		int opt = 1;

		data->seqnum = -1;

		if (setsockopt(new_sk, SOL_BLUETOOTH, BT_PKT_SEQNUM, &opt,
							sizeof(opt)) < 0) {
			tester_print("Can't set socket BT_PKT_SEQNUM option: "
					"%s (%d)", strerror(errno), errno);
			tester_test_failed();
			return false;
		}
	}

	ret = iso_connect(new_io, cond, user_data);

	g_io_channel_unref(new_io);
	return ret;
}

static gboolean iso_accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;

	data->io_id[0] = 0;

	if (isodata->bcast)
		return iso_accept(io, cond, user_data, 0, iso_accept_cb);
	else
		return iso_accept(io, cond, user_data, 0, iso_connect_cb);
}

static gboolean iso_accept2_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[1] = 0;

	return iso_accept(io, cond, user_data, 1, iso_accept2_cb);
}

static void test_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_listen(data, 0, iso_accept_cb);
}

static void test_connect2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	uint8_t num[2] = {0, 1};
	GIOFunc funcs[2] = {iso_connect_cb, iso_connect2_cb};

	setup_connect_many(data, 2, num, funcs);
}

static gboolean iso_connect2_seq_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[0] = 0;

	setup_connect(data, 1, iso_connect2_cb);

	return iso_connect(io, cond, user_data);
}

static void test_connect2_seq(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_connect(data, 0, iso_connect2_seq_cb);
}

static gboolean test_connect2_busy_done(gpointer user_data)
{
	struct test_data *data = tester_get_data();

	if (data->io_id[0] > 0) {
		/* First connection still exists */
		g_source_remove(data->io_id[0]);
		data->io_id[0] = 0;
		tester_test_passed();
	} else {
		tester_test_failed();
	}

	return FALSE;
}

static gboolean iso_connect_cb_busy_disc(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[0] = 0;

	tester_print("Disconnected 1");
	tester_test_failed();
	return FALSE;
}

static gboolean iso_connect_cb_busy_2(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	int err, sk_err, sk;
	socklen_t len;

	data->io_id[1] = 0;

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(sk_err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	tester_print("Connected 2: %d", err);

	if (err == -EBUSY && data->io_id[0] > 0) {
		/* Wait in case first connection still gets disconnected */
		data->io_id[1] = g_timeout_add(250, test_connect2_busy_done,
									data);
	} else {
		tester_test_failed();
	}

	return FALSE;
}

static gboolean iso_connect_cb_busy(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	/* First connection shall not be disconnected */
	data->io_id[0] = g_io_add_watch(io, G_IO_ERR | G_IO_HUP,
						iso_connect_cb_busy_disc, data);

	/* Second connect shall fail since CIG is now busy */
	setup_connect(data, 1, iso_connect_cb_busy_2);

	return iso_connect(io, cond, user_data);
}

static void test_connect2_busy(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_connect(data, 0, iso_connect_cb_busy);
}

static gboolean iso_connect_close_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;

	data->io_id[0] = 0;

	tester_print("Disconnected");

	--data->step;
	if (!data->step)
		tester_test_passed();

	return FALSE;
}

static bool hook_remove_cig(const void *msg, uint16_t len, void *user_data)
{
	struct test_data *data = user_data;

	tester_print("Remove CIG");

	--data->step;
	if (!data->step)
		tester_test_passed();

	return true;
}

static void test_connect_close(const void *test_data)
{
	struct test_data *data = tester_get_data();
	int sk;
	GIOChannel *io;

	data->step = 2;

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_CMD,
					BT_HCI_CMD_LE_REMOVE_CIG,
					hook_remove_cig, data);

	sk = setup_sock(data, 0);
	if (sk < 0)
		return;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	data->io_id[0] = g_io_add_watch(io, G_IO_HUP, iso_connect_close_cb,
									data);

	shutdown(sk, SHUT_RDWR);
}

static gboolean iso_connect_wait_close_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	int sk;

	tester_print("Connected");

	sk = g_io_channel_unix_get_fd(io);

	data->io_id[0] = g_io_add_watch(io, G_IO_HUP, iso_connect_close_cb,
									data);

	shutdown(sk, SHUT_RDWR);

	return FALSE;
}

static void test_connect_wait_close(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->step = 1;

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_CMD,
					BT_HCI_CMD_LE_REMOVE_CIG,
					hook_remove_cig, data);

	setup_connect(data, 0, iso_connect_wait_close_cb);
}

static void test_connect_suspend(const void *test_data)
{
	test_connect(test_data);
	trigger_force_suspend((void *)test_data);
}

static bool hook_acl_disc(const void *msg, uint16_t len, void *user_data)
{
	const uint8_t *msg_data = msg;
	const struct bt_hci_evt_le_enhanced_conn_complete *ev;
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	if (msg_data[0] != BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE)
		return true;

	ev = (void *) &msg_data[1];

	tester_print("Disconnect ACL");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_hci_disconnect(bthost, le16_to_cpu(ev->handle), 0x13);

	hciemu_flush_client_events(data->hciemu);

	return true;
}

static void test_connect_acl_disc(const void *test_data)
{
	struct test_data *data = tester_get_data();

	/* ACL disconnected before ISO is created */
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_LE_META_EVENT,
					hook_acl_disc, NULL);

	test_connect(test_data);
}

static void test_bcast(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_connect(data, 0, iso_connect_cb);
}

static void test_bcast_reconnect(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->reconnect = 1;
	setup_connect(data, 0, iso_connect_cb);
}

static void test_bcast2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	uint8_t num[2] = {0, 1};
	GIOFunc funcs[2] = {iso_connect_cb, iso_connect2_cb};

	setup_connect_many(data, 2, num, funcs);
}

static void test_bcast2_reconn(const void *test_data)
{
	struct test_data *data = tester_get_data();
	uint8_t num[2] = {0, 1};
	GIOFunc funcs[2] = {iso_connect_cb, iso_connect2_cb};

	data->io_queue = queue_new();

	data->reconnect = 1;
	setup_connect_many(data, 2, num, funcs);
}

static void test_bcast_recv(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_listen(data, 0, iso_accept_cb);
}

static void test_bcast_recv2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	uint8_t num[2] = {0, 1};
	GIOFunc funcs[2] = {iso_accept_cb, iso_accept2_cb};

	setup_listen_many(data, 2, num, funcs);
}

static void test_bcast_recv_defer(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->step = 1;

	setup_listen(data, 0, iso_accept_cb);
}

static void test_bcast_recv_defer_reconnect(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->reconnect = 1;
	data->step = 1;

	setup_listen(data, 0, iso_accept_cb);
}

static void test_bcast_recv2_defer(const void *test_data)
{
	struct test_data *data = tester_get_data();
	uint8_t num[2] = {0, 1};
	GIOFunc funcs[2] = {iso_accept_cb, iso_accept2_cb};

	data->step = 2;

	setup_listen_many(data, 2, num, funcs);
}

static void test_connect2_suspend(const void *test_data)
{
	test_connect2(test_data);
	trigger_force_suspend((void *)test_data);
}

static void test_iso_ethtool_get_ts_info(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_ethtool_get_ts_info(data->mgmt_index, BTPROTO_ISO, false);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_iso("Basic Framework - Success", NULL, setup_powered,
							test_framework);

	test_iso("Basic ISO Socket - Success", NULL, setup_powered,
							test_socket);

	test_iso("Basic ISO Get Socket Option - Success", NULL, setup_powered,
							test_getsockopt);

	test_iso("Basic ISO Set Socket Option - Success", NULL, setup_powered,
							test_setsockopt);

	test_iso("ISO QoS 8_1_1 - Success", &connect_8_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_2_1 - Success", &connect_8_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_1_1 - Success", &connect_16_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_1 - Success", &connect_16_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_1 CIG 0x01 - Success", &connect_1_16_2_1,
							setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_1 CIG 0x01 CIS 0x01 - Success",
							&connect_1_1_16_2_1,
							setup_powered,
							test_connect);

	test_iso("ISO QoS 24_1_1 - Success", &connect_24_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_2_1 - Success", &connect_24_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_1 - Success", &connect_32_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_1 - Success", &connect_32_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_1_1 - Success", &connect_44_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_2_1 - Success", &connect_44_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_1 - Success", &connect_48_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_1 - Success", &connect_48_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_3_1 - Success", &connect_48_3_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_4_1 - Success", &connect_48_4_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_5_1 - Success", &connect_48_5_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_6_1 - Success", &connect_48_6_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_1_2 - Success", &connect_8_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_2_2 - Success", &connect_8_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_1_2 - Success", &connect_16_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_2 - Success", &connect_16_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_1_2 - Success", &connect_24_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_2_2 - Success", &connect_24_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_2 - Success", &connect_32_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_2 - Success", &connect_32_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_1_2 - Success", &connect_44_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_2_2 - Success", &connect_44_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_2 - Success", &connect_48_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_2 - Success", &connect_48_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_3_2 - Success", &connect_48_3_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_4_2 - Success", &connect_48_4_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_5_2 - Success", &connect_48_5_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_6_2 - Success", &connect_48_6_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_1_gs - Success", &connect_16_1_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_gs - Success", &connect_16_2_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_gs - Success", &connect_32_1_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_gs - Success", &connect_32_2_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_gs - Success", &connect_48_1_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_gs - Success", &connect_48_2_gs, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_gr - Success", &connect_32_1_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_gr - Success", &connect_32_2_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_gr - Success", &connect_48_1_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_gr - Success", &connect_48_2_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_3_gr - Success", &connect_48_3_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_4_gr - Success", &connect_48_4_gr, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_g - Success", &bcast_48_1_g,
						setup_powered, test_bcast);

	test_iso("ISO QoS 48_2_g - Success", &bcast_48_2_g,
						setup_powered, test_bcast);

	test_iso("ISO QoS 48_3_g - Success", &bcast_48_3_g,
						setup_powered, test_bcast);

	test_iso("ISO QoS 48_4_g - Success", &bcast_48_4_g,
						setup_powered, test_bcast);

	test_iso("ISO QoS - Invalid", &connect_invalid, setup_powered,
							test_connect);

	test_iso("ISO QoS CIG 0xF0 - Invalid", &connect_cig_f0_invalid,
			setup_powered, test_connect);

	test_iso("ISO QoS CIS 0xF0 - Invalid", &connect_cis_f0_invalid,
			setup_powered, test_connect);

	test_iso_rej("ISO Connect - Reject", &connect_reject, setup_powered,
			test_connect, BT_HCI_ERR_CONN_FAILED_TO_ESTABLISH);

	test_iso("ISO Send - Success", &connect_16_2_1_send, setup_powered,
							test_connect);

	/* Test basic TX timestamping */
	test_iso("ISO Send - TX Timestamping", &connect_send_tx_timestamping,
						setup_powered, test_connect);

	/* Test TX timestamping with flags set via per-packet CMSG */
	test_iso("ISO Send - TX CMSG Timestamping",
			&connect_send_tx_cmsg_timestamping, setup_powered,
			test_connect);

	test_iso("ISO Receive - Success", &listen_16_2_1_recv, setup_powered,
							test_listen);

	test_iso("ISO Receive Fragmented - Success", &listen_16_2_1_recv_frag,
							setup_powered,
							test_listen);

	test_iso("ISO Receive Timestamped - Success", &listen_16_2_1_recv_ts,
							setup_powered,
							test_listen);

	test_iso("ISO Receive Packet Status - Success",
						&listen_16_2_1_recv_pkt_status,
						setup_powered, test_listen);

	test_iso("ISO Receive Packet Seqnum - Success",
						&listen_16_2_1_recv_pkt_seqnum,
						setup_powered, test_listen);

	test_iso("ISO Receive - RX Timestamping",
					&listen_16_2_1_recv_rx_timestamping,
					setup_powered, test_listen);

	test_iso("ISO Receive - HW Timestamping",
					&listen_16_2_1_recv_hw_timestamping,
					setup_powered, test_listen);

	test_iso("ISO Receive Fragmented - HW Timestamping",
				&listen_16_2_1_recv_frag_hw_timestamping,
				setup_powered, test_listen);

	test_iso("ISO Defer - Success", &defer_16_2_1, setup_powered,
							test_defer);

	test_iso("ISO Defer Connect - Success", &defer_16_2_1, setup_powered,
							test_connect);

	test_iso("ISO Defer Close - Success", &defer_16_2_1, setup_powered,
							test_connect_close);

	test_iso("ISO Connect Close - Success", &connect_16_2_1, setup_powered,
							test_connect_close);

	test_iso("ISO Defer Wait Close - Success", &defer_16_2_1,
					setup_powered, test_connect_wait_close);

	test_iso("ISO Connect Wait Close - Success", &connect_16_2_1,
					setup_powered, test_connect_wait_close);

	test_iso("ISO Connect Suspend - Success", &connect_suspend,
							setup_powered,
							test_connect_suspend);

	test_iso("ISO Connected Suspend - Success", &suspend_16_2_1,
							setup_powered,
							test_connect);

	test_iso2("ISO Connect2 CIG 0x01 - Success", &connect_1_16_2_1,
							setup_powered,
							test_connect2);

	test_iso2("ISO Connect2 Busy CIG 0x01 - Success/Invalid",
					&connect_1_16_2_1, setup_powered,
					test_connect2_busy);

	test_iso2("ISO Defer Connect2 CIG 0x01 - Success", &defer_1_16_2_1,
							setup_powered,
							test_connect2);

	test_iso2("ISO Connect2 Suspend - Success", &connect_suspend,
							setup_powered,
							test_connect2_suspend);

	test_iso2("ISO Connected2 Suspend - Success", &suspend_16_2_1,
							setup_powered,
							test_connect2);

	test_iso("ISO Connect ACL Disconnect - Failure", &connect_suspend,
							setup_powered,
							test_connect_acl_disc);

	test_iso("ISO Defer Send - Success", &connect_16_2_1_defer_send,
							setup_powered,
							test_connect);

	test_iso("ISO 48_2_1 Defer Send - Success", &connect_48_2_1_defer_send,
							setup_powered,
							test_connect);

	test_iso("ISO Defer Receive - Success", &listen_16_2_1_defer_recv,
						setup_powered, test_listen);

	test_iso("ISO 48_2_1 Defer Receive - Success",
						&listen_48_2_1_defer_recv,
						setup_powered, test_listen);

	test_iso("ISO Defer Reject - Success", &listen_16_2_1_defer_reject,
						setup_powered, test_listen);

	test_iso("ISO Send and Receive - Success", &connect_16_2_1_send_recv,
							setup_powered,
							test_connect);

	test_iso("ISO Disconnect - Success", &disconnect_16_2_1,
							setup_powered,
							test_connect);

	test_iso("ISO Reconnect - Success", &reconnect_16_2_1,
							setup_powered,
							test_reconnect);

	test_iso("ISO Reconnect Send and Receive #16 - Success",
						&reconnect_16_2_1_send_recv,
						setup_powered,
						test_reconnect_16);

	test_iso("ISO AC 1 & 4 - Success", &connect_ac_1_4, setup_powered,
							test_connect);

	test_iso("ISO AC 2 & 10 - Success", &connect_ac_2_10, setup_powered,
							test_connect);

	test_iso("ISO AC 3 & 5 - Success", &connect_ac_3_5, setup_powered,
							test_connect);

	test_iso("ISO AC 6(i) - Success", &connect_ac_6i, setup_powered,
							test_connect);

	test_iso2("ISO AC 6(ii) - Success", &connect_ac_6ii, setup_powered,
							test_connect2);

	test_iso("ISO AC 7(i) - Success", &connect_ac_7i, setup_powered,
							test_connect);

	test_iso2("ISO AC 7(ii) - Success", &connect_ac_7ii, setup_powered,
							test_connect2);

	test_iso("ISO AC 8(i) - Success", &connect_ac_8i, setup_powered,
							test_connect);

	test_iso2("ISO AC 8(ii) - Success", &connect_ac_8ii, setup_powered,
							test_connect2);

	test_iso("ISO AC 9(i) - Success", &connect_ac_9i, setup_powered,
							test_connect);

	test_iso2("ISO AC 9(ii) - Success", &connect_ac_9ii, setup_powered,
							test_connect2);

	test_iso("ISO AC 11(i) - Success", &connect_ac_11i, setup_powered,
							test_connect);

	test_iso2("ISO AC 11(ii) - Success", &connect_ac_11ii, setup_powered,
							test_connect2);

	test_iso2("ISO AC 1 + 2 - Success", &connect_ac_1_2, setup_powered,
							test_connect2_seq);

	test_iso2("ISO AC 1 + 2 CIG 0x01/0x02 - Success",
							&connect_ac_1_2_cig_1_2,
							setup_powered,
							test_connect2_seq);

	test_iso2("ISO Reconnect AC 6(i) - Success", &reconnect_ac_6i,
							setup_powered,
							test_reconnect);

	test_iso2("ISO Reconnect AC 6(ii) - Success", &reconnect_ac_6ii,
							setup_powered,
							test_reconnect);

	test_iso2("ISO AC 6(ii) CIS 0xEF/auto - Success",
						&connect_ac_6ii_cis_ef_auto,
						setup_powered, test_connect);

	test_iso2("ISO AC 6(ii) CIS 0xEF/0xEF - Invalid",
						&connect_ac_6ii_cis_ef_ef,
						setup_powered, test_connect);

	test_iso("ISO Broadcaster - Success", &bcast_16_2_1_send, setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster Encrypted - Success", &bcast_enc_16_2_1_send,
							setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster BIG 0x01 - Success", &bcast_1_16_2_1_send,
							setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster BIG 0x01 BIS 0x01 - Success",
							&bcast_1_1_16_2_1_send,
							setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster SID auto - Success", &bcast_16_2_1_send_sid,
							setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster SID 0x01 - Success", &bcast_16_2_1_send_sid1,
							setup_powered,
							test_bcast);
	test_iso("ISO Broadcaster Reconnect - Success", &bcast_16_2_1_reconnect,
							setup_powered,
							test_bcast_reconnect);

	test_iso("ISO Broadcaster Receiver - Success", &bcast_16_2_1_recv,
							setup_powered,
							test_bcast_recv);
	test_iso("ISO Broadcaster Receiver SID auto - Success",
							&bcast_16_2_1_recv_sid,
							setup_powered,
							test_bcast_recv);
	test_iso("ISO Broadcaster Receiver SID 0x01 - Success",
							&bcast_16_2_1_recv_sid1,
							setup_powered,
							test_bcast_recv);
	test_iso2("ISO Broadcaster Receiver2 - Success", &bcast_16_2_1_recv2,
							setup_powered,
							test_bcast_recv2);

	test_iso("ISO Broadcaster Receiver Encrypted - Success",
							&bcast_enc_16_2_1_recv,
							setup_powered,
							test_bcast_recv);
	test_iso("ISO Broadcaster Receiver Defer - Success",
						&bcast_16_2_1_recv_defer,
						setup_powered,
						test_bcast_recv_defer);
	test_iso("ISO Broadcaster Receiver Defer Reconnect - Success",
					&bcast_16_2_1_recv_defer_reconnect,
					setup_powered,
					test_bcast_recv_defer_reconnect);
	test_iso2("ISO Broadcaster Receiver2 Defer - Success",
						&bcast_16_2_1_recv2_defer,
						setup_powered,
						test_bcast_recv2_defer);

	test_iso("ISO Broadcaster Receiver Defer No BIS - Success",
						&bcast_16_2_1_recv_defer_no_bis,
						setup_powered,
						test_bcast_recv);
	test_iso("ISO Broadcaster Receiver Defer PA Bind - Success",
					&bcast_16_2_1_recv_defer_pa_bind,
					setup_powered,
					test_bcast_recv_defer);
	test_iso("ISO Broadcaster Receiver Defer Get BASE - Success",
					&bcast_16_2_1_recv_defer_get_base,
					setup_powered,
					test_bcast_recv);

	test_iso("ISO Broadcaster AC 12 - Success", &bcast_ac_12, setup_powered,
							test_bcast);

	test_iso("ISO Broadcaster AC 13 BIG 0x01 BIS 0x01 - Success",
						&bcast_ac_13_1_1,
						setup_powered,
						test_bcast2);

	test_iso("ISO Broadcaster AC 13 BIG 0x01 - Success", &bcast_ac_13_1,
						setup_powered, test_bcast2);

	test_iso("ISO Broadcaster AC 13 Reconnect - Success",
					&bcast_ac_13_1_1_reconn, setup_powered,
					test_bcast2_reconn);

	test_iso("ISO Broadcaster AC 14 - Success", &bcast_ac_14, setup_powered,
							test_bcast);

	test_iso("ISO Ethtool Get Ts Info - Success", NULL, setup_powered,
						test_iso_ethtool_get_ts_info);

	return tester_run();
}
