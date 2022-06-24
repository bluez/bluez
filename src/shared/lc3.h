/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 */

#define LTV(_type, _bytes...) \
	{ \
		.len = 1 + sizeof((uint8_t []) { _bytes }), \
		.type = _type, \
		.data = { _bytes }, \
	}

#define LC3_ID			0x06

#define LC3_BASE		0x01

#define LC3_FREQ		(LC3_BASE)
#define LC3_FREQ_8KHZ		BIT(0)
#define LC3_FREQ_11KHZ		BIT(1)
#define LC3_FREQ_16KHZ		BIT(2)
#define LC3_FREQ_22KHZ		BIT(3)
#define LC3_FREQ_24KHZ		BIT(4)
#define LC3_FREQ_32KHZ		BIT(5)
#define LC3_FREQ_44KHZ		BIT(6)
#define LC3_FREQ_48KHZ		BIT(7)
#define LC3_FREQ_ANY		(LC3_FREQ_8KHZ | \
					LC3_FREQ_11KHZ | \
					LC3_FREQ_16KHZ | \
					LC3_FREQ_22KHZ | \
					LC3_FREQ_24KHZ | \
					LC3_FREQ_32KHZ | \
					LC3_FREQ_44KHZ | \
					LC3_FREQ_48KHZ)

#define LC3_DURATION		(LC3_BASE + 1)
#define LC3_DURATION_7_5	BIT(0)
#define LC3_DURATION_10		BIT(1)
#define LC3_DURATION_ANY	(LC3_DURATION_7_5 | LC3_DURATION_10)
#define LC3_DURATION_PREFER_7_5	BIT(4)
#define LC3_DURATION_PREFER_10	BIT(5)


#define LC3_CHAN_COUNT		(LC3_BASE + 2)
#define LC3_CHAN_COUNT_SUPPORT	BIT(0)

#define LC3_FRAME_LEN		(LC3_BASE + 3)

#define LC3_FRAME_COUNT		(LC3_BASE + 4)

#define LC3_CAPABILITIES(_freq, _duration, _chan_count, _len_min, _len_max) \
	{ \
		LTV(LC3_FREQ, _freq), \
		LTV(LC3_DURATION, _duration), \
		LTV(LC3_CHAN_COUNT, _chan_count), \
		LTV(LC3_FRAME_LEN, _len_min, _len_min >> 8, \
				_len_max, _len_max >> 8), \
	}

#define LC3_CONFIG_BASE		0x01

#define LC3_CONFIG_FREQ		(LC3_CONFIG_BASE)
#define LC3_CONFIG_FREQ_8KHZ	0x01
#define LC3_CONFIG_FREQ_11KHZ	0x02
#define LC3_CONFIG_FREQ_16KHZ	0x03
#define LC3_CONFIG_FREQ_22KHZ	0x04
#define LC3_CONFIG_FREQ_24KHZ	0x05
#define LC3_CONFIG_FREQ_32KHZ	0x06
#define LC3_CONFIG_FREQ_44KHZ	0x07
#define LC3_CONFIG_FREQ_48KHZ	0x08

#define LC3_CONFIG_DURATION	(LC3_CONFIG_BASE + 1)
#define LC3_CONFIG_DURATION_7_5	0x00
#define LC3_CONFIG_DURATION_10	0x01

#define LC3_CONFIG_CHAN_ALLOC	(LC3_CONFIG_BASE + 2)

#define LC3_CONFIG_FRAME_LEN	(LC3_CONFIG_BASE + 3)

#define LC3_CONFIG(_freq, _duration, _len) \
	{ \
		LTV(LC3_CONFIG_FREQ, _freq), \
		LTV(LC3_CONFIG_DURATION, _duration), \
		LTV(LC3_CONFIG_FRAME_LEN, _len, _len >> 8), \
	}

#define LC3_CONFIG_8KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_8KHZ, _duration, _len)

#define LC3_CONFIG_11KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_11KHZ, _duration, _len)

#define LC3_CONFIG_16KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_16KHZ, _duration, _len)

#define LC3_CONFIG_22KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_22KHZ, _duration, _len)

#define LC3_CONFIG_24KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_24KHZ, _duration, _len)

#define LC3_CONFIG_32KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_32KHZ, _duration, _len)

#define LC3_CONFIG_44KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_44KHZ, _duration, _len)

#define LC3_CONFIG_48KHZ(_duration, _len) \
	LC3_CONFIG(LC3_CONFIG_FREQ_48KHZ, _duration, _len)
