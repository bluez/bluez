/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2010 Keith Mok <ek9852@gmail.com>
 *  Copyright (C) 2008-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2004-2005  Henryk Ploetz <henryk@ploetzli.ch>
 *  Copyright (C) 2005-2006  Brad Midgley <bmidgley@xmission.com>
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

#include <stdint.h>
#include <limits.h>
#include "sbc.h"
#include "sbc_math.h"
#include "sbc_tables.h"

#include "sbc_primitives_iwmmxt.h"

/*
 * IWMMXT optimizations
 */

#ifdef SBC_BUILD_WITH_IWMMXT_SUPPORT

static inline void sbc_analyze_four_iwmmxt(const int16_t *in, int32_t *out,
					const FIXED_T *consts)
{
	asm volatile (
		"wldrd        wr0, [%0]\n"
		"tbcstw       wr4, %2\n"
		"wldrd        wr2, [%1]\n"
		"wldrd        wr1, [%0, #8]\n"
		"wldrd        wr3, [%1, #8]\n"
		"wmadds       wr0, wr2, wr0\n"
		" wldrd       wr6, [%0, #16]\n"
		"wmadds       wr1, wr3, wr1\n"
		" wldrd       wr7, [%0, #24]\n"
		"waddwss      wr0, wr0, wr4\n"
		" wldrd       wr8, [%1, #16]\n"
		"waddwss      wr1, wr1, wr4\n"
		" wldrd       wr9, [%1, #24]\n"
		" wmadds      wr6, wr8, wr6\n"
		"  wldrd      wr2, [%0, #32]\n"
		" wmadds      wr7, wr9, wr7\n"
		"  wldrd      wr3, [%0, #40]\n"
		" waddwss     wr0, wr6, wr0\n"
		"  wldrd      wr4, [%1, #32]\n"
		" waddwss     wr1, wr7, wr1\n"
		"  wldrd      wr5, [%1, #40]\n"
		"  wmadds     wr2, wr4, wr2\n"
		"wldrd        wr6, [%0, #48]\n"
		"  wmadds     wr3, wr5, wr3\n"
		"wldrd        wr7, [%0, #56]\n"
		"  waddwss    wr0, wr2, wr0\n"
		"wldrd        wr8, [%1, #48]\n"
		"  waddwss    wr1, wr3, wr1\n"
		"wldrd        wr9, [%1, #56]\n"
		"wmadds       wr6, wr8, wr6\n"
		" wldrd       wr2, [%0, #64]\n"
		"wmadds       wr7, wr9, wr7\n"
		" wldrd       wr3, [%0, #72]\n"
		"waddwss      wr0, wr6, wr0\n"
		" wldrd       wr4, [%1, #64]\n"
		"waddwss      wr1, wr7, wr1\n"
		" wldrd       wr5, [%1, #72]\n"
		" wmadds      wr2, wr4, wr2\n"
		"tmcr       wcgr0, %4\n"
		" wmadds      wr3, wr5, wr3\n"
		" waddwss     wr0, wr2, wr0\n"
		" waddwss     wr1, wr3, wr1\n"
		"\n"
		"wsrawg       wr0, wr0, wcgr0\n"
		" wldrd       wr4, [%1, #80]\n"
		"wsrawg       wr1, wr1, wcgr0\n"
		" wldrd       wr5, [%1, #88]\n"
		"wpackwss     wr0, wr0, wr0\n"
		" wldrd       wr6, [%1, #96]\n"
		"wpackwss     wr1, wr1, wr1\n"
		"wmadds       wr2, wr5, wr0\n"
		" wldrd       wr7, [%1, #104]\n"
		"wmadds       wr0, wr4, wr0\n"
		"\n"
		" wmadds      wr3, wr7, wr1\n"
		" wmadds      wr1, wr6, wr1\n"
		" waddwss     wr2, wr3, wr2\n"
		" waddwss     wr0, wr1, wr0\n"
		"\n"
		"wstrd        wr0, [%3]\n"
		"wstrd        wr2, [%3, #8]\n"
		:
		: "r" (in), "r" (consts),
			"r" (1 << (SBC_PROTO_FIXED4_SCALE - 1)), "r" (out),
			"r" (SBC_PROTO_FIXED4_SCALE)
		: "wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
		  "wr8", "wr9", "wcgr0", "memory");
}

static inline void sbc_analyze_eight_iwmmxt(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	asm volatile (
		"wldrd        wr0, [%0]\n"
		"tbcstw       wr15, %2\n"
		"wldrd        wr1, [%0, #8]\n"
		"wldrd        wr2, [%0, #16]\n"
		"wldrd        wr3, [%0, #24]\n"
		"wldrd        wr4, [%1]\n"
		"wldrd        wr5, [%1, #8]\n"
		"wldrd        wr6, [%1, #16]\n"
		"wldrd        wr7, [%1, #24]\n"
		"wmadds       wr0, wr0, wr4\n"
		" wldrd       wr8, [%1, #32]\n"
		"wmadds       wr1, wr1, wr5\n"
		" wldrd       wr9, [%1, #40]\n"
		"wmadds       wr2, wr2, wr6\n"
		" wldrd      wr10, [%1, #48]\n"
		"wmadds       wr3, wr3, wr7\n"
		" wldrd      wr11, [%1, #56]\n"
		"waddwss      wr0, wr0, wr15\n"
		" wldrd       wr4, [%0, #32]\n"
		"waddwss      wr1, wr1, wr15\n"
		" wldrd       wr5, [%0, #40]\n"
		"waddwss      wr2, wr2, wr15\n"
		" wldrd       wr6, [%0, #48]\n"
		"waddwss      wr3, wr3, wr15\n"
		" wldrd       wr7, [%0, #56]\n"
		" wmadds      wr4, wr4, wr8\n"
		"  wldrd     wr12, [%0, #64]\n"
		" wmadds      wr5, wr5, wr9\n"
		"  wldrd     wr13, [%0, #72]\n"
		" wmadds      wr6, wr6, wr10\n"
		"  wldrd     wr14, [%0, #80]\n"
		" wmadds      wr7, wr7, wr11\n"
		"  wldrd     wr15, [%0, #88]\n"
		" waddwss     wr0, wr4, wr0\n"
		"  wldrd      wr8, [%1, #64]\n"
		" waddwss     wr1, wr5, wr1\n"
		"  wldrd      wr9, [%1, #72]\n"
		" waddwss     wr2, wr6, wr2\n"
		"  wldrd     wr10, [%1, #80]\n"
		" waddwss     wr3, wr7, wr3\n"
		"  wldrd     wr11, [%1, #88]\n"
		"  wmadds    wr12, wr12, wr8\n"
		"wldrd        wr4, [%0, #96]\n"
		"  wmadds    wr13, wr13, wr9\n"
		"wldrd        wr5, [%0, #104]\n"
		"  wmadds    wr14, wr14, wr10\n"
		"wldrd        wr6, [%0, #112]\n"
		"  wmadds    wr15, wr15, wr11\n"
		"wldrd        wr7, [%0, #120]\n"
		"  waddwss    wr0, wr12, wr0\n"
		"wldrd        wr8, [%1, #96]\n"
		"  waddwss    wr1, wr13, wr1\n"
		"wldrd        wr9, [%1, #104]\n"
		"  waddwss    wr2, wr14, wr2\n"
		"wldrd       wr10, [%1, #112]\n"
		"  waddwss    wr3, wr15, wr3\n"
		"wldrd       wr11, [%1, #120]\n"
		"wmadds       wr4, wr4, wr8\n"
		" wldrd      wr12, [%0, #128]\n"
		"wmadds       wr5, wr5, wr9\n"
		" wldrd      wr13, [%0, #136]\n"
		"wmadds       wr6, wr6, wr10\n"
		" wldrd      wr14, [%0, #144]\n"
		"wmadds       wr7, wr7, wr11\n"
		" wldrd      wr15, [%0, #152]\n"
		"waddwss      wr0, wr4, wr0\n"
		" wldrd       wr8, [%1, #128]\n"
		"waddwss      wr1, wr5, wr1\n"
		" wldrd       wr9, [%1, #136]\n"
		"waddwss      wr2, wr6, wr2\n"
		" wldrd      wr10, [%1, #144]\n"
		" waddwss     wr3, wr7, wr3\n"
		" wldrd     wr11, [%1, #152]\n"
		" wmadds     wr12, wr12, wr8\n"
		"tmcr       wcgr0, %4\n"
		" wmadds     wr13, wr13, wr9\n"
		" wmadds     wr14, wr14, wr10\n"
		" wmadds     wr15, wr15, wr11\n"
		" waddwss     wr0, wr12, wr0\n"
		" waddwss     wr1, wr13, wr1\n"
		" waddwss     wr2, wr14, wr2\n"
		" waddwss     wr3, wr15, wr3\n"
		"\n"
		"wsrawg       wr0, wr0, wcgr0\n"
		"wsrawg       wr1, wr1, wcgr0\n"
		"wsrawg       wr2, wr2, wcgr0\n"
		"wsrawg       wr3, wr3, wcgr0\n"
		"\n"
		"wpackwss     wr0, wr0, wr0\n"
		"wpackwss     wr1, wr1, wr1\n"
		" wldrd       wr4, [%1, #160]\n"
		"wpackwss     wr2, wr2, wr2\n"
		" wldrd       wr5, [%1, #168]\n"
		"wpackwss     wr3, wr3, wr3\n"
		"  wldrd      wr6, [%1, #192]\n"
		" wmadds      wr4, wr4, wr0\n"
		"  wldrd      wr7, [%1, #200]\n"
		" wmadds      wr5, wr5, wr0\n"
		"   wldrd     wr8, [%1, #224]\n"
		"  wmadds     wr6, wr6, wr1\n"
		"   wldrd     wr9, [%1, #232]\n"
		"  wmadds     wr7, wr7, wr1\n"
		"  waddwss    wr4, wr6, wr4\n"
		"  waddwss    wr5, wr7, wr5\n"
		"   wmadds    wr8, wr8, wr2\n"
		"wldrd        wr6, [%1, #256]\n"
		"   wmadds    wr9, wr9, wr2\n"
		"wldrd        wr7, [%1, #264]\n"
		"waddwss      wr4, wr8, wr4\n"
		"   waddwss   wr5, wr9, wr5\n"
		"wmadds       wr6, wr6, wr3\n"
		"wmadds       wr7, wr7, wr3\n"
		"waddwss      wr4, wr6, wr4\n"
		"waddwss      wr5, wr7, wr5\n"
		"\n"
		"wstrd        wr4, [%3]\n"
		"wstrd        wr5, [%3, #8]\n"
		"\n"
		"wldrd        wr6, [%1, #176]\n"
		"wldrd        wr5, [%1, #184]\n"
		"wmadds       wr5, wr5, wr0\n"
		"wldrd        wr8, [%1, #208]\n"
		"wmadds       wr0, wr6, wr0\n"
		"wldrd        wr9, [%1, #216]\n"
		"wmadds       wr9, wr9, wr1\n"
		"wldrd        wr6, [%1, #240]\n"
		"wmadds       wr1, wr8, wr1\n"
		"wldrd        wr7, [%1, #248]\n"
		"waddwss      wr0, wr1, wr0\n"
		"waddwss      wr5, wr9, wr5\n"
		"wmadds       wr7, wr7, wr2\n"
		"wldrd        wr8, [%1, #272]\n"
		"wmadds       wr2, wr6, wr2\n"
		"wldrd        wr9, [%1, #280]\n"
		"waddwss      wr0, wr2, wr0\n"
		"waddwss      wr5, wr7, wr5\n"
		"wmadds       wr9, wr9, wr3\n"
		"wmadds       wr3, wr8, wr3\n"
		"waddwss      wr0, wr3, wr0\n"
		"waddwss      wr5, wr9, wr5\n"
		"\n"
		"wstrd        wr0, [%3, #16]\n"
		"wstrd        wr5, [%3, #24]\n"
		:
		: "r" (in), "r" (consts),
			"r" (1 << (SBC_PROTO_FIXED8_SCALE - 1)), "r" (out),
			"r" (SBC_PROTO_FIXED8_SCALE)
		: "wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
		  "wr8", "wr9", "wr10", "wr11", "wr12", "wr13", "wr14", "wr15",
		  "wcgr0", "memory");
}

static inline void sbc_analyze_4b_4s_iwmmxt(int16_t *x, int32_t *out,
						int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_four_iwmmxt(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_iwmmxt(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	sbc_analyze_four_iwmmxt(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_iwmmxt(x + 0, out, analysis_consts_fixed4_simd_even);
}

static inline void sbc_analyze_4b_8s_iwmmxt(int16_t *x, int32_t *out,
						int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_eight_iwmmxt(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_iwmmxt(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	sbc_analyze_eight_iwmmxt(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_iwmmxt(x + 0, out, analysis_consts_fixed8_simd_even);
}

void sbc_init_primitives_iwmmxt(struct sbc_encoder_state *state)
{
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_iwmmxt;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_iwmmxt;
	state->implementation_info = "IWMMXT";
}

#endif
