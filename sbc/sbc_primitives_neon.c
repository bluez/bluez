/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
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

#include "sbc_primitives_neon.h"

/*
 * ARM NEON optimizations
 */

#ifdef SBC_BUILD_WITH_NEON_SUPPORT

static inline void _sbc_analyze_four_neon(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	/* TODO: merge even and odd cases (or even merge all four calls to this
	 * function) in order to have only aligned reads from 'in' array
	 * and reduce number of load instructions */
	asm volatile (
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmull.s16  q0, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmull.s16  q1, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"

		"vmlal.s16  q0, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmlal.s16  q1, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q0, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmlal.s16  q1, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"

		"vmlal.s16  q0, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmlal.s16  q1, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q0, d4, d8\n"
		"vmlal.s16  q1, d5, d9\n"

		"vpadd.s32  d0, d0, d1\n"
		"vpadd.s32  d1, d2, d3\n"

		"vrshrn.s32 d0, q0, %3\n"

		"vld1.16    {d2, d3, d4, d5}, [%1, :128]!\n"

		"vdup.i32   d1, d0[1]\n"  /* TODO: can be eliminated */
		"vdup.i32   d0, d0[0]\n"  /* TODO: can be eliminated */

		"vmull.s16  q3, d2, d0\n"
		"vmull.s16  q4, d3, d0\n"
		"vmlal.s16  q3, d4, d1\n"
		"vmlal.s16  q4, d5, d1\n"

		"vpadd.s32  d0, d6, d7\n" /* TODO: can be eliminated */
		"vpadd.s32  d1, d8, d9\n" /* TODO: can be eliminated */

		"vst1.32    {d0, d1}, [%2, :128]\n"
		: "+r" (in), "+r" (consts)
		: "r" (out),
			"i" (SBC_PROTO_FIXED4_SCALE)
		: "memory",
			"d0", "d1", "d2", "d3", "d4", "d5",
			"d6", "d7", "d8", "d9", "d10", "d11");
}

static inline void _sbc_analyze_eight_neon(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	/* TODO: merge even and odd cases (or even merge all four calls to this
	 * function) in order to have only aligned reads from 'in' array
	 * and reduce number of load instructions */
	asm volatile (
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmull.s16  q6, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmull.s16  q7, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"
		"vmull.s16  q8, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmull.s16  q9, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q6, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmlal.s16  q7, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"
		"vmlal.s16  q8, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmlal.s16  q9, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q6, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmlal.s16  q7, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"
		"vmlal.s16  q8, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmlal.s16  q9, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q6, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmlal.s16  q7, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"
		"vmlal.s16  q8, d6, d10\n"
		"vld1.16    {d4, d5}, [%0, :64]!\n"
		"vmlal.s16  q9, d7, d11\n"
		"vld1.16    {d8, d9}, [%1, :128]!\n"

		"vmlal.s16  q6, d4, d8\n"
		"vld1.16    {d6,  d7}, [%0, :64]!\n"
		"vmlal.s16  q7, d5, d9\n"
		"vld1.16    {d10, d11}, [%1, :128]!\n"

		"vmlal.s16  q8, d6, d10\n"
		"vmlal.s16  q9, d7, d11\n"

		"vpadd.s32  d0, d12, d13\n"
		"vpadd.s32  d1, d14, d15\n"
		"vpadd.s32  d2, d16, d17\n"
		"vpadd.s32  d3, d18, d19\n"

		"vrshr.s32 q0, q0, %3\n"
		"vrshr.s32 q1, q1, %3\n"
		"vmovn.s32 d0, q0\n"
		"vmovn.s32 d1, q1\n"

		"vdup.i32   d3, d1[1]\n"  /* TODO: can be eliminated */
		"vdup.i32   d2, d1[0]\n"  /* TODO: can be eliminated */
		"vdup.i32   d1, d0[1]\n"  /* TODO: can be eliminated */
		"vdup.i32   d0, d0[0]\n"  /* TODO: can be eliminated */

		"vld1.16    {d4, d5}, [%1, :128]!\n"
		"vmull.s16  q6, d4, d0\n"
		"vld1.16    {d6, d7}, [%1, :128]!\n"
		"vmull.s16  q7, d5, d0\n"
		"vmull.s16  q8, d6, d0\n"
		"vmull.s16  q9, d7, d0\n"

		"vld1.16    {d4, d5}, [%1, :128]!\n"
		"vmlal.s16  q6, d4, d1\n"
		"vld1.16    {d6, d7}, [%1, :128]!\n"
		"vmlal.s16  q7, d5, d1\n"
		"vmlal.s16  q8, d6, d1\n"
		"vmlal.s16  q9, d7, d1\n"

		"vld1.16    {d4, d5}, [%1, :128]!\n"
		"vmlal.s16  q6, d4, d2\n"
		"vld1.16    {d6, d7}, [%1, :128]!\n"
		"vmlal.s16  q7, d5, d2\n"
		"vmlal.s16  q8, d6, d2\n"
		"vmlal.s16  q9, d7, d2\n"

		"vld1.16    {d4, d5}, [%1, :128]!\n"
		"vmlal.s16  q6, d4, d3\n"
		"vld1.16    {d6, d7}, [%1, :128]!\n"
		"vmlal.s16  q7, d5, d3\n"
		"vmlal.s16  q8, d6, d3\n"
		"vmlal.s16  q9, d7, d3\n"

		"vpadd.s32  d0, d12, d13\n" /* TODO: can be eliminated */
		"vpadd.s32  d1, d14, d15\n" /* TODO: can be eliminated */
		"vpadd.s32  d2, d16, d17\n" /* TODO: can be eliminated */
		"vpadd.s32  d3, d18, d19\n" /* TODO: can be eliminated */

		"vst1.32    {d0, d1, d2, d3}, [%2, :128]\n"
		: "+r" (in), "+r" (consts)
		: "r" (out),
			"i" (SBC_PROTO_FIXED8_SCALE)
		: "memory",
			"d0", "d1", "d2", "d3", "d4", "d5",
			"d6", "d7", "d8", "d9", "d10", "d11",
			"d12", "d13", "d14", "d15", "d16", "d17",
			"d18", "d19");
}

static inline void sbc_analyze_4b_4s_neon(int16_t *x,
						int32_t *out, int out_stride)
{
	/* Analyze blocks */
	_sbc_analyze_four_neon(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	_sbc_analyze_four_neon(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	_sbc_analyze_four_neon(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	_sbc_analyze_four_neon(x + 0, out, analysis_consts_fixed4_simd_even);
}

static inline void sbc_analyze_4b_8s_neon(int16_t *x,
						int32_t *out, int out_stride)
{
	/* Analyze blocks */
	_sbc_analyze_eight_neon(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	_sbc_analyze_eight_neon(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	_sbc_analyze_eight_neon(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	_sbc_analyze_eight_neon(x + 0, out, analysis_consts_fixed8_simd_even);
}

static void sbc_calc_scalefactors_neon(
	int32_t sb_sample_f[16][2][8],
	uint32_t scale_factor[2][8],
	int blocks, int channels, int subbands)
{
	int ch, sb;
	for (ch = 0; ch < channels; ch++) {
		for (sb = 0; sb < subbands; sb += 4) {
			int blk = blocks;
			int32_t *in = &sb_sample_f[0][ch][sb];
			asm volatile (
				"vmov.s32  q0, %[c1]\n"
				"vmov.s32  q1, %[c1]\n"
			"1:\n"
				"vld1.32   {d16, d17}, [%[in], :128], %[inc]\n"
				"vabs.s32  q8,  q8\n"
				"vld1.32   {d18, d19}, [%[in], :128], %[inc]\n"
				"vabs.s32  q9,  q9\n"
				"vld1.32   {d20, d21}, [%[in], :128], %[inc]\n"
				"vabs.s32  q10, q10\n"
				"vld1.32   {d22, d23}, [%[in], :128], %[inc]\n"
				"vabs.s32  q11, q11\n"
				"vcgt.s32  q12, q8,  #0\n"
				"vcgt.s32  q13, q9,  #0\n"
				"vcgt.s32  q14, q10, #0\n"
				"vcgt.s32  q15, q11, #0\n"
				"vadd.s32  q8,  q8,  q12\n"
				"vadd.s32  q9,  q9,  q13\n"
				"vadd.s32  q10, q10, q14\n"
				"vadd.s32  q11, q11, q15\n"
				"vorr.s32  q0,  q0,  q8\n"
				"vorr.s32  q1,  q1,  q9\n"
				"vorr.s32  q0,  q0,  q10\n"
				"vorr.s32  q1,  q1,  q11\n"
				"subs      %[blk], %[blk], #4\n"
				"bgt       1b\n"
				"vorr.s32  q0,  q0, q1\n"
				"vmov.s32  q15, %[c2]\n"
				"vclz.s32  q0,  q0\n"
				"vsub.s32  q0,  q15, q0\n"
				"vst1.32   {d0, d1}, [%[out], :128]\n"
			:
			  [blk]    "+r" (blk),
			  [in]     "+r" (in)
			:
			  [inc]     "r" ((char *) &sb_sample_f[1][0][0] -
					 (char *) &sb_sample_f[0][0][0]),
			  [out]     "r" (&scale_factor[ch][sb]),
			  [c1]      "i" (1 << SCALE_OUT_BITS),
			  [c2]      "i" (31 - SCALE_OUT_BITS)
			: "d0", "d1", "d2", "d3", "d16", "d17", "d18", "d19",
			  "d20", "d21", "d22", "d23", "d24", "d25", "d26",
			  "d27", "d28", "d29", "d30", "d31", "cc", "memory");
		}
	}
}

void sbc_init_primitives_neon(struct sbc_encoder_state *state)
{
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_neon;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_neon;
	state->sbc_calc_scalefactors = sbc_calc_scalefactors_neon;
	state->implementation_info = "NEON";
}

#endif
