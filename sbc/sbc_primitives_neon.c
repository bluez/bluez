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
				"vmov.s32  q0, #0\n"
				"vmov.s32  q1, %[c1]\n"
				"vmov.s32  q14, #1\n"
				"vmov.s32  q15, %[c2]\n"
				"vadd.s32  q1, q1, q14\n"
			"1:\n"
				"vld1.32   {d16, d17}, [%[in], :128], %[inc]\n"
				"vabs.s32  q8,  q8\n"
				"vld1.32   {d18, d19}, [%[in], :128], %[inc]\n"
				"vabs.s32  q9,  q9\n"
				"vld1.32   {d20, d21}, [%[in], :128], %[inc]\n"
				"vabs.s32  q10, q10\n"
				"vld1.32   {d22, d23}, [%[in], :128], %[inc]\n"
				"vabs.s32  q11, q11\n"
				"vmax.s32  q0,  q0,  q8\n"
				"vmax.s32  q1,  q1,  q9\n"
				"vmax.s32  q0,  q0,  q10\n"
				"vmax.s32  q1,  q1,  q11\n"
				"subs      %[blk], %[blk], #4\n"
				"bgt       1b\n"
				"vmax.s32  q0,  q0,  q1\n"
				"vsub.s32  q0,  q0,  q14\n"
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

int sbc_calc_scalefactors_j_neon(
	int32_t sb_sample_f[16][2][8],
	uint32_t scale_factor[2][8],
	int blocks, int subbands)
{
	static SBC_ALIGNED int32_t joint_bits_mask[8] = {
		8,   4,  2,  1, 128, 64, 32, 16
	};
	int joint, i;
	int32_t  *in0, *in1;
	int32_t  *in = &sb_sample_f[0][0][0];
	uint32_t *out0, *out1;
	uint32_t *out = &scale_factor[0][0];
	int32_t  *consts = joint_bits_mask;

	i = subbands;

	asm volatile (
		/*
		 * constants: q13 = (31 - SCALE_OUT_BITS), q14 = 1
		 * input:     q0  = ((1 << SCALE_OUT_BITS) + 1)
		 *            %[in0] - samples for channel 0
		 *            %[in1] - samples for shannel 1
		 * output:    q0, q1 - scale factors without joint stereo
		 *            q2, q3 - scale factors with joint stereo
		 *            q15    - joint stereo selection mask
		 */
		".macro calc_scalefactors\n"
			"vmov.s32  q1, q0\n"
			"vmov.s32  q2, q0\n"
			"vmov.s32  q3, q0\n"
			"mov       %[i], %[blocks]\n"
		"1:\n"
			"vld1.32   {d18, d19}, [%[in1], :128], %[inc]\n"
			"vbic.s32  q11, q9,  q14\n"
			"vld1.32   {d16, d17}, [%[in0], :128], %[inc]\n"
			"vhadd.s32 q10, q8,  q11\n"
			"vhsub.s32 q11, q8,  q11\n"
			"vabs.s32  q8,  q8\n"
			"vabs.s32  q9,  q9\n"
			"vabs.s32  q10, q10\n"
			"vabs.s32  q11, q11\n"
			"vmax.s32  q0,  q0,  q8\n"
			"vmax.s32  q1,  q1,  q9\n"
			"vmax.s32  q2,  q2,  q10\n"
			"vmax.s32  q3,  q3,  q11\n"
			"subs      %[i], %[i], #1\n"
			"bgt       1b\n"
			"vsub.s32  q0,  q0,  q14\n"
			"vsub.s32  q1,  q1,  q14\n"
			"vsub.s32  q2,  q2,  q14\n"
			"vsub.s32  q3,  q3,  q14\n"
			"vclz.s32  q0,  q0\n"
			"vclz.s32  q1,  q1\n"
			"vclz.s32  q2,  q2\n"
			"vclz.s32  q3,  q3\n"
			"vsub.s32  q0,  q13, q0\n"
			"vsub.s32  q1,  q13, q1\n"
			"vsub.s32  q2,  q13, q2\n"
			"vsub.s32  q3,  q13, q3\n"
		".endm\n"
		/*
		 * constants: q14 = 1
		 * input: q15    - joint stereo selection mask
		 *        %[in0] - value set by calc_scalefactors macro
		 *        %[in1] - value set by calc_scalefactors macro
		 */
		".macro update_joint_stereo_samples\n"
			"sub       %[out1], %[in1], %[inc]\n"
			"sub       %[out0], %[in0], %[inc]\n"
			"sub       %[in1], %[in1], %[inc], asl #1\n"
			"sub       %[in0], %[in0], %[inc], asl #1\n"
			"vld1.32   {d18, d19}, [%[in1], :128]\n"
			"vbic.s32  q11, q9,  q14\n"
			"vld1.32   {d16, d17}, [%[in0], :128]\n"
			"vld1.32   {d2, d3}, [%[out1], :128]\n"
			"vbic.s32  q3,  q1,  q14\n"
			"vld1.32   {d0, d1}, [%[out0], :128]\n"
			"vhsub.s32 q10, q8,  q11\n"
			"vhadd.s32 q11, q8,  q11\n"
			"vhsub.s32 q2,  q0,  q3\n"
			"vhadd.s32 q3,  q0,  q3\n"
			"vbif.s32  q10, q9,  q15\n"
			"vbif.s32  d22, d16, d30\n"
			"sub       %[inc], %[zero], %[inc], asl #1\n"
			"sub       %[i], %[blocks], #2\n"
		"2:\n"
			"vbif.s32  d23, d17, d31\n"
			"vst1.32   {d20, d21}, [%[in1], :128], %[inc]\n"
			"vbif.s32  d4,  d2,  d30\n"
			"vld1.32   {d18, d19}, [%[in1], :128]\n"
			"vbif.s32  d5,  d3,  d31\n"
			"vst1.32   {d22, d23}, [%[in0], :128], %[inc]\n"
			"vbif.s32  d6,  d0,  d30\n"
			"vld1.32   {d16, d17}, [%[in0], :128]\n"
			"vbif.s32  d7,  d1,  d31\n"
			"vst1.32   {d4, d5}, [%[out1], :128], %[inc]\n"
			"vbic.s32  q11, q9,  q14\n"
			"vld1.32   {d2, d3}, [%[out1], :128]\n"
			"vst1.32   {d6, d7}, [%[out0], :128], %[inc]\n"
			"vbic.s32  q3,  q1,  q14\n"
			"vld1.32   {d0, d1}, [%[out0], :128]\n"
			"vhsub.s32 q10, q8,  q11\n"
			"vhadd.s32 q11, q8,  q11\n"
			"vhsub.s32 q2,  q0,  q3\n"
			"vhadd.s32 q3,  q0,  q3\n"
			"vbif.s32  q10, q9,  q15\n"
			"vbif.s32  d22, d16, d30\n"
			"subs      %[i], %[i], #2\n"
			"bgt       2b\n"
			"sub       %[inc], %[zero], %[inc], asr #1\n"
			"vbif.s32  d23, d17, d31\n"
			"vst1.32   {d20, d21}, [%[in1], :128]\n"
			"vbif.s32  q2,  q1,  q15\n"
			"vst1.32   {d22, d23}, [%[in0], :128]\n"
			"vbif.s32  q3,  q0,  q15\n"
			"vst1.32   {d4, d5}, [%[out1], :128]\n"
			"vst1.32   {d6, d7}, [%[out0], :128]\n"
		".endm\n"

		"vmov.s32  q14, #1\n"
		"vmov.s32  q13, %[c2]\n"

		"cmp   %[i], #4\n"
		"bne   8f\n"

	"4:\n" /* 4 subbands */
		"add   %[in0], %[in], #0\n"
		"add   %[in1], %[in], #32\n"
		"add   %[out0], %[out], #0\n"
		"add   %[out1], %[out], #32\n"
		"vmov.s32  q0, %[c1]\n"
		"vadd.s32  q0, q0, q14\n"

		"calc_scalefactors\n"

		/* check whether to use joint stereo for subbands 0, 1, 2 */
		"vadd.s32  q15, q0,  q1\n"
		"vadd.s32  q9,  q2,  q3\n"
		"vmov.s32  d31[1], %[zero]\n" /* last subband -> no joint */
		"vld1.32   {d16, d17}, [%[consts], :128]!\n"
		"vcgt.s32  q15, q15, q9\n"

		/* calculate and save to memory 'joint' variable */
		/* update and save scale factors to memory */
		"  vand.s32  q8, q8, q15\n"
		"vbit.s32  q0,  q2,  q15\n"
		"  vpadd.s32 d16, d16, d17\n"
		"vbit.s32  q1,  q3,  q15\n"
		"  vpadd.s32 d16, d16, d16\n"
		"vst1.32   {d0, d1}, [%[out0], :128]\n"
		"vst1.32   {d2, d3}, [%[out1], :128]\n"
		"  vst1.32   {d16[0]}, [%[joint]]\n"

		"update_joint_stereo_samples\n"
		"b     9f\n"

	"8:\n" /* 8 subbands */
		"add   %[in0], %[in], #16\n\n"
		"add   %[in1], %[in], #48\n"
		"add   %[out0], %[out], #16\n\n"
		"add   %[out1], %[out], #48\n"
		"vmov.s32  q0, %[c1]\n"
		"vadd.s32  q0, q0, q14\n"

		"calc_scalefactors\n"

		/* check whether to use joint stereo for subbands 4, 5, 6 */
		"vadd.s32  q15, q0,  q1\n"
		"vadd.s32  q9,  q2,  q3\n"
		"vmov.s32  d31[1], %[zero]\n"  /* last subband -> no joint */
		"vld1.32   {d16, d17}, [%[consts], :128]!\n"
		"vcgt.s32  q15, q15, q9\n"

		/* calculate part of 'joint' variable and save it to d24 */
		/* update and save scale factors to memory */
		"  vand.s32  q8, q8, q15\n"
		"vbit.s32  q0,  q2,  q15\n"
		"  vpadd.s32 d16, d16, d17\n"
		"vbit.s32  q1,  q3,  q15\n"
		"vst1.32   {d0, d1}, [%[out0], :128]\n"
		"vst1.32   {d2, d3}, [%[out1], :128]\n"
		"  vpadd.s32 d24, d16, d16\n"

		"update_joint_stereo_samples\n"

		"add   %[in0], %[in], #0\n"
		"add   %[in1], %[in], #32\n"
		"add   %[out0], %[out], #0\n\n"
		"add   %[out1], %[out], #32\n"
		"vmov.s32  q0, %[c1]\n"
		"vadd.s32  q0, q0, q14\n"

		"calc_scalefactors\n"

		/* check whether to use joint stereo for subbands 0, 1, 2, 3 */
		"vadd.s32  q15, q0,  q1\n"
		"vadd.s32  q9,  q2,  q3\n"
		"vld1.32   {d16, d17}, [%[consts], :128]!\n"
		"vcgt.s32  q15, q15, q9\n"

		/* combine last part of 'joint' with d24 and save to memory */
		/* update and save scale factors to memory */
		"  vand.s32  q8, q8, q15\n"
		"vbit.s32  q0,  q2,  q15\n"
		"  vpadd.s32 d16, d16, d17\n"
		"vbit.s32  q1,  q3,  q15\n"
		"  vpadd.s32 d16, d16, d16\n"
		"vst1.32   {d0, d1}, [%[out0], :128]\n"
		"  vadd.s32  d16, d16, d24\n"
		"vst1.32   {d2, d3}, [%[out1], :128]\n"
		"  vst1.32   {d16[0]}, [%[joint]]\n"

		"update_joint_stereo_samples\n"
	"9:\n"
		".purgem calc_scalefactors\n"
		".purgem update_joint_stereo_samples\n"
		:
		  [i]      "+&r" (i),
		  [in]     "+&r" (in),
		  [in0]    "=&r" (in0),
		  [in1]    "=&r" (in1),
		  [out]    "+&r" (out),
		  [out0]   "=&r" (out0),
		  [out1]   "=&r" (out1),
		  [consts] "+&r" (consts)
		:
		  [inc]      "r" ((char *) &sb_sample_f[1][0][0] -
				 (char *) &sb_sample_f[0][0][0]),
		  [blocks]   "r" (blocks),
		  [joint]    "r" (&joint),
		  [c1]       "i" (1 << SCALE_OUT_BITS),
		  [c2]       "i" (31 - SCALE_OUT_BITS),
		  [zero]     "r" (0)
		: "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
		  "d16", "d17", "d18", "d19", "d20", "d21", "d22",
		  "d23", "d24", "d25", "d26", "d27", "d28", "d29",
		  "d30", "d31", "cc", "memory");

	return joint;
}

#define PERM_BE(a, b, c, d) {             \
		(a * 2) + 1, (a * 2) + 0, \
		(b * 2) + 1, (b * 2) + 0, \
		(c * 2) + 1, (c * 2) + 0, \
		(d * 2) + 1, (d * 2) + 0  \
	}
#define PERM_LE(a, b, c, d) {             \
		(a * 2) + 0, (a * 2) + 1, \
		(b * 2) + 0, (b * 2) + 1, \
		(c * 2) + 0, (c * 2) + 1, \
		(d * 2) + 0, (d * 2) + 1  \
	}

static SBC_ALWAYS_INLINE int sbc_enc_process_input_4s_neon_internal(
	int position,
	const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
	int nsamples, int nchannels, int big_endian)
{
	static SBC_ALIGNED uint8_t perm_be[2][8] = {
		PERM_BE(7, 3, 6, 4),
		PERM_BE(0, 2, 1, 5)
	};
	static SBC_ALIGNED uint8_t perm_le[2][8] = {
		PERM_LE(7, 3, 6, 4),
		PERM_LE(0, 2, 1, 5)
	};
	/* handle X buffer wraparound */
	if (position < nsamples) {
		int16_t *dst = &X[0][SBC_X_BUFFER_SIZE - 40];
		int16_t *src = &X[0][position];
		asm volatile (
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0}, [%[src], :64]!\n"
			"vst1.16 {d0}, [%[dst], :64]!\n"
			:
			  [dst] "+r" (dst),
			  [src] "+r" (src)
			: : "memory", "d0", "d1", "d2", "d3");
		if (nchannels > 1) {
			dst = &X[1][SBC_X_BUFFER_SIZE - 40];
			src = &X[1][position];
			asm volatile (
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0}, [%[src], :64]!\n"
				"vst1.16 {d0}, [%[dst], :64]!\n"
				:
				  [dst] "+r" (dst),
				  [src] "+r" (src)
				: : "memory", "d0", "d1", "d2", "d3");
		}
		position = SBC_X_BUFFER_SIZE - 40;
	}

	if ((nchannels > 1) && ((uintptr_t)pcm & 1)) {
		/* poor 'pcm' alignment */
		int16_t *x = &X[0][position];
		int16_t *y = &X[1][position];
		asm volatile (
			"vld1.8  {d0, d1}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #16\n"
			"sub     %[y], %[y], #16\n"
			"sub     %[position], %[position], #8\n"
			"vld1.8  {d4, d5}, [%[pcm]]!\n"
			"vuzp.16 d4,  d5\n"
			"vld1.8  {d20, d21}, [%[pcm]]!\n"
			"vuzp.16 d20, d21\n"
			"vswp    d5,  d20\n"
			"vtbl.8  d16, {d4, d5}, d0\n"
			"vtbl.8  d17, {d4, d5}, d1\n"
			"vtbl.8  d18, {d20, d21}, d0\n"
			"vtbl.8  d19, {d20, d21}, d1\n"
			"vst1.16 {d16, d17}, [%[x], :128]\n"
			"vst1.16 {d18, d19}, [%[y], :128]\n"
			"subs    %[nsamples], %[nsamples], #8\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [y]        "+r" (y),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19",
			  "d20", "d21", "d22", "d23");
	} else if (nchannels > 1) {
		/* proper 'pcm' alignment */
		int16_t *x = &X[0][position];
		int16_t *y = &X[1][position];
		asm volatile (
			"vld1.8  {d0, d1}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #16\n"
			"sub     %[y], %[y], #16\n"
			"sub     %[position], %[position], #8\n"
			"vld2.16 {d4, d5}, [%[pcm]]!\n"
			"vld2.16 {d20, d21}, [%[pcm]]!\n"
			"vswp    d5, d20\n"
			"vtbl.8  d16, {d4, d5}, d0\n"
			"vtbl.8  d17, {d4, d5}, d1\n"
			"vtbl.8  d18, {d20, d21}, d0\n"
			"vtbl.8  d19, {d20, d21}, d1\n"
			"vst1.16 {d16, d17}, [%[x], :128]\n"
			"vst1.16 {d18, d19}, [%[y], :128]\n"
			"subs    %[nsamples], %[nsamples], #8\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [y]        "+r" (y),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19",
			  "d20", "d21", "d22", "d23");
	} else {
		int16_t *x = &X[0][position];
		asm volatile (
			"vld1.8  {d0, d1}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #16\n"
			"sub     %[position], %[position], #8\n"
			"vld1.8  {d4, d5}, [%[pcm]]!\n"
			"vtbl.8  d16, {d4, d5}, d0\n"
			"vtbl.8  d17, {d4, d5}, d1\n"
			"vst1.16 {d16, d17}, [%[x], :128]\n"
			"subs    %[nsamples], %[nsamples], #8\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19");
	}
	return position;
}

static SBC_ALWAYS_INLINE int sbc_enc_process_input_8s_neon_internal(
	int position,
	const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
	int nsamples, int nchannels, int big_endian)
{
	static SBC_ALIGNED uint8_t perm_be[4][8] = {
		PERM_BE(15, 7, 14, 8),
		PERM_BE(13, 9, 12, 10),
		PERM_BE(11, 3, 6,  0),
		PERM_BE(5,  1, 4,  2)
	};
	static SBC_ALIGNED uint8_t perm_le[4][8] = {
		PERM_LE(15, 7, 14, 8),
		PERM_LE(13, 9, 12, 10),
		PERM_LE(11, 3, 6,  0),
		PERM_LE(5,  1, 4,  2)
	};
	/* handle X buffer wraparound */
	if (position < nsamples) {
		int16_t *dst = &X[0][SBC_X_BUFFER_SIZE - 72];
		int16_t *src = &X[0][position];
		asm volatile (
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
			"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
			"vld1.16 {d0, d1}, [%[src], :128]!\n"
			"vst1.16 {d0, d1}, [%[dst], :128]!\n"
			:
			  [dst] "+r" (dst),
			  [src] "+r" (src)
			: : "memory", "d0", "d1", "d2", "d3");
		if (nchannels > 1) {
			dst = &X[1][SBC_X_BUFFER_SIZE - 72];
			src = &X[1][position];
			asm volatile (
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0, d1, d2, d3}, [%[src], :128]!\n"
				"vst1.16 {d0, d1, d2, d3}, [%[dst], :128]!\n"
				"vld1.16 {d0, d1}, [%[src], :128]!\n"
				"vst1.16 {d0, d1}, [%[dst], :128]!\n"
				:
				  [dst] "+r" (dst),
				  [src] "+r" (src)
				: : "memory", "d0", "d1", "d2", "d3");
		}
		position = SBC_X_BUFFER_SIZE - 72;
	}

	if ((nchannels > 1) && ((uintptr_t)pcm & 1)) {
		/* poor 'pcm' alignment */
		int16_t *x = &X[0][position];
		int16_t *y = &X[1][position];
		asm volatile (
			"vld1.8  {d0, d1, d2, d3}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #32\n"
			"sub     %[y], %[y], #32\n"
			"sub     %[position], %[position], #16\n"
			"vld1.8  {d4, d5, d6, d7}, [%[pcm]]!\n"
			"vuzp.16 q2,  q3\n"
			"vld1.8  {d20, d21, d22, d23}, [%[pcm]]!\n"
			"vuzp.16 q10, q11\n"
			"vswp    q3,  q10\n"
			"vtbl.8  d16, {d4, d5, d6, d7}, d0\n"
			"vtbl.8  d17, {d4, d5, d6, d7}, d1\n"
			"vtbl.8  d18, {d4, d5, d6, d7}, d2\n"
			"vtbl.8  d19, {d4, d5, d6, d7}, d3\n"
			"vst1.16 {d16, d17, d18, d19}, [%[x], :128]\n"
			"vtbl.8  d16, {d20, d21, d22, d23}, d0\n"
			"vtbl.8  d17, {d20, d21, d22, d23}, d1\n"
			"vtbl.8  d18, {d20, d21, d22, d23}, d2\n"
			"vtbl.8  d19, {d20, d21, d22, d23}, d3\n"
			"vst1.16 {d16, d17, d18, d19}, [%[y], :128]\n"
			"subs    %[nsamples], %[nsamples], #16\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [y]        "+r" (y),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19",
			  "d20", "d21", "d22", "d23");
	} else if (nchannels > 1) {
		/* proper 'pcm' alignment */
		int16_t *x = &X[0][position];
		int16_t *y = &X[1][position];
		asm volatile (
			"vld1.8  {d0, d1, d2, d3}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #32\n"
			"sub     %[y], %[y], #32\n"
			"sub     %[position], %[position], #16\n"
			"vld2.16  {d4, d5, d6, d7}, [%[pcm]]!\n"
			"vld2.16  {d20, d21, d22, d23}, [%[pcm]]!\n"
			"vswp    q3, q10\n"
			"vtbl.8  d16, {d4, d5, d6, d7}, d0\n"
			"vtbl.8  d17, {d4, d5, d6, d7}, d1\n"
			"vtbl.8  d18, {d4, d5, d6, d7}, d2\n"
			"vtbl.8  d19, {d4, d5, d6, d7}, d3\n"
			"vst1.16 {d16, d17, d18, d19}, [%[x], :128]\n"
			"vtbl.8  d16, {d20, d21, d22, d23}, d0\n"
			"vtbl.8  d17, {d20, d21, d22, d23}, d1\n"
			"vtbl.8  d18, {d20, d21, d22, d23}, d2\n"
			"vtbl.8  d19, {d20, d21, d22, d23}, d3\n"
			"vst1.16 {d16, d17, d18, d19}, [%[y], :128]\n"
			"subs    %[nsamples], %[nsamples], #16\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [y]        "+r" (y),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19",
			  "d20", "d21", "d22", "d23");
	} else {
		int16_t *x = &X[0][position];
		asm volatile (
			"vld1.8  {d0, d1, d2, d3}, [%[perm], :128]\n"
		"1:\n"
			"sub     %[x], %[x], #32\n"
			"sub     %[position], %[position], #16\n"
			"vld1.8  {d4, d5, d6, d7}, [%[pcm]]!\n"
			"vtbl.8  d16, {d4, d5, d6, d7}, d0\n"
			"vtbl.8  d17, {d4, d5, d6, d7}, d1\n"
			"vtbl.8  d18, {d4, d5, d6, d7}, d2\n"
			"vtbl.8  d19, {d4, d5, d6, d7}, d3\n"
			"vst1.16 {d16, d17, d18, d19}, [%[x], :128]\n"
			"subs    %[nsamples], %[nsamples], #16\n"
			"bgt     1b\n"
			:
			  [x]        "+r" (x),
			  [pcm]      "+r" (pcm),
			  [nsamples] "+r" (nsamples),
			  [position] "+r" (position)
			:
			  [perm]      "r" (big_endian ? perm_be : perm_le)
			: "cc", "memory", "d0", "d1", "d2", "d3", "d4",
			  "d5", "d6", "d7", "d16", "d17", "d18", "d19");
	}
	return position;
}

#undef PERM_BE
#undef PERM_LE

static int sbc_enc_process_input_4s_be_neon(int position, const uint8_t *pcm,
					int16_t X[2][SBC_X_BUFFER_SIZE],
					int nsamples, int nchannels)
{
	return sbc_enc_process_input_4s_neon_internal(
		position, pcm, X, nsamples, nchannels, 1);
}

static int sbc_enc_process_input_4s_le_neon(int position, const uint8_t *pcm,
					int16_t X[2][SBC_X_BUFFER_SIZE],
					int nsamples, int nchannels)
{
	return sbc_enc_process_input_4s_neon_internal(
		position, pcm, X, nsamples, nchannels, 0);
}

static int sbc_enc_process_input_8s_be_neon(int position, const uint8_t *pcm,
					int16_t X[2][SBC_X_BUFFER_SIZE],
					int nsamples, int nchannels)
{
	return sbc_enc_process_input_8s_neon_internal(
		position, pcm, X, nsamples, nchannels, 1);
}

static int sbc_enc_process_input_8s_le_neon(int position, const uint8_t *pcm,
					int16_t X[2][SBC_X_BUFFER_SIZE],
					int nsamples, int nchannels)
{
	return sbc_enc_process_input_8s_neon_internal(
		position, pcm, X, nsamples, nchannels, 0);
}

void sbc_init_primitives_neon(struct sbc_encoder_state *state)
{
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_neon;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_neon;
	state->sbc_calc_scalefactors = sbc_calc_scalefactors_neon;
	state->sbc_calc_scalefactors_j = sbc_calc_scalefactors_j_neon;
	state->sbc_enc_process_input_4s_le = sbc_enc_process_input_4s_le_neon;
	state->sbc_enc_process_input_4s_be = sbc_enc_process_input_4s_be_neon;
	state->sbc_enc_process_input_8s_le = sbc_enc_process_input_8s_le_neon;
	state->sbc_enc_process_input_8s_be = sbc_enc_process_input_8s_be_neon;
	state->implementation_info = "NEON";
}

#endif
