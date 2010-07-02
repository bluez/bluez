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

#include "sbc_primitives_armv6.h"

/*
 * ARMv6 optimizations. The instructions are scheduled for ARM11 pipeline.
 */

#ifdef SBC_BUILD_WITH_ARMV6_SUPPORT

static void __attribute__((naked)) sbc_analyze_four_armv6()
{
	/* r0 = in, r1 = out, r2 = consts */
	asm volatile (
		"push   {r1, r4-r7, lr}\n"
		"push   {r8-r11}\n"
		"ldrd   r4,  r5,  [r0, #0]\n"
		"ldrd   r6,  r7,  [r2, #0]\n"
		"ldrd   r8,  r9,  [r0, #16]\n"
		"ldrd   r10, r11, [r2, #16]\n"
		"mov    r14, #0x8000\n"
		"smlad  r3,  r4,  r6,  r14\n"
		"smlad  r12, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r0, #32]\n"
		"ldrd   r6,  r7,  [r2, #32]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #48]\n"
		"ldrd   r10, r11, [r2, #48]\n"
		"smlad  r3,  r4,  r6,  r3\n"
		"smlad  r12, r5,  r7,  r12\n"
		"ldrd   r4,  r5,  [r0, #64]\n"
		"ldrd   r6,  r7,  [r2, #64]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #8]\n"
		"ldrd   r10, r11, [r2, #8]\n"
		"smlad  r3,  r4,  r6,  r3\n"      /* t1[0] is done */
		"smlad  r12, r5,  r7,  r12\n"     /* t1[1] is done */
		"ldrd   r4,  r5,  [r0, #24]\n"
		"ldrd   r6,  r7,  [r2, #24]\n"
		"pkhtb  r3,  r12, r3, asr #16\n"  /* combine t1[0] and t1[1] */
		"smlad  r12, r8,  r10, r14\n"
		"smlad  r14, r9,  r11, r14\n"
		"ldrd   r8,  r9,  [r0, #40]\n"
		"ldrd   r10, r11, [r2, #40]\n"
		"smlad  r12, r4,  r6,  r12\n"
		"smlad  r14, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r0, #56]\n"
		"ldrd   r6,  r7,  [r2, #56]\n"
		"smlad  r12, r8,  r10, r12\n"
		"smlad  r14, r9,  r11, r14\n"
		"ldrd   r8,  r9,  [r0, #72]\n"
		"ldrd   r10, r11, [r2, #72]\n"
		"smlad  r12, r4,  r6,  r12\n"
		"smlad  r14, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r2, #80]\n"    /* start loading cos table */
		"smlad  r12, r8,  r10, r12\n"     /* t1[2] is done */
		"smlad  r14, r9,  r11, r14\n"     /* t1[3] is done */
		"ldrd   r6,  r7,  [r2, #88]\n"
		"ldrd   r8,  r9,  [r2, #96]\n"
		"ldrd   r10, r11, [r2, #104]\n"   /* cos table fully loaded */
		"pkhtb  r12, r14, r12, asr #16\n" /* combine t1[2] and t1[3] */
		"smuad  r4,  r3,  r4\n"
		"smuad  r5,  r3,  r5\n"
		"smlad  r4,  r12, r8,  r4\n"
		"smlad  r5,  r12, r9,  r5\n"
		"smuad  r6,  r3,  r6\n"
		"smuad  r7,  r3,  r7\n"
		"smlad  r6,  r12, r10, r6\n"
		"smlad  r7,  r12, r11, r7\n"
		"pop    {r8-r11}\n"
		"stmia  r1, {r4, r5, r6, r7}\n"
		"pop    {r1, r4-r7, pc}\n"
	);
}

#define sbc_analyze_four(in, out, consts) \
	((void (*)(int16_t *, int32_t *, const FIXED_T*)) \
		sbc_analyze_four_armv6)((in), (out), (consts))

static void __attribute__((naked)) sbc_analyze_eight_armv6()
{
	/* r0 = in, r1 = out, r2 = consts */
	asm volatile (
		"push   {r1, r4-r7, lr}\n"
		"push   {r8-r11}\n"
		"ldrd   r4,  r5,  [r0, #24]\n"
		"ldrd   r6,  r7,  [r2, #24]\n"
		"ldrd   r8,  r9,  [r0, #56]\n"
		"ldrd   r10, r11, [r2, #56]\n"
		"mov    r14, #0x8000\n"
		"smlad  r3,  r4,  r6,  r14\n"
		"smlad  r12, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r0, #88]\n"
		"ldrd   r6,  r7,  [r2, #88]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #120]\n"
		"ldrd   r10, r11, [r2, #120]\n"
		"smlad  r3,  r4,  r6,  r3\n"
		"smlad  r12, r5,  r7,  r12\n"
		"ldrd   r4,  r5,  [r0, #152]\n"
		"ldrd   r6,  r7,  [r2, #152]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #16]\n"
		"ldrd   r10, r11, [r2, #16]\n"
		"smlad  r3,  r4,  r6,  r3\n"      /* t1[6] is done */
		"smlad  r12, r5,  r7,  r12\n"     /* t1[7] is done */
		"ldrd   r4,  r5,  [r0, #48]\n"
		"ldrd   r6,  r7,  [r2, #48]\n"
		"pkhtb  r3,  r12, r3, asr #16\n"  /* combine t1[6] and t1[7] */
		"str    r3,  [sp, #-4]!\n"        /* save to stack */
		"smlad  r3,  r8,  r10, r14\n"
		"smlad  r12, r9,  r11, r14\n"
		"ldrd   r8,  r9,  [r0, #80]\n"
		"ldrd   r10, r11, [r2, #80]\n"
		"smlad  r3,  r4,  r6,  r3\n"
		"smlad  r12, r5,  r7,  r12\n"
		"ldrd   r4,  r5,  [r0, #112]\n"
		"ldrd   r6,  r7,  [r2, #112]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #144]\n"
		"ldrd   r10, r11, [r2, #144]\n"
		"smlad  r3,  r4,  r6,  r3\n"
		"smlad  r12, r5,  r7,  r12\n"
		"ldrd   r4,  r5,  [r0, #0]\n"
		"ldrd   r6,  r7,  [r2, #0]\n"
		"smlad  r3,  r8,  r10, r3\n"      /* t1[4] is done */
		"smlad  r12, r9,  r11, r12\n"     /* t1[5] is done */
		"ldrd   r8,  r9,  [r0, #32]\n"
		"ldrd   r10, r11, [r2, #32]\n"
		"pkhtb  r3,  r12, r3, asr #16\n"  /* combine t1[4] and t1[5] */
		"str    r3,  [sp, #-4]!\n"        /* save to stack */
		"smlad  r3,  r4,  r6,  r14\n"
		"smlad  r12, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r0, #64]\n"
		"ldrd   r6,  r7,  [r2, #64]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #96]\n"
		"ldrd   r10, r11, [r2, #96]\n"
		"smlad  r3,  r4,  r6,  r3\n"
		"smlad  r12, r5,  r7,  r12\n"
		"ldrd   r4,  r5,  [r0, #128]\n"
		"ldrd   r6,  r7,  [r2, #128]\n"
		"smlad  r3,  r8,  r10, r3\n"
		"smlad  r12, r9,  r11, r12\n"
		"ldrd   r8,  r9,  [r0, #8]\n"
		"ldrd   r10, r11, [r2, #8]\n"
		"smlad  r3,  r4,  r6,  r3\n"      /* t1[0] is done */
		"smlad  r12, r5,  r7,  r12\n"     /* t1[1] is done */
		"ldrd   r4,  r5,  [r0, #40]\n"
		"ldrd   r6,  r7,  [r2, #40]\n"
		"pkhtb  r3,  r12, r3, asr #16\n"  /* combine t1[0] and t1[1] */
		"smlad  r12, r8,  r10, r14\n"
		"smlad  r14, r9,  r11, r14\n"
		"ldrd   r8,  r9,  [r0, #72]\n"
		"ldrd   r10, r11, [r2, #72]\n"
		"smlad  r12, r4,  r6,  r12\n"
		"smlad  r14, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r0, #104]\n"
		"ldrd   r6,  r7,  [r2, #104]\n"
		"smlad  r12, r8,  r10, r12\n"
		"smlad  r14, r9,  r11, r14\n"
		"ldrd   r8,  r9,  [r0, #136]\n"
		"ldrd   r10, r11, [r2, #136]!\n"
		"smlad  r12, r4,  r6,  r12\n"
		"smlad  r14, r5,  r7,  r14\n"
		"ldrd   r4,  r5,  [r2, #(160 - 136 + 0)]\n"
		"smlad  r12, r8,  r10, r12\n"     /* t1[2] is done */
		"smlad  r14, r9,  r11, r14\n"     /* t1[3] is done */
		"ldrd   r6,  r7,  [r2, #(160 - 136 + 8)]\n"
		"smuad  r4,  r3,  r4\n"
		"smuad  r5,  r3,  r5\n"
		"pkhtb  r12, r14, r12, asr #16\n" /* combine t1[2] and t1[3] */
						  /* r3  = t2[0:1] */
						  /* r12 = t2[2:3] */
		"pop    {r0, r14}\n"              /* t2[4:5], t2[6:7] */
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 32)]\n"
		"smuad  r6,  r3,  r6\n"
		"smuad  r7,  r3,  r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 40)]\n"
		"smlad  r4,  r12, r8,  r4\n"
		"smlad  r5,  r12, r9,  r5\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 64)]\n"
		"smlad  r6,  r12, r10, r6\n"
		"smlad  r7,  r12, r11, r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 72)]\n"
		"smlad  r4,  r0,  r8,  r4\n"
		"smlad  r5,  r0,  r9,  r5\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 96)]\n"
		"smlad  r6,  r0,  r10, r6\n"
		"smlad  r7,  r0,  r11, r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 104)]\n"
		"smlad  r4,  r14, r8,  r4\n"
		"smlad  r5,  r14, r9,  r5\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 16 + 0)]\n"
		"smlad  r6,  r14, r10, r6\n"
		"smlad  r7,  r14, r11, r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 16 + 8)]\n"
		"stmia  r1!, {r4, r5}\n"
		"smuad  r4,  r3,  r8\n"
		"smuad  r5,  r3,  r9\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 16 + 32)]\n"
		"stmia  r1!, {r6, r7}\n"
		"smuad  r6,  r3,  r10\n"
		"smuad  r7,  r3,  r11\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 16 + 40)]\n"
		"smlad  r4,  r12, r8,  r4\n"
		"smlad  r5,  r12, r9,  r5\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 16 + 64)]\n"
		"smlad  r6,  r12, r10, r6\n"
		"smlad  r7,  r12, r11, r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 16 + 72)]\n"
		"smlad  r4,  r0,  r8,  r4\n"
		"smlad  r5,  r0,  r9,  r5\n"
		"ldrd   r8,  r9,  [r2, #(160 - 136 + 16 + 96)]\n"
		"smlad  r6,  r0,  r10, r6\n"
		"smlad  r7,  r0,  r11, r7\n"
		"ldrd   r10, r11, [r2, #(160 - 136 + 16 + 104)]\n"
		"smlad  r4,  r14, r8,  r4\n"
		"smlad  r5,  r14, r9,  r5\n"
		"smlad  r6,  r14, r10, r6\n"
		"smlad  r7,  r14, r11, r7\n"
		"pop    {r8-r11}\n"
		"stmia  r1!, {r4, r5, r6, r7}\n"
		"pop    {r1, r4-r7, pc}\n"
	);
}

#define sbc_analyze_eight(in, out, consts) \
	((void (*)(int16_t *, int32_t *, const FIXED_T*)) \
		sbc_analyze_eight_armv6)((in), (out), (consts))

static void sbc_analyze_4b_4s_armv6(int16_t *x, int32_t *out, int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_four(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	sbc_analyze_four(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four(x + 0, out, analysis_consts_fixed4_simd_even);
}

static void sbc_analyze_4b_8s_armv6(int16_t *x, int32_t *out, int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_eight(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	sbc_analyze_eight(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight(x + 0, out, analysis_consts_fixed8_simd_even);
}

void sbc_init_primitives_armv6(struct sbc_encoder_state *state)
{
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_armv6;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_armv6;
	state->implementation_info = "ARMv6 SIMD";
}

#endif
