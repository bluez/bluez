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

#include "sbc_primitives_mmx.h"

/*
 * MMX optimizations
 */

#ifdef SBC_BUILD_WITH_MMX_SUPPORT

static inline void sbc_analyze_four_mmx(const int16_t *in, int32_t *out,
					const FIXED_T *consts)
{
	static const SBC_ALIGNED int32_t round_c[2] = {
		1 << (SBC_PROTO_FIXED4_SCALE - 1),
		1 << (SBC_PROTO_FIXED4_SCALE - 1),
	};
	asm volatile (
		"movq        (%0), %%mm0\n"
		"movq       8(%0), %%mm1\n"
		"pmaddwd     (%1), %%mm0\n"
		"pmaddwd    8(%1), %%mm1\n"
		"paddd       (%2), %%mm0\n"
		"paddd       (%2), %%mm1\n"
		"\n"
		"movq      16(%0), %%mm2\n"
		"movq      24(%0), %%mm3\n"
		"pmaddwd   16(%1), %%mm2\n"
		"pmaddwd   24(%1), %%mm3\n"
		"paddd      %%mm2, %%mm0\n"
		"paddd      %%mm3, %%mm1\n"
		"\n"
		"movq      32(%0), %%mm2\n"
		"movq      40(%0), %%mm3\n"
		"pmaddwd   32(%1), %%mm2\n"
		"pmaddwd   40(%1), %%mm3\n"
		"paddd      %%mm2, %%mm0\n"
		"paddd      %%mm3, %%mm1\n"
		"\n"
		"movq      48(%0), %%mm2\n"
		"movq      56(%0), %%mm3\n"
		"pmaddwd   48(%1), %%mm2\n"
		"pmaddwd   56(%1), %%mm3\n"
		"paddd      %%mm2, %%mm0\n"
		"paddd      %%mm3, %%mm1\n"
		"\n"
		"movq      64(%0), %%mm2\n"
		"movq      72(%0), %%mm3\n"
		"pmaddwd   64(%1), %%mm2\n"
		"pmaddwd   72(%1), %%mm3\n"
		"paddd      %%mm2, %%mm0\n"
		"paddd      %%mm3, %%mm1\n"
		"\n"
		"psrad         %4, %%mm0\n"
		"psrad         %4, %%mm1\n"
		"packssdw   %%mm0, %%mm0\n"
		"packssdw   %%mm1, %%mm1\n"
		"\n"
		"movq       %%mm0, %%mm2\n"
		"pmaddwd   80(%1), %%mm0\n"
		"pmaddwd   88(%1), %%mm2\n"
		"\n"
		"movq       %%mm1, %%mm3\n"
		"pmaddwd   96(%1), %%mm1\n"
		"pmaddwd  104(%1), %%mm3\n"
		"paddd      %%mm1, %%mm0\n"
		"paddd      %%mm3, %%mm2\n"
		"\n"
		"movq       %%mm0, (%3)\n"
		"movq       %%mm2, 8(%3)\n"
		:
		: "r" (in), "r" (consts), "r" (&round_c), "r" (out),
			"i" (SBC_PROTO_FIXED4_SCALE)
		: "memory");
}

static inline void sbc_analyze_eight_mmx(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	static const SBC_ALIGNED int32_t round_c[2] = {
		1 << (SBC_PROTO_FIXED8_SCALE - 1),
		1 << (SBC_PROTO_FIXED8_SCALE - 1),
	};
	asm volatile (
		"movq        (%0), %%mm0\n"
		"movq       8(%0), %%mm1\n"
		"movq      16(%0), %%mm2\n"
		"movq      24(%0), %%mm3\n"
		"pmaddwd     (%1), %%mm0\n"
		"pmaddwd    8(%1), %%mm1\n"
		"pmaddwd   16(%1), %%mm2\n"
		"pmaddwd   24(%1), %%mm3\n"
		"paddd       (%2), %%mm0\n"
		"paddd       (%2), %%mm1\n"
		"paddd       (%2), %%mm2\n"
		"paddd       (%2), %%mm3\n"
		"\n"
		"movq      32(%0), %%mm4\n"
		"movq      40(%0), %%mm5\n"
		"movq      48(%0), %%mm6\n"
		"movq      56(%0), %%mm7\n"
		"pmaddwd   32(%1), %%mm4\n"
		"pmaddwd   40(%1), %%mm5\n"
		"pmaddwd   48(%1), %%mm6\n"
		"pmaddwd   56(%1), %%mm7\n"
		"paddd      %%mm4, %%mm0\n"
		"paddd      %%mm5, %%mm1\n"
		"paddd      %%mm6, %%mm2\n"
		"paddd      %%mm7, %%mm3\n"
		"\n"
		"movq      64(%0), %%mm4\n"
		"movq      72(%0), %%mm5\n"
		"movq      80(%0), %%mm6\n"
		"movq      88(%0), %%mm7\n"
		"pmaddwd   64(%1), %%mm4\n"
		"pmaddwd   72(%1), %%mm5\n"
		"pmaddwd   80(%1), %%mm6\n"
		"pmaddwd   88(%1), %%mm7\n"
		"paddd      %%mm4, %%mm0\n"
		"paddd      %%mm5, %%mm1\n"
		"paddd      %%mm6, %%mm2\n"
		"paddd      %%mm7, %%mm3\n"
		"\n"
		"movq      96(%0), %%mm4\n"
		"movq     104(%0), %%mm5\n"
		"movq     112(%0), %%mm6\n"
		"movq     120(%0), %%mm7\n"
		"pmaddwd   96(%1), %%mm4\n"
		"pmaddwd  104(%1), %%mm5\n"
		"pmaddwd  112(%1), %%mm6\n"
		"pmaddwd  120(%1), %%mm7\n"
		"paddd      %%mm4, %%mm0\n"
		"paddd      %%mm5, %%mm1\n"
		"paddd      %%mm6, %%mm2\n"
		"paddd      %%mm7, %%mm3\n"
		"\n"
		"movq     128(%0), %%mm4\n"
		"movq     136(%0), %%mm5\n"
		"movq     144(%0), %%mm6\n"
		"movq     152(%0), %%mm7\n"
		"pmaddwd  128(%1), %%mm4\n"
		"pmaddwd  136(%1), %%mm5\n"
		"pmaddwd  144(%1), %%mm6\n"
		"pmaddwd  152(%1), %%mm7\n"
		"paddd      %%mm4, %%mm0\n"
		"paddd      %%mm5, %%mm1\n"
		"paddd      %%mm6, %%mm2\n"
		"paddd      %%mm7, %%mm3\n"
		"\n"
		"psrad         %4, %%mm0\n"
		"psrad         %4, %%mm1\n"
		"psrad         %4, %%mm2\n"
		"psrad         %4, %%mm3\n"
		"\n"
		"packssdw   %%mm0, %%mm0\n"
		"packssdw   %%mm1, %%mm1\n"
		"packssdw   %%mm2, %%mm2\n"
		"packssdw   %%mm3, %%mm3\n"
		"\n"
		"movq       %%mm0, %%mm4\n"
		"movq       %%mm0, %%mm5\n"
		"pmaddwd  160(%1), %%mm4\n"
		"pmaddwd  168(%1), %%mm5\n"
		"\n"
		"movq       %%mm1, %%mm6\n"
		"movq       %%mm1, %%mm7\n"
		"pmaddwd  192(%1), %%mm6\n"
		"pmaddwd  200(%1), %%mm7\n"
		"paddd      %%mm6, %%mm4\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm2, %%mm6\n"
		"movq       %%mm2, %%mm7\n"
		"pmaddwd  224(%1), %%mm6\n"
		"pmaddwd  232(%1), %%mm7\n"
		"paddd      %%mm6, %%mm4\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm3, %%mm6\n"
		"movq       %%mm3, %%mm7\n"
		"pmaddwd  256(%1), %%mm6\n"
		"pmaddwd  264(%1), %%mm7\n"
		"paddd      %%mm6, %%mm4\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm4, (%3)\n"
		"movq       %%mm5, 8(%3)\n"
		"\n"
		"movq       %%mm0, %%mm5\n"
		"pmaddwd  176(%1), %%mm0\n"
		"pmaddwd  184(%1), %%mm5\n"
		"\n"
		"movq       %%mm1, %%mm7\n"
		"pmaddwd  208(%1), %%mm1\n"
		"pmaddwd  216(%1), %%mm7\n"
		"paddd      %%mm1, %%mm0\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm2, %%mm7\n"
		"pmaddwd  240(%1), %%mm2\n"
		"pmaddwd  248(%1), %%mm7\n"
		"paddd      %%mm2, %%mm0\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm3, %%mm7\n"
		"pmaddwd  272(%1), %%mm3\n"
		"pmaddwd  280(%1), %%mm7\n"
		"paddd      %%mm3, %%mm0\n"
		"paddd      %%mm7, %%mm5\n"
		"\n"
		"movq       %%mm0, 16(%3)\n"
		"movq       %%mm5, 24(%3)\n"
		:
		: "r" (in), "r" (consts), "r" (&round_c), "r" (out),
			"i" (SBC_PROTO_FIXED8_SCALE)
		: "memory");
}

static inline void sbc_analyze_4b_4s_mmx(int16_t *x, int32_t *out,
						int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_four_mmx(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_mmx(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	sbc_analyze_four_mmx(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_mmx(x + 0, out, analysis_consts_fixed4_simd_even);

	asm volatile ("emms\n");
}

static inline void sbc_analyze_4b_8s_mmx(int16_t *x, int32_t *out,
						int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_eight_mmx(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_mmx(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	sbc_analyze_eight_mmx(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_mmx(x + 0, out, analysis_consts_fixed8_simd_even);

	asm volatile ("emms\n");
}

static void sbc_calc_scalefactors_mmx(
	int32_t sb_sample_f[16][2][8],
	uint32_t scale_factor[2][8],
	int blocks, int channels, int subbands)
{
	static const SBC_ALIGNED int32_t consts[2] = {
		1 << SCALE_OUT_BITS,
		1 << SCALE_OUT_BITS,
	};
	int ch, sb;
	intptr_t blk;
	for (ch = 0; ch < channels; ch++) {
		for (sb = 0; sb < subbands; sb += 2) {
			blk = (blocks - 1) * (((char *) &sb_sample_f[1][0][0] -
				(char *) &sb_sample_f[0][0][0]));
			asm volatile (
				"movq         (%4), %%mm0\n"
			"1:\n"
				"movq     (%1, %0), %%mm1\n"
				"pxor        %%mm2, %%mm2\n"
				"pcmpgtd     %%mm2, %%mm1\n"
				"paddd    (%1, %0), %%mm1\n"
				"pcmpgtd     %%mm1, %%mm2\n"
				"pxor        %%mm2, %%mm1\n"

				"por         %%mm1, %%mm0\n"

				"sub            %2, %0\n"
				"jns            1b\n"

				"movd        %%mm0, %k0\n"
				"psrlq         $32, %%mm0\n"
				"bsrl          %k0, %k0\n"
				"subl           %5, %k0\n"
				"movl          %k0, (%3)\n"

				"movd        %%mm0, %k0\n"
				"bsrl          %k0, %k0\n"
				"subl           %5, %k0\n"
				"movl          %k0, 4(%3)\n"
			: "+r" (blk)
			: "r" (&sb_sample_f[0][ch][sb]),
				"i" ((char *) &sb_sample_f[1][0][0] -
					(char *) &sb_sample_f[0][0][0]),
				"r" (&scale_factor[ch][sb]),
				"r" (&consts),
				"i" (SCALE_OUT_BITS)
			: "memory");
		}
	}
	asm volatile ("emms\n");
}

static int check_mmx_support(void)
{
#ifdef __amd64__
	return 1; /* We assume that all 64-bit processors have MMX support */
#else
	int cpuid_feature_information;
	asm volatile (
		/* According to Intel manual, CPUID instruction is supported
		 * if the value of ID bit (bit 21) in EFLAGS can be modified */
		"pushf\n"
		"movl     (%%esp),   %0\n"
		"xorl     $0x200000, (%%esp)\n" /* try to modify ID bit */
		"popf\n"
		"pushf\n"
		"xorl     (%%esp),   %0\n"      /* check if ID bit changed */
		"jz       1f\n"
		"push     %%eax\n"
		"push     %%ebx\n"
		"push     %%ecx\n"
		"mov      $1,        %%eax\n"
		"cpuid\n"
		"pop      %%ecx\n"
		"pop      %%ebx\n"
		"pop      %%eax\n"
		"1:\n"
		"popf\n"
		: "=d" (cpuid_feature_information)
		:
		: "cc");
    return cpuid_feature_information & (1 << 23);
#endif
}

void sbc_init_primitives_mmx(struct sbc_encoder_state *state)
{
	if (check_mmx_support()) {
		state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_mmx;
		state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_mmx;
		state->sbc_calc_scalefactors = sbc_calc_scalefactors_mmx;
		state->implementation_info = "MMX";
	}
}

#endif
