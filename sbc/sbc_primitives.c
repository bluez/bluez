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
#include <string.h>
#include "sbc.h"
#include "sbc_math.h"
#include "sbc_tables.h"

#include "sbc_primitives.h"
#include "sbc_primitives_mmx.h"
#include "sbc_primitives_iwmmxt.h"
#include "sbc_primitives_neon.h"
#include "sbc_primitives_armv6.h"

/*
 * A reference C code of analysis filter with SIMD-friendly tables
 * reordering and code layout. This code can be used to develop platform
 * specific SIMD optimizations. Also it may be used as some kind of test
 * for compiler autovectorization capabilities (who knows, if the compiler
 * is very good at this stuff, hand optimized assembly may be not strictly
 * needed for some platform).
 *
 * Note: It is also possible to make a simple variant of analysis filter,
 * which needs only a single constants table without taking care about
 * even/odd cases. This simple variant of filter can be implemented without
 * input data permutation. The only thing that would be lost is the
 * possibility to use pairwise SIMD multiplications. But for some simple
 * CPU cores without SIMD extensions it can be useful. If anybody is
 * interested in implementing such variant of a filter, sourcecode from
 * bluez versions 4.26/4.27 can be used as a reference and the history of
 * the changes in git repository done around that time may be worth checking.
 */

static inline void sbc_analyze_four_simd(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	FIXED_A t1[4];
	FIXED_T t2[4];
	int hop = 0;

	/* rounding coefficient */
	t1[0] = t1[1] = t1[2] = t1[3] =
		(FIXED_A) 1 << (SBC_PROTO_FIXED4_SCALE - 1);

	/* low pass polyphase filter */
	for (hop = 0; hop < 40; hop += 8) {
		t1[0] += (FIXED_A) in[hop] * consts[hop];
		t1[0] += (FIXED_A) in[hop + 1] * consts[hop + 1];
		t1[1] += (FIXED_A) in[hop + 2] * consts[hop + 2];
		t1[1] += (FIXED_A) in[hop + 3] * consts[hop + 3];
		t1[2] += (FIXED_A) in[hop + 4] * consts[hop + 4];
		t1[2] += (FIXED_A) in[hop + 5] * consts[hop + 5];
		t1[3] += (FIXED_A) in[hop + 6] * consts[hop + 6];
		t1[3] += (FIXED_A) in[hop + 7] * consts[hop + 7];
	}

	/* scaling */
	t2[0] = t1[0] >> SBC_PROTO_FIXED4_SCALE;
	t2[1] = t1[1] >> SBC_PROTO_FIXED4_SCALE;
	t2[2] = t1[2] >> SBC_PROTO_FIXED4_SCALE;
	t2[3] = t1[3] >> SBC_PROTO_FIXED4_SCALE;

	/* do the cos transform */
	t1[0]  = (FIXED_A) t2[0] * consts[40 + 0];
	t1[0] += (FIXED_A) t2[1] * consts[40 + 1];
	t1[1]  = (FIXED_A) t2[0] * consts[40 + 2];
	t1[1] += (FIXED_A) t2[1] * consts[40 + 3];
	t1[2]  = (FIXED_A) t2[0] * consts[40 + 4];
	t1[2] += (FIXED_A) t2[1] * consts[40 + 5];
	t1[3]  = (FIXED_A) t2[0] * consts[40 + 6];
	t1[3] += (FIXED_A) t2[1] * consts[40 + 7];

	t1[0] += (FIXED_A) t2[2] * consts[40 + 8];
	t1[0] += (FIXED_A) t2[3] * consts[40 + 9];
	t1[1] += (FIXED_A) t2[2] * consts[40 + 10];
	t1[1] += (FIXED_A) t2[3] * consts[40 + 11];
	t1[2] += (FIXED_A) t2[2] * consts[40 + 12];
	t1[2] += (FIXED_A) t2[3] * consts[40 + 13];
	t1[3] += (FIXED_A) t2[2] * consts[40 + 14];
	t1[3] += (FIXED_A) t2[3] * consts[40 + 15];

	out[0] = t1[0] >>
		(SBC_COS_TABLE_FIXED4_SCALE - SCALE_OUT_BITS);
	out[1] = t1[1] >>
		(SBC_COS_TABLE_FIXED4_SCALE - SCALE_OUT_BITS);
	out[2] = t1[2] >>
		(SBC_COS_TABLE_FIXED4_SCALE - SCALE_OUT_BITS);
	out[3] = t1[3] >>
		(SBC_COS_TABLE_FIXED4_SCALE - SCALE_OUT_BITS);
}

static inline void sbc_analyze_eight_simd(const int16_t *in, int32_t *out,
							const FIXED_T *consts)
{
	FIXED_A t1[8];
	FIXED_T t2[8];
	int i, hop;

	/* rounding coefficient */
	t1[0] = t1[1] = t1[2] = t1[3] = t1[4] = t1[5] = t1[6] = t1[7] =
		(FIXED_A) 1 << (SBC_PROTO_FIXED8_SCALE-1);

	/* low pass polyphase filter */
	for (hop = 0; hop < 80; hop += 16) {
		t1[0] += (FIXED_A) in[hop] * consts[hop];
		t1[0] += (FIXED_A) in[hop + 1] * consts[hop + 1];
		t1[1] += (FIXED_A) in[hop + 2] * consts[hop + 2];
		t1[1] += (FIXED_A) in[hop + 3] * consts[hop + 3];
		t1[2] += (FIXED_A) in[hop + 4] * consts[hop + 4];
		t1[2] += (FIXED_A) in[hop + 5] * consts[hop + 5];
		t1[3] += (FIXED_A) in[hop + 6] * consts[hop + 6];
		t1[3] += (FIXED_A) in[hop + 7] * consts[hop + 7];
		t1[4] += (FIXED_A) in[hop + 8] * consts[hop + 8];
		t1[4] += (FIXED_A) in[hop + 9] * consts[hop + 9];
		t1[5] += (FIXED_A) in[hop + 10] * consts[hop + 10];
		t1[5] += (FIXED_A) in[hop + 11] * consts[hop + 11];
		t1[6] += (FIXED_A) in[hop + 12] * consts[hop + 12];
		t1[6] += (FIXED_A) in[hop + 13] * consts[hop + 13];
		t1[7] += (FIXED_A) in[hop + 14] * consts[hop + 14];
		t1[7] += (FIXED_A) in[hop + 15] * consts[hop + 15];
	}

	/* scaling */
	t2[0] = t1[0] >> SBC_PROTO_FIXED8_SCALE;
	t2[1] = t1[1] >> SBC_PROTO_FIXED8_SCALE;
	t2[2] = t1[2] >> SBC_PROTO_FIXED8_SCALE;
	t2[3] = t1[3] >> SBC_PROTO_FIXED8_SCALE;
	t2[4] = t1[4] >> SBC_PROTO_FIXED8_SCALE;
	t2[5] = t1[5] >> SBC_PROTO_FIXED8_SCALE;
	t2[6] = t1[6] >> SBC_PROTO_FIXED8_SCALE;
	t2[7] = t1[7] >> SBC_PROTO_FIXED8_SCALE;


	/* do the cos transform */
	t1[0] = t1[1] = t1[2] = t1[3] = t1[4] = t1[5] = t1[6] = t1[7] = 0;

	for (i = 0; i < 4; i++) {
		t1[0] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 0];
		t1[0] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 1];
		t1[1] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 2];
		t1[1] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 3];
		t1[2] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 4];
		t1[2] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 5];
		t1[3] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 6];
		t1[3] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 7];
		t1[4] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 8];
		t1[4] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 9];
		t1[5] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 10];
		t1[5] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 11];
		t1[6] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 12];
		t1[6] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 13];
		t1[7] += (FIXED_A) t2[i * 2 + 0] * consts[80 + i * 16 + 14];
		t1[7] += (FIXED_A) t2[i * 2 + 1] * consts[80 + i * 16 + 15];
	}

	for (i = 0; i < 8; i++)
		out[i] = t1[i] >>
			(SBC_COS_TABLE_FIXED8_SCALE - SCALE_OUT_BITS);
}

static inline void sbc_analyze_4b_4s_simd(int16_t *x,
						int32_t *out, int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_four_simd(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_simd(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	sbc_analyze_four_simd(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_simd(x + 0, out, analysis_consts_fixed4_simd_even);
}

static inline void sbc_analyze_4b_8s_simd(int16_t *x,
					  int32_t *out, int out_stride)
{
	/* Analyze blocks */
	sbc_analyze_eight_simd(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_simd(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	sbc_analyze_eight_simd(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_simd(x + 0, out, analysis_consts_fixed8_simd_even);
}

static inline int16_t unaligned16_be(const uint8_t *ptr)
{
	return (int16_t) ((ptr[0] << 8) | ptr[1]);
}

static inline int16_t unaligned16_le(const uint8_t *ptr)
{
	return (int16_t) (ptr[0] | (ptr[1] << 8));
}

/*
 * Internal helper functions for input data processing. In order to get
 * optimal performance, it is important to have "nsamples", "nchannels"
 * and "big_endian" arguments used with this inline function as compile
 * time constants.
 */

static SBC_ALWAYS_INLINE int sbc_encoder_process_input_s4_internal(
	int position,
	const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
	int nsamples, int nchannels, int big_endian)
{
	/* handle X buffer wraparound */
	if (position < nsamples) {
		if (nchannels > 0)
			memcpy(&X[0][SBC_X_BUFFER_SIZE - 40], &X[0][position],
							36 * sizeof(int16_t));
		if (nchannels > 1)
			memcpy(&X[1][SBC_X_BUFFER_SIZE - 40], &X[1][position],
							36 * sizeof(int16_t));
		position = SBC_X_BUFFER_SIZE - 40;
	}

	#define PCM(i) (big_endian ? \
		unaligned16_be(pcm + (i) * 2) : unaligned16_le(pcm + (i) * 2))

	/* copy/permutate audio samples */
	while ((nsamples -= 8) >= 0) {
		position -= 8;
		if (nchannels > 0) {
			int16_t *x = &X[0][position];
			x[0]  = PCM(0 + 7 * nchannels);
			x[1]  = PCM(0 + 3 * nchannels);
			x[2]  = PCM(0 + 6 * nchannels);
			x[3]  = PCM(0 + 4 * nchannels);
			x[4]  = PCM(0 + 0 * nchannels);
			x[5]  = PCM(0 + 2 * nchannels);
			x[6]  = PCM(0 + 1 * nchannels);
			x[7]  = PCM(0 + 5 * nchannels);
		}
		if (nchannels > 1) {
			int16_t *x = &X[1][position];
			x[0]  = PCM(1 + 7 * nchannels);
			x[1]  = PCM(1 + 3 * nchannels);
			x[2]  = PCM(1 + 6 * nchannels);
			x[3]  = PCM(1 + 4 * nchannels);
			x[4]  = PCM(1 + 0 * nchannels);
			x[5]  = PCM(1 + 2 * nchannels);
			x[6]  = PCM(1 + 1 * nchannels);
			x[7]  = PCM(1 + 5 * nchannels);
		}
		pcm += 16 * nchannels;
	}
	#undef PCM

	return position;
}

static SBC_ALWAYS_INLINE int sbc_encoder_process_input_s8_internal(
	int position,
	const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
	int nsamples, int nchannels, int big_endian)
{
	/* handle X buffer wraparound */
	if (position < nsamples) {
		if (nchannels > 0)
			memcpy(&X[0][SBC_X_BUFFER_SIZE - 72], &X[0][position],
							72 * sizeof(int16_t));
		if (nchannels > 1)
			memcpy(&X[1][SBC_X_BUFFER_SIZE - 72], &X[1][position],
							72 * sizeof(int16_t));
		position = SBC_X_BUFFER_SIZE - 72;
	}

	#define PCM(i) (big_endian ? \
		unaligned16_be(pcm + (i) * 2) : unaligned16_le(pcm + (i) * 2))

	/* copy/permutate audio samples */
	while ((nsamples -= 16) >= 0) {
		position -= 16;
		if (nchannels > 0) {
			int16_t *x = &X[0][position];
			x[0]  = PCM(0 + 15 * nchannels);
			x[1]  = PCM(0 + 7 * nchannels);
			x[2]  = PCM(0 + 14 * nchannels);
			x[3]  = PCM(0 + 8 * nchannels);
			x[4]  = PCM(0 + 13 * nchannels);
			x[5]  = PCM(0 + 9 * nchannels);
			x[6]  = PCM(0 + 12 * nchannels);
			x[7]  = PCM(0 + 10 * nchannels);
			x[8]  = PCM(0 + 11 * nchannels);
			x[9]  = PCM(0 + 3 * nchannels);
			x[10] = PCM(0 + 6 * nchannels);
			x[11] = PCM(0 + 0 * nchannels);
			x[12] = PCM(0 + 5 * nchannels);
			x[13] = PCM(0 + 1 * nchannels);
			x[14] = PCM(0 + 4 * nchannels);
			x[15] = PCM(0 + 2 * nchannels);
		}
		if (nchannels > 1) {
			int16_t *x = &X[1][position];
			x[0]  = PCM(1 + 15 * nchannels);
			x[1]  = PCM(1 + 7 * nchannels);
			x[2]  = PCM(1 + 14 * nchannels);
			x[3]  = PCM(1 + 8 * nchannels);
			x[4]  = PCM(1 + 13 * nchannels);
			x[5]  = PCM(1 + 9 * nchannels);
			x[6]  = PCM(1 + 12 * nchannels);
			x[7]  = PCM(1 + 10 * nchannels);
			x[8]  = PCM(1 + 11 * nchannels);
			x[9]  = PCM(1 + 3 * nchannels);
			x[10] = PCM(1 + 6 * nchannels);
			x[11] = PCM(1 + 0 * nchannels);
			x[12] = PCM(1 + 5 * nchannels);
			x[13] = PCM(1 + 1 * nchannels);
			x[14] = PCM(1 + 4 * nchannels);
			x[15] = PCM(1 + 2 * nchannels);
		}
		pcm += 32 * nchannels;
	}
	#undef PCM

	return position;
}

/*
 * Input data processing functions. The data is endian converted if needed,
 * channels are deintrleaved and audio samples are reordered for use in
 * SIMD-friendly analysis filter function. The results are put into "X"
 * array, getting appended to the previous data (or it is better to say
 * prepended, as the buffer is filled from top to bottom). Old data is
 * discarded when neededed, but availability of (10 * nrof_subbands)
 * contiguous samples is always guaranteed for the input to the analysis
 * filter. This is achieved by copying a sufficient part of old data
 * to the top of the buffer on buffer wraparound.
 */

static int sbc_enc_process_input_4s_le(int position,
		const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
		int nsamples, int nchannels)
{
	if (nchannels > 1)
		return sbc_encoder_process_input_s4_internal(
			position, pcm, X, nsamples, 2, 0);
	else
		return sbc_encoder_process_input_s4_internal(
			position, pcm, X, nsamples, 1, 0);
}

static int sbc_enc_process_input_4s_be(int position,
		const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
		int nsamples, int nchannels)
{
	if (nchannels > 1)
		return sbc_encoder_process_input_s4_internal(
			position, pcm, X, nsamples, 2, 1);
	else
		return sbc_encoder_process_input_s4_internal(
			position, pcm, X, nsamples, 1, 1);
}

static int sbc_enc_process_input_8s_le(int position,
		const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
		int nsamples, int nchannels)
{
	if (nchannels > 1)
		return sbc_encoder_process_input_s8_internal(
			position, pcm, X, nsamples, 2, 0);
	else
		return sbc_encoder_process_input_s8_internal(
			position, pcm, X, nsamples, 1, 0);
}

static int sbc_enc_process_input_8s_be(int position,
		const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
		int nsamples, int nchannels)
{
	if (nchannels > 1)
		return sbc_encoder_process_input_s8_internal(
			position, pcm, X, nsamples, 2, 1);
	else
		return sbc_encoder_process_input_s8_internal(
			position, pcm, X, nsamples, 1, 1);
}

/* Supplementary function to count the number of leading zeros */

static inline int sbc_clz(uint32_t x)
{
#ifdef __GNUC__
	return __builtin_clz(x);
#else
	/* TODO: this should be replaced with something better if good
	 * performance is wanted when using compilers other than gcc */
	int cnt = 0;
	while (x) {
		cnt++;
		x >>= 1;
	}
	return 32 - cnt;
#endif
}

static void sbc_calc_scalefactors(
	int32_t sb_sample_f[16][2][8],
	uint32_t scale_factor[2][8],
	int blocks, int channels, int subbands)
{
	int ch, sb, blk;
	for (ch = 0; ch < channels; ch++) {
		for (sb = 0; sb < subbands; sb++) {
			uint32_t x = 1 << SCALE_OUT_BITS;
			for (blk = 0; blk < blocks; blk++) {
				int32_t tmp = fabs(sb_sample_f[blk][ch][sb]);
				if (tmp != 0)
					x |= tmp - 1;
			}
			scale_factor[ch][sb] = (31 - SCALE_OUT_BITS) -
				sbc_clz(x);
		}
	}
}

static int sbc_calc_scalefactors_j(
	int32_t sb_sample_f[16][2][8],
	uint32_t scale_factor[2][8],
	int blocks, int subbands)
{
	int blk, joint = 0;
	int32_t tmp0, tmp1;
	uint32_t x, y;

	/* last subband does not use joint stereo */
	int sb = subbands - 1;
	x = 1 << SCALE_OUT_BITS;
	y = 1 << SCALE_OUT_BITS;
	for (blk = 0; blk < blocks; blk++) {
		tmp0 = fabs(sb_sample_f[blk][0][sb]);
		tmp1 = fabs(sb_sample_f[blk][1][sb]);
		if (tmp0 != 0)
			x |= tmp0 - 1;
		if (tmp1 != 0)
			y |= tmp1 - 1;
	}
	scale_factor[0][sb] = (31 - SCALE_OUT_BITS) - sbc_clz(x);
	scale_factor[1][sb] = (31 - SCALE_OUT_BITS) - sbc_clz(y);

	/* the rest of subbands can use joint stereo */
	while (--sb >= 0) {
		int32_t sb_sample_j[16][2];
		x = 1 << SCALE_OUT_BITS;
		y = 1 << SCALE_OUT_BITS;
		for (blk = 0; blk < blocks; blk++) {
			tmp0 = sb_sample_f[blk][0][sb];
			tmp1 = sb_sample_f[blk][1][sb];
			sb_sample_j[blk][0] = ASR(tmp0, 1) + ASR(tmp1, 1);
			sb_sample_j[blk][1] = ASR(tmp0, 1) - ASR(tmp1, 1);
			tmp0 = fabs(tmp0);
			tmp1 = fabs(tmp1);
			if (tmp0 != 0)
				x |= tmp0 - 1;
			if (tmp1 != 0)
				y |= tmp1 - 1;
		}
		scale_factor[0][sb] = (31 - SCALE_OUT_BITS) -
			sbc_clz(x);
		scale_factor[1][sb] = (31 - SCALE_OUT_BITS) -
			sbc_clz(y);
		x = 1 << SCALE_OUT_BITS;
		y = 1 << SCALE_OUT_BITS;
		for (blk = 0; blk < blocks; blk++) {
			tmp0 = fabs(sb_sample_j[blk][0]);
			tmp1 = fabs(sb_sample_j[blk][1]);
			if (tmp0 != 0)
				x |= tmp0 - 1;
			if (tmp1 != 0)
				y |= tmp1 - 1;
		}
		x = (31 - SCALE_OUT_BITS) - sbc_clz(x);
		y = (31 - SCALE_OUT_BITS) - sbc_clz(y);

		/* decide whether to use joint stereo for this subband */
		if ((scale_factor[0][sb] + scale_factor[1][sb]) > x + y) {
			joint |= 1 << (subbands - 1 - sb);
			scale_factor[0][sb] = x;
			scale_factor[1][sb] = y;
			for (blk = 0; blk < blocks; blk++) {
				sb_sample_f[blk][0][sb] = sb_sample_j[blk][0];
				sb_sample_f[blk][1][sb] = sb_sample_j[blk][1];
			}
		}
	}

	/* bitmask with the information about subbands using joint stereo */
	return joint;
}

/*
 * Detect CPU features and setup function pointers
 */
void sbc_init_primitives(struct sbc_encoder_state *state)
{
	/* Default implementation for analyze functions */
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s_simd;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s_simd;

	/* Default implementation for input reordering / deinterleaving */
	state->sbc_enc_process_input_4s_le = sbc_enc_process_input_4s_le;
	state->sbc_enc_process_input_4s_be = sbc_enc_process_input_4s_be;
	state->sbc_enc_process_input_8s_le = sbc_enc_process_input_8s_le;
	state->sbc_enc_process_input_8s_be = sbc_enc_process_input_8s_be;

	/* Default implementation for scale factors calculation */
	state->sbc_calc_scalefactors = sbc_calc_scalefactors;
	state->sbc_calc_scalefactors_j = sbc_calc_scalefactors_j;
	state->implementation_info = "Generic C";

	/* X86/AMD64 optimizations */
#ifdef SBC_BUILD_WITH_MMX_SUPPORT
	sbc_init_primitives_mmx(state);
#endif

	/* ARM optimizations */
#ifdef SBC_BUILD_WITH_ARMV6_SUPPORT
	sbc_init_primitives_armv6(state);
#endif
#ifdef SBC_BUILD_WITH_IWMMXT_SUPPORT
	sbc_init_primitives_iwmmxt(state);
#endif
#ifdef SBC_BUILD_WITH_NEON_SUPPORT
	sbc_init_primitives_neon(state);
#endif
}
