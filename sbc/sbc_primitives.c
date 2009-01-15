/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include "sbc_primitives.h"

/*
 * A standard C code of analysis filter.
 */
static inline void sbc_analyze_four(const int16_t *in, int32_t *out)
{
	FIXED_A t1[4];
	FIXED_T t2[4];
	int i = 0, hop = 0;

	/* rounding coefficient */
	t1[0] = t1[1] = t1[2] = t1[3] =
		(FIXED_A) 1 << (SBC_PROTO_FIXED4_SCALE - 1);

	/* low pass polyphase filter */
	for (hop = 0; hop < 40; hop += 8) {
		t1[0] += (FIXED_A) in[hop] * _sbc_proto_fixed4[hop];
		t1[1] += (FIXED_A) in[hop + 1] * _sbc_proto_fixed4[hop + 1];
		t1[2] += (FIXED_A) in[hop + 2] * _sbc_proto_fixed4[hop + 2];
		t1[1] += (FIXED_A) in[hop + 3] * _sbc_proto_fixed4[hop + 3];
		t1[0] += (FIXED_A) in[hop + 4] * _sbc_proto_fixed4[hop + 4];
		t1[3] += (FIXED_A) in[hop + 5] * _sbc_proto_fixed4[hop + 5];
		t1[3] += (FIXED_A) in[hop + 7] * _sbc_proto_fixed4[hop + 7];
	}

	/* scaling */
	t2[0] = t1[0] >> SBC_PROTO_FIXED4_SCALE;
	t2[1] = t1[1] >> SBC_PROTO_FIXED4_SCALE;
	t2[2] = t1[2] >> SBC_PROTO_FIXED4_SCALE;
	t2[3] = t1[3] >> SBC_PROTO_FIXED4_SCALE;

	/* do the cos transform */
	for (i = 0, hop = 0; i < 4; hop += 8, i++) {
		out[i] = ((FIXED_A) t2[0] * cos_table_fixed_4[0 + hop] +
			  (FIXED_A) t2[1] * cos_table_fixed_4[1 + hop] +
			  (FIXED_A) t2[2] * cos_table_fixed_4[2 + hop] +
			  (FIXED_A) t2[3] * cos_table_fixed_4[5 + hop]) >>
			(SBC_COS_TABLE_FIXED4_SCALE - SCALE_OUT_BITS);
	}
}

static void sbc_analyze_4b_4s(int16_t *pcm, int16_t *x,
			      int32_t *out, int out_stride)
{
	int i;

	/* Input 4 x 4 Audio Samples */
	for (i = 0; i < 16; i += 4) {
		x[64 + i] = x[0 + i] = pcm[15 - i];
		x[65 + i] = x[1 + i] = pcm[14 - i];
		x[66 + i] = x[2 + i] = pcm[13 - i];
		x[67 + i] = x[3 + i] = pcm[12 - i];
	}

	/* Analyze four blocks */
	sbc_analyze_four(x + 12, out);
	out += out_stride;
	sbc_analyze_four(x + 8, out);
	out += out_stride;
	sbc_analyze_four(x + 4, out);
	out += out_stride;
	sbc_analyze_four(x, out);
}

static inline void sbc_analyze_eight(const int16_t *in, int32_t *out)
{
	FIXED_A t1[8];
	FIXED_T t2[8];
	int i, hop;

	/* rounding coefficient */
	t1[0] = t1[1] = t1[2] = t1[3] = t1[4] = t1[5] = t1[6] = t1[7] =
		(FIXED_A) 1 << (SBC_PROTO_FIXED8_SCALE-1);

	/* low pass polyphase filter */
	for (hop = 0; hop < 80; hop += 16) {
		t1[0] += (FIXED_A) in[hop] * _sbc_proto_fixed8[hop];
		t1[1] += (FIXED_A) in[hop + 1] * _sbc_proto_fixed8[hop + 1];
		t1[2] += (FIXED_A) in[hop + 2] * _sbc_proto_fixed8[hop + 2];
		t1[3] += (FIXED_A) in[hop + 3] * _sbc_proto_fixed8[hop + 3];
		t1[4] += (FIXED_A) in[hop + 4] * _sbc_proto_fixed8[hop + 4];
		t1[3] += (FIXED_A) in[hop + 5] * _sbc_proto_fixed8[hop + 5];
		t1[2] += (FIXED_A) in[hop + 6] * _sbc_proto_fixed8[hop + 6];
		t1[1] += (FIXED_A) in[hop + 7] * _sbc_proto_fixed8[hop + 7];
		t1[0] += (FIXED_A) in[hop + 8] * _sbc_proto_fixed8[hop + 8];
		t1[5] += (FIXED_A) in[hop + 9] * _sbc_proto_fixed8[hop + 9];
		t1[6] += (FIXED_A) in[hop + 10] * _sbc_proto_fixed8[hop + 10];
		t1[7] += (FIXED_A) in[hop + 11] * _sbc_proto_fixed8[hop + 11];
		t1[7] += (FIXED_A) in[hop + 13] * _sbc_proto_fixed8[hop + 13];
		t1[6] += (FIXED_A) in[hop + 14] * _sbc_proto_fixed8[hop + 14];
		t1[5] += (FIXED_A) in[hop + 15] * _sbc_proto_fixed8[hop + 15];
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
	for (i = 0, hop = 0; i < 8; hop += 16, i++) {
		out[i] = ((FIXED_A) t2[0] * cos_table_fixed_8[0 + hop] +
			  (FIXED_A) t2[1] * cos_table_fixed_8[1 + hop] +
			  (FIXED_A) t2[2] * cos_table_fixed_8[2 + hop] +
			  (FIXED_A) t2[3] * cos_table_fixed_8[3 + hop] +
			  (FIXED_A) t2[4] * cos_table_fixed_8[4 + hop] +
			  (FIXED_A) t2[5] * cos_table_fixed_8[9 + hop] +
			  (FIXED_A) t2[6] * cos_table_fixed_8[10 + hop] +
			  (FIXED_A) t2[7] * cos_table_fixed_8[11 + hop]) >>
			(SBC_COS_TABLE_FIXED8_SCALE - SCALE_OUT_BITS);
	}
}

static void sbc_analyze_4b_8s(int16_t *pcm, int16_t *x,
			      int32_t *out, int out_stride)
{
	int i;

	/* Input 4 x 8 Audio Samples */
	for (i = 0; i < 32; i += 8) {
		x[128 + i] = x[0 + i] = pcm[31 - i];
		x[129 + i] = x[1 + i] = pcm[30 - i];
		x[130 + i] = x[2 + i] = pcm[29 - i];
		x[131 + i] = x[3 + i] = pcm[28 - i];
		x[132 + i] = x[4 + i] = pcm[27 - i];
		x[133 + i] = x[5 + i] = pcm[26 - i];
		x[134 + i] = x[6 + i] = pcm[25 - i];
		x[135 + i] = x[7 + i] = pcm[24 - i];
	}

	/* Analyze four blocks */
	sbc_analyze_eight(x + 24, out);
	out += out_stride;
	sbc_analyze_eight(x + 16, out);
	out += out_stride;
	sbc_analyze_eight(x + 8, out);
	out += out_stride;
	sbc_analyze_eight(x, out);
}

/*
 * A reference C code of analysis filter with SIMD-friendly tables
 * reordering and code layout. This code can be used to develop platform
 * specific SIMD optimizations. Also it may be used as some kind of test
 * for compiler autovectorization capabilities (who knows, if the compiler
 * is very good at this stuff, hand optimized assembly may be not strictly
 * needed for some platform).
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

static inline void sbc_analyze_4b_4s_simd(int16_t *pcm, int16_t *x,
					  int32_t *out, int out_stride)
{
	/* Fetch audio samples and do input data reordering for SIMD */
	x[64] = x[0]  = pcm[8 + 7];
	x[65] = x[1]  = pcm[8 + 3];
	x[66] = x[2]  = pcm[8 + 6];
	x[67] = x[3]  = pcm[8 + 4];
	x[68] = x[4]  = pcm[8 + 0];
	x[69] = x[5]  = pcm[8 + 2];
	x[70] = x[6]  = pcm[8 + 1];
	x[71] = x[7]  = pcm[8 + 5];

	x[72] = x[8]  = pcm[0 + 7];
	x[73] = x[9]  = pcm[0 + 3];
	x[74] = x[10] = pcm[0 + 6];
	x[75] = x[11] = pcm[0 + 4];
	x[76] = x[12] = pcm[0 + 0];
	x[77] = x[13] = pcm[0 + 2];
	x[78] = x[14] = pcm[0 + 1];
	x[79] = x[15] = pcm[0 + 5];

	/* Analyze blocks */
	sbc_analyze_four_simd(x + 12, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_simd(x + 8, out, analysis_consts_fixed4_simd_even);
	out += out_stride;
	sbc_analyze_four_simd(x + 4, out, analysis_consts_fixed4_simd_odd);
	out += out_stride;
	sbc_analyze_four_simd(x + 0, out, analysis_consts_fixed4_simd_even);
}

static inline void sbc_analyze_4b_8s_simd(int16_t *pcm, int16_t *x,
					  int32_t *out, int out_stride)
{
	/* Fetch audio samples and do input data reordering for SIMD */
	x[128] = x[0]  = pcm[16 + 15];
	x[129] = x[1]  = pcm[16 + 7];
	x[130] = x[2]  = pcm[16 + 14];
	x[131] = x[3]  = pcm[16 + 8];
	x[132] = x[4]  = pcm[16 + 13];
	x[133] = x[5]  = pcm[16 + 9];
	x[134] = x[6]  = pcm[16 + 12];
	x[135] = x[7]  = pcm[16 + 10];
	x[136] = x[8]  = pcm[16 + 11];
	x[137] = x[9]  = pcm[16 + 3];
	x[138] = x[10] = pcm[16 + 6];
	x[139] = x[11] = pcm[16 + 0];
	x[140] = x[12] = pcm[16 + 5];
	x[141] = x[13] = pcm[16 + 1];
	x[142] = x[14] = pcm[16 + 4];
	x[143] = x[15] = pcm[16 + 2];

	x[144] = x[16] = pcm[0 + 15];
	x[145] = x[17] = pcm[0 + 7];
	x[146] = x[18] = pcm[0 + 14];
	x[147] = x[19] = pcm[0 + 8];
	x[148] = x[20] = pcm[0 + 13];
	x[149] = x[21] = pcm[0 + 9];
	x[150] = x[22] = pcm[0 + 12];
	x[151] = x[23] = pcm[0 + 10];
	x[152] = x[24] = pcm[0 + 11];
	x[153] = x[25] = pcm[0 + 3];
	x[154] = x[26] = pcm[0 + 6];
	x[155] = x[27] = pcm[0 + 0];
	x[156] = x[28] = pcm[0 + 5];
	x[157] = x[29] = pcm[0 + 1];
	x[158] = x[30] = pcm[0 + 4];
	x[159] = x[31] = pcm[0 + 2];

	/* Analyze blocks */
	sbc_analyze_eight_simd(x + 24, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_simd(x + 16, out, analysis_consts_fixed8_simd_even);
	out += out_stride;
	sbc_analyze_eight_simd(x + 8, out, analysis_consts_fixed8_simd_odd);
	out += out_stride;
	sbc_analyze_eight_simd(x + 0, out, analysis_consts_fixed8_simd_even);
}

/*
 * Detect CPU features and setup function pointers
 */
void sbc_init_primitives(struct sbc_encoder_state *state)
{
	/* Default implementation for analyze functions */
	state->sbc_analyze_4b_4s = sbc_analyze_4b_4s;
	state->sbc_analyze_4b_8s = sbc_analyze_4b_8s;
}
