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

#ifndef __SBC_PRIMITIVES_H
#define __SBC_PRIMITIVES_H

#define SCALE_OUT_BITS 15
#define SBC_X_BUFFER_SIZE 328

#ifdef __GNUC__
#define SBC_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define SBC_ALWAYS_INLINE inline
#endif

struct sbc_encoder_state {
	int position;
	int16_t SBC_ALIGNED X[2][SBC_X_BUFFER_SIZE];
	/* Polyphase analysis filter for 4 subbands configuration,
	 * it handles 4 blocks at once */
	void (*sbc_analyze_4b_4s)(int16_t *x, int32_t *out, int out_stride);
	/* Polyphase analysis filter for 8 subbands configuration,
	 * it handles 4 blocks at once */
	void (*sbc_analyze_4b_8s)(int16_t *x, int32_t *out, int out_stride);
	/* Process input data (deinterleave, endian conversion, reordering),
	 * depending on the number of subbands and input data byte order */
	int (*sbc_enc_process_input_4s_le)(int position,
			const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
			int nsamples, int nchannels);
	int (*sbc_enc_process_input_4s_be)(int position,
			const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
			int nsamples, int nchannels);
	int (*sbc_enc_process_input_8s_le)(int position,
			const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
			int nsamples, int nchannels);
	int (*sbc_enc_process_input_8s_be)(int position,
			const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
			int nsamples, int nchannels);
	/* Scale factors calculation */
	void (*sbc_calc_scalefactors)(int32_t sb_sample_f[16][2][8],
			uint32_t scale_factor[2][8],
			int blocks, int channels, int subbands);
	/* Scale factors calculation with joint stereo support */
	int (*sbc_calc_scalefactors_j)(int32_t sb_sample_f[16][2][8],
			uint32_t scale_factor[2][8],
			int blocks, int subbands);
	const char *implementation_info;
};

/*
 * Initialize pointers to the functions which are the basic "building bricks"
 * of SBC codec. Best implementation is selected based on target CPU
 * capabilities.
 */
void sbc_init_primitives(struct sbc_encoder_state *encoder_state);

#endif
