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

#ifndef __SBC_PRIMITIVES_H
#define __SBC_PRIMITIVES_H

#define SCALE_OUT_BITS 15

#ifdef __GNUC__
#define SBC_ALWAYS_INLINE __attribute__((always_inline))
#else
#define SBC_ALWAYS_INLINE inline
#endif

struct sbc_encoder_state {
	int subbands;
	int position[2];
	int16_t SBC_ALIGNED X[2][256];
	/* Polyphase analysis filter for 4 subbands configuration,
	 * it handles 4 blocks at once */
	void (*sbc_analyze_4b_4s)(int16_t *pcm, int16_t *x,
					int32_t *out, int out_stride);
	/* Polyphase analysis filter for 8 subbands configuration,
	 * it handles 4 blocks at once */
	void (*sbc_analyze_4b_8s)(int16_t *pcm, int16_t *x,
					int32_t *out, int out_stride);
};

/*
 * Initialize pointers to the functions which are the basic "building bricks"
 * of SBC codec. Best implementation is selected based on target CPU
 * capabilities.
 */
void sbc_init_primitives(struct sbc_encoder_state *encoder_state);

#endif
