/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2008-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2004-2005  Henryk Ploetz <henryk@ploetzli.ch>
 *  Copyright (C) 2005-2008  Brad Midgley <bmidgley@xmission.com>
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

/* todo items:

  use a log2 table for byte integer scale factors calculation (sum log2 results
  for high and low bytes) fill bitpool by 16 bits instead of one at a time in
  bits allocation/bitpool generation port to the dsp

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>

#include "sbc_math.h"
#include "sbc_tables.h"

#include "sbc.h"
#include "sbc_primitives.h"

#define SBC_SYNCWORD	0x9C

/* This structure contains an unpacked SBC frame.
   Yes, there is probably quite some unused space herein */
struct sbc_frame {
	uint8_t frequency;
	uint8_t block_mode;
	uint8_t blocks;
	enum {
		MONO		= SBC_MODE_MONO,
		DUAL_CHANNEL	= SBC_MODE_DUAL_CHANNEL,
		STEREO		= SBC_MODE_STEREO,
		JOINT_STEREO	= SBC_MODE_JOINT_STEREO
	} mode;
	uint8_t channels;
	enum {
		LOUDNESS	= SBC_AM_LOUDNESS,
		SNR		= SBC_AM_SNR
	} allocation;
	uint8_t subband_mode;
	uint8_t subbands;
	uint8_t bitpool;
	uint16_t codesize;
	uint8_t length;

	/* bit number x set means joint stereo has been used in subband x */
	uint8_t joint;

	/* only the lower 4 bits of every element are to be used */
	uint32_t SBC_ALIGNED scale_factor[2][8];

	/* raw integer subband samples in the frame */
	int32_t SBC_ALIGNED sb_sample_f[16][2][8];

	/* modified subband samples */
	int32_t SBC_ALIGNED sb_sample[16][2][8];

	/* original pcm audio samples */
	int16_t SBC_ALIGNED pcm_sample[2][16*8];
};

struct sbc_decoder_state {
	int subbands;
	int32_t V[2][170];
	int offset[2][16];
};

/*
 * Calculates the CRC-8 of the first len bits in data
 */
static const uint8_t crc_table[256] = {
	0x00, 0x1D, 0x3A, 0x27, 0x74, 0x69, 0x4E, 0x53,
	0xE8, 0xF5, 0xD2, 0xCF, 0x9C, 0x81, 0xA6, 0xBB,
	0xCD, 0xD0, 0xF7, 0xEA, 0xB9, 0xA4, 0x83, 0x9E,
	0x25, 0x38, 0x1F, 0x02, 0x51, 0x4C, 0x6B, 0x76,
	0x87, 0x9A, 0xBD, 0xA0, 0xF3, 0xEE, 0xC9, 0xD4,
	0x6F, 0x72, 0x55, 0x48, 0x1B, 0x06, 0x21, 0x3C,
	0x4A, 0x57, 0x70, 0x6D, 0x3E, 0x23, 0x04, 0x19,
	0xA2, 0xBF, 0x98, 0x85, 0xD6, 0xCB, 0xEC, 0xF1,
	0x13, 0x0E, 0x29, 0x34, 0x67, 0x7A, 0x5D, 0x40,
	0xFB, 0xE6, 0xC1, 0xDC, 0x8F, 0x92, 0xB5, 0xA8,
	0xDE, 0xC3, 0xE4, 0xF9, 0xAA, 0xB7, 0x90, 0x8D,
	0x36, 0x2B, 0x0C, 0x11, 0x42, 0x5F, 0x78, 0x65,
	0x94, 0x89, 0xAE, 0xB3, 0xE0, 0xFD, 0xDA, 0xC7,
	0x7C, 0x61, 0x46, 0x5B, 0x08, 0x15, 0x32, 0x2F,
	0x59, 0x44, 0x63, 0x7E, 0x2D, 0x30, 0x17, 0x0A,
	0xB1, 0xAC, 0x8B, 0x96, 0xC5, 0xD8, 0xFF, 0xE2,
	0x26, 0x3B, 0x1C, 0x01, 0x52, 0x4F, 0x68, 0x75,
	0xCE, 0xD3, 0xF4, 0xE9, 0xBA, 0xA7, 0x80, 0x9D,
	0xEB, 0xF6, 0xD1, 0xCC, 0x9F, 0x82, 0xA5, 0xB8,
	0x03, 0x1E, 0x39, 0x24, 0x77, 0x6A, 0x4D, 0x50,
	0xA1, 0xBC, 0x9B, 0x86, 0xD5, 0xC8, 0xEF, 0xF2,
	0x49, 0x54, 0x73, 0x6E, 0x3D, 0x20, 0x07, 0x1A,
	0x6C, 0x71, 0x56, 0x4B, 0x18, 0x05, 0x22, 0x3F,
	0x84, 0x99, 0xBE, 0xA3, 0xF0, 0xED, 0xCA, 0xD7,
	0x35, 0x28, 0x0F, 0x12, 0x41, 0x5C, 0x7B, 0x66,
	0xDD, 0xC0, 0xE7, 0xFA, 0xA9, 0xB4, 0x93, 0x8E,
	0xF8, 0xE5, 0xC2, 0xDF, 0x8C, 0x91, 0xB6, 0xAB,
	0x10, 0x0D, 0x2A, 0x37, 0x64, 0x79, 0x5E, 0x43,
	0xB2, 0xAF, 0x88, 0x95, 0xC6, 0xDB, 0xFC, 0xE1,
	0x5A, 0x47, 0x60, 0x7D, 0x2E, 0x33, 0x14, 0x09,
	0x7F, 0x62, 0x45, 0x58, 0x0B, 0x16, 0x31, 0x2C,
	0x97, 0x8A, 0xAD, 0xB0, 0xE3, 0xFE, 0xD9, 0xC4
};

static uint8_t sbc_crc8(const uint8_t *data, size_t len)
{
	uint8_t crc = 0x0f;
	size_t i;
	uint8_t octet;

	for (i = 0; i < len / 8; i++)
		crc = crc_table[crc ^ data[i]];

	octet = data[i];
	for (i = 0; i < len % 8; i++) {
		char bit = ((octet ^ crc) & 0x80) >> 7;

		crc = ((crc & 0x7f) << 1) ^ (bit ? 0x1d : 0);

		octet = octet << 1;
	}

	return crc;
}

/*
 * Code straight from the spec to calculate the bits array
 * Takes a pointer to the frame in question, a pointer to the bits array and
 * the sampling frequency (as 2 bit integer)
 */
static SBC_ALWAYS_INLINE void sbc_calculate_bits_internal(
		const struct sbc_frame *frame, int (*bits)[8], int subbands)
{
	uint8_t sf = frame->frequency;

	if (frame->mode == MONO || frame->mode == DUAL_CHANNEL) {
		int bitneed[2][8], loudness, max_bitneed, bitcount, slicecount, bitslice;
		int ch, sb;

		for (ch = 0; ch < frame->channels; ch++) {
			max_bitneed = 0;
			if (frame->allocation == SNR) {
				for (sb = 0; sb < subbands; sb++) {
					bitneed[ch][sb] = frame->scale_factor[ch][sb];
					if (bitneed[ch][sb] > max_bitneed)
						max_bitneed = bitneed[ch][sb];
				}
			} else {
				for (sb = 0; sb < subbands; sb++) {
					if (frame->scale_factor[ch][sb] == 0)
						bitneed[ch][sb] = -5;
					else {
						if (subbands == 4)
							loudness = frame->scale_factor[ch][sb] - sbc_offset4[sf][sb];
						else
							loudness = frame->scale_factor[ch][sb] - sbc_offset8[sf][sb];
						if (loudness > 0)
							bitneed[ch][sb] = loudness / 2;
						else
							bitneed[ch][sb] = loudness;
					}
					if (bitneed[ch][sb] > max_bitneed)
						max_bitneed = bitneed[ch][sb];
				}
			}

			bitcount = 0;
			slicecount = 0;
			bitslice = max_bitneed + 1;
			do {
				bitslice--;
				bitcount += slicecount;
				slicecount = 0;
				for (sb = 0; sb < subbands; sb++) {
					if ((bitneed[ch][sb] > bitslice + 1) && (bitneed[ch][sb] < bitslice + 16))
						slicecount++;
					else if (bitneed[ch][sb] == bitslice + 1)
						slicecount += 2;
				}
			} while (bitcount + slicecount < frame->bitpool);

			if (bitcount + slicecount == frame->bitpool) {
				bitcount += slicecount;
				bitslice--;
			}

			for (sb = 0; sb < subbands; sb++) {
				if (bitneed[ch][sb] < bitslice + 2)
					bits[ch][sb] = 0;
				else {
					bits[ch][sb] = bitneed[ch][sb] - bitslice;
					if (bits[ch][sb] > 16)
						bits[ch][sb] = 16;
				}
			}

			for (sb = 0; bitcount < frame->bitpool &&
							sb < subbands; sb++) {
				if ((bits[ch][sb] >= 2) && (bits[ch][sb] < 16)) {
					bits[ch][sb]++;
					bitcount++;
				} else if ((bitneed[ch][sb] == bitslice + 1) && (frame->bitpool > bitcount + 1)) {
					bits[ch][sb] = 2;
					bitcount += 2;
				}
			}

			for (sb = 0; bitcount < frame->bitpool &&
							sb < subbands; sb++) {
				if (bits[ch][sb] < 16) {
					bits[ch][sb]++;
					bitcount++;
				}
			}

		}

	} else if (frame->mode == STEREO || frame->mode == JOINT_STEREO) {
		int bitneed[2][8], loudness, max_bitneed, bitcount, slicecount, bitslice;
		int ch, sb;

		max_bitneed = 0;
		if (frame->allocation == SNR) {
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < subbands; sb++) {
					bitneed[ch][sb] = frame->scale_factor[ch][sb];
					if (bitneed[ch][sb] > max_bitneed)
						max_bitneed = bitneed[ch][sb];
				}
			}
		} else {
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < subbands; sb++) {
					if (frame->scale_factor[ch][sb] == 0)
						bitneed[ch][sb] = -5;
					else {
						if (subbands == 4)
							loudness = frame->scale_factor[ch][sb] - sbc_offset4[sf][sb];
						else
							loudness = frame->scale_factor[ch][sb] - sbc_offset8[sf][sb];
						if (loudness > 0)
							bitneed[ch][sb] = loudness / 2;
						else
							bitneed[ch][sb] = loudness;
					}
					if (bitneed[ch][sb] > max_bitneed)
						max_bitneed = bitneed[ch][sb];
				}
			}
		}

		bitcount = 0;
		slicecount = 0;
		bitslice = max_bitneed + 1;
		do {
			bitslice--;
			bitcount += slicecount;
			slicecount = 0;
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < subbands; sb++) {
					if ((bitneed[ch][sb] > bitslice + 1) && (bitneed[ch][sb] < bitslice + 16))
						slicecount++;
					else if (bitneed[ch][sb] == bitslice + 1)
						slicecount += 2;
				}
			}
		} while (bitcount + slicecount < frame->bitpool);

		if (bitcount + slicecount == frame->bitpool) {
			bitcount += slicecount;
			bitslice--;
		}

		for (ch = 0; ch < 2; ch++) {
			for (sb = 0; sb < subbands; sb++) {
				if (bitneed[ch][sb] < bitslice + 2) {
					bits[ch][sb] = 0;
				} else {
					bits[ch][sb] = bitneed[ch][sb] - bitslice;
					if (bits[ch][sb] > 16)
						bits[ch][sb] = 16;
				}
			}
		}

		ch = 0;
		sb = 0;
		while (bitcount < frame->bitpool) {
			if ((bits[ch][sb] >= 2) && (bits[ch][sb] < 16)) {
				bits[ch][sb]++;
				bitcount++;
			} else if ((bitneed[ch][sb] == bitslice + 1) && (frame->bitpool > bitcount + 1)) {
				bits[ch][sb] = 2;
				bitcount += 2;
			}
			if (ch == 1) {
				ch = 0;
				sb++;
				if (sb >= subbands)
					break;
			} else
				ch = 1;
		}

		ch = 0;
		sb = 0;
		while (bitcount < frame->bitpool) {
			if (bits[ch][sb] < 16) {
				bits[ch][sb]++;
				bitcount++;
			}
			if (ch == 1) {
				ch = 0;
				sb++;
				if (sb >= subbands)
					break;
			} else
				ch = 1;
		}

	}

}

static void sbc_calculate_bits(const struct sbc_frame *frame, int (*bits)[8])
{
	if (frame->subbands == 4)
		sbc_calculate_bits_internal(frame, bits, 4);
	else
		sbc_calculate_bits_internal(frame, bits, 8);
}

/*
 * Unpacks a SBC frame at the beginning of the stream in data,
 * which has at most len bytes into frame.
 * Returns the length in bytes of the packed frame, or a negative
 * value on error. The error codes are:
 *
 *  -1   Data stream too short
 *  -2   Sync byte incorrect
 *  -3   CRC8 incorrect
 *  -4   Bitpool value out of bounds
 */
static int sbc_unpack_frame(const uint8_t *data, struct sbc_frame *frame,
								size_t len)
{
	unsigned int consumed;
	/* Will copy the parts of the header that are relevant to crc
	 * calculation here */
	uint8_t crc_header[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	int crc_pos = 0;
	int32_t temp;

	int audio_sample;
	int ch, sb, blk, bit;	/* channel, subband, block and bit standard
				   counters */
	int bits[2][8];		/* bits distribution */
	uint32_t levels[2][8];	/* levels derived from that */

	if (len < 4)
		return -1;

	if (data[0] != SBC_SYNCWORD)
		return -2;

	frame->frequency = (data[1] >> 6) & 0x03;

	frame->block_mode = (data[1] >> 4) & 0x03;
	switch (frame->block_mode) {
	case SBC_BLK_4:
		frame->blocks = 4;
		break;
	case SBC_BLK_8:
		frame->blocks = 8;
		break;
	case SBC_BLK_12:
		frame->blocks = 12;
		break;
	case SBC_BLK_16:
		frame->blocks = 16;
		break;
	}

	frame->mode = (data[1] >> 2) & 0x03;
	switch (frame->mode) {
	case MONO:
		frame->channels = 1;
		break;
	case DUAL_CHANNEL:	/* fall-through */
	case STEREO:
	case JOINT_STEREO:
		frame->channels = 2;
		break;
	}

	frame->allocation = (data[1] >> 1) & 0x01;

	frame->subband_mode = (data[1] & 0x01);
	frame->subbands = frame->subband_mode ? 8 : 4;

	frame->bitpool = data[2];

	if ((frame->mode == MONO || frame->mode == DUAL_CHANNEL) &&
			frame->bitpool > 16 * frame->subbands)
		return -4;

	if ((frame->mode == STEREO || frame->mode == JOINT_STEREO) &&
			frame->bitpool > 32 * frame->subbands)
		return -4;

	/* data[3] is crc, we're checking it later */

	consumed = 32;

	crc_header[0] = data[1];
	crc_header[1] = data[2];
	crc_pos = 16;

	if (frame->mode == JOINT_STEREO) {
		if (len * 8 < consumed + frame->subbands)
			return -1;

		frame->joint = 0x00;
		for (sb = 0; sb < frame->subbands - 1; sb++)
			frame->joint |= ((data[4] >> (7 - sb)) & 0x01) << sb;
		if (frame->subbands == 4)
			crc_header[crc_pos / 8] = data[4] & 0xf0;
		else
			crc_header[crc_pos / 8] = data[4];

		consumed += frame->subbands;
		crc_pos += frame->subbands;
	}

	if (len * 8 < consumed + (4 * frame->subbands * frame->channels))
		return -1;

	for (ch = 0; ch < frame->channels; ch++) {
		for (sb = 0; sb < frame->subbands; sb++) {
			/* FIXME assert(consumed % 4 == 0); */
			frame->scale_factor[ch][sb] =
				(data[consumed >> 3] >> (4 - (consumed & 0x7))) & 0x0F;
			crc_header[crc_pos >> 3] |=
				frame->scale_factor[ch][sb] << (4 - (crc_pos & 0x7));

			consumed += 4;
			crc_pos += 4;
		}
	}

	if (data[3] != sbc_crc8(crc_header, crc_pos))
		return -3;

	sbc_calculate_bits(frame, bits);

	for (ch = 0; ch < frame->channels; ch++) {
		for (sb = 0; sb < frame->subbands; sb++)
			levels[ch][sb] = (1 << bits[ch][sb]) - 1;
	}

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (levels[ch][sb] > 0) {
					audio_sample = 0;
					for (bit = 0; bit < bits[ch][sb]; bit++) {
						if (consumed > len * 8)
							return -1;

						if ((data[consumed >> 3] >> (7 - (consumed & 0x7))) & 0x01)
							audio_sample |= 1 << (bits[ch][sb] - bit - 1);

						consumed++;
					}

					frame->sb_sample[blk][ch][sb] =
						(((audio_sample << 1) | 1) << frame->scale_factor[ch][sb]) /
						levels[ch][sb] - (1 << frame->scale_factor[ch][sb]);
				} else
					frame->sb_sample[blk][ch][sb] = 0;
			}
		}
	}

	if (frame->mode == JOINT_STEREO) {
		for (blk = 0; blk < frame->blocks; blk++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (frame->joint & (0x01 << sb)) {
					temp = frame->sb_sample[blk][0][sb] +
						frame->sb_sample[blk][1][sb];
					frame->sb_sample[blk][1][sb] =
						frame->sb_sample[blk][0][sb] -
						frame->sb_sample[blk][1][sb];
					frame->sb_sample[blk][0][sb] = temp;
				}
			}
		}
	}

	if ((consumed & 0x7) != 0)
		consumed += 8 - (consumed & 0x7);

	return consumed >> 3;
}

static void sbc_decoder_init(struct sbc_decoder_state *state,
					const struct sbc_frame *frame)
{
	int i, ch;

	memset(state->V, 0, sizeof(state->V));
	state->subbands = frame->subbands;

	for (ch = 0; ch < 2; ch++)
		for (i = 0; i < frame->subbands * 2; i++)
			state->offset[ch][i] = (10 * i + 10);
}

static SBC_ALWAYS_INLINE int16_t sbc_clip16(int32_t s)
{
	if (s > 0x7FFF)
		return 0x7FFF;
	else if (s < -0x8000)
		return -0x8000;
	else
		return s;
}

static inline void sbc_synthesize_four(struct sbc_decoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, k, idx;
	int32_t *v = state->V[ch];
	int *offset = state->offset[ch];

	for (i = 0; i < 8; i++) {
		/* Shifting */
		offset[i]--;
		if (offset[i] < 0) {
			offset[i] = 79;
			memcpy(v + 80, v, 9 * sizeof(*v));
		}

		/* Distribute the new matrix value to the shifted position */
		v[offset[i]] = SCALE4_STAGED1(
			MULA(synmatrix4[i][0], frame->sb_sample[blk][ch][0],
			MULA(synmatrix4[i][1], frame->sb_sample[blk][ch][1],
			MULA(synmatrix4[i][2], frame->sb_sample[blk][ch][2],
			MUL (synmatrix4[i][3], frame->sb_sample[blk][ch][3])))));
	}

	/* Compute the samples */
	for (idx = 0, i = 0; i < 4; i++, idx += 5) {
		k = (i + 4) & 0xf;

		/* Store in output, Q0 */
		frame->pcm_sample[ch][blk * 4 + i] = sbc_clip16(SCALE4_STAGED1(
			MULA(v[offset[i] + 0], sbc_proto_4_40m0[idx + 0],
			MULA(v[offset[k] + 1], sbc_proto_4_40m1[idx + 0],
			MULA(v[offset[i] + 2], sbc_proto_4_40m0[idx + 1],
			MULA(v[offset[k] + 3], sbc_proto_4_40m1[idx + 1],
			MULA(v[offset[i] + 4], sbc_proto_4_40m0[idx + 2],
			MULA(v[offset[k] + 5], sbc_proto_4_40m1[idx + 2],
			MULA(v[offset[i] + 6], sbc_proto_4_40m0[idx + 3],
			MULA(v[offset[k] + 7], sbc_proto_4_40m1[idx + 3],
			MULA(v[offset[i] + 8], sbc_proto_4_40m0[idx + 4],
			MUL( v[offset[k] + 9], sbc_proto_4_40m1[idx + 4]))))))))))));
	}
}

static inline void sbc_synthesize_eight(struct sbc_decoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, j, k, idx;
	int *offset = state->offset[ch];

	for (i = 0; i < 16; i++) {
		/* Shifting */
		offset[i]--;
		if (offset[i] < 0) {
			offset[i] = 159;
			for (j = 0; j < 9; j++)
				state->V[ch][j + 160] = state->V[ch][j];
		}

		/* Distribute the new matrix value to the shifted position */
		state->V[ch][offset[i]] = SCALE8_STAGED1(
			MULA(synmatrix8[i][0], frame->sb_sample[blk][ch][0],
			MULA(synmatrix8[i][1], frame->sb_sample[blk][ch][1],
			MULA(synmatrix8[i][2], frame->sb_sample[blk][ch][2],
			MULA(synmatrix8[i][3], frame->sb_sample[blk][ch][3],
			MULA(synmatrix8[i][4], frame->sb_sample[blk][ch][4],
			MULA(synmatrix8[i][5], frame->sb_sample[blk][ch][5],
			MULA(synmatrix8[i][6], frame->sb_sample[blk][ch][6],
			MUL( synmatrix8[i][7], frame->sb_sample[blk][ch][7])))))))));
	}

	/* Compute the samples */
	for (idx = 0, i = 0; i < 8; i++, idx += 5) {
		k = (i + 8) & 0xf;

		/* Store in output, Q0 */
		frame->pcm_sample[ch][blk * 8 + i] = sbc_clip16(SCALE8_STAGED1(
			MULA(state->V[ch][offset[i] + 0], sbc_proto_8_80m0[idx + 0],
			MULA(state->V[ch][offset[k] + 1], sbc_proto_8_80m1[idx + 0],
			MULA(state->V[ch][offset[i] + 2], sbc_proto_8_80m0[idx + 1],
			MULA(state->V[ch][offset[k] + 3], sbc_proto_8_80m1[idx + 1],
			MULA(state->V[ch][offset[i] + 4], sbc_proto_8_80m0[idx + 2],
			MULA(state->V[ch][offset[k] + 5], sbc_proto_8_80m1[idx + 2],
			MULA(state->V[ch][offset[i] + 6], sbc_proto_8_80m0[idx + 3],
			MULA(state->V[ch][offset[k] + 7], sbc_proto_8_80m1[idx + 3],
			MULA(state->V[ch][offset[i] + 8], sbc_proto_8_80m0[idx + 4],
			MUL( state->V[ch][offset[k] + 9], sbc_proto_8_80m1[idx + 4]))))))))))));
	}
}

static int sbc_synthesize_audio(struct sbc_decoder_state *state,
						struct sbc_frame *frame)
{
	int ch, blk;

	switch (frame->subbands) {
	case 4:
		for (ch = 0; ch < frame->channels; ch++) {
			for (blk = 0; blk < frame->blocks; blk++)
				sbc_synthesize_four(state, frame, ch, blk);
		}
		return frame->blocks * 4;

	case 8:
		for (ch = 0; ch < frame->channels; ch++) {
			for (blk = 0; blk < frame->blocks; blk++)
				sbc_synthesize_eight(state, frame, ch, blk);
		}
		return frame->blocks * 8;

	default:
		return -EIO;
	}
}

static int sbc_analyze_audio(struct sbc_encoder_state *state,
						struct sbc_frame *frame)
{
	int ch, blk;
	int16_t *x;

	switch (frame->subbands) {
	case 4:
		for (ch = 0; ch < frame->channels; ch++) {
			x = &state->X[ch][state->position - 16 +
							frame->blocks * 4];
			for (blk = 0; blk < frame->blocks; blk += 4) {
				state->sbc_analyze_4b_4s(
					x,
					frame->sb_sample_f[blk][ch],
					frame->sb_sample_f[blk + 1][ch] -
					frame->sb_sample_f[blk][ch]);
				x -= 16;
			}
		}
		return frame->blocks * 4;

	case 8:
		for (ch = 0; ch < frame->channels; ch++) {
			x = &state->X[ch][state->position - 32 +
							frame->blocks * 8];
			for (blk = 0; blk < frame->blocks; blk += 4) {
				state->sbc_analyze_4b_8s(
					x,
					frame->sb_sample_f[blk][ch],
					frame->sb_sample_f[blk + 1][ch] -
					frame->sb_sample_f[blk][ch]);
				x -= 32;
			}
		}
		return frame->blocks * 8;

	default:
		return -EIO;
	}
}

/* Supplementary bitstream writing macros for 'sbc_pack_frame' */

#define PUT_BITS(data_ptr, bits_cache, bits_count, v, n)		\
	do {								\
		bits_cache = (v) | (bits_cache << (n));			\
		bits_count += (n);					\
		if (bits_count >= 16) {					\
			bits_count -= 8;				\
			*data_ptr++ = (uint8_t)				\
				(bits_cache >> bits_count);		\
			bits_count -= 8;				\
			*data_ptr++ = (uint8_t)				\
				(bits_cache >> bits_count);		\
		}							\
	} while (0)

#define FLUSH_BITS(data_ptr, bits_cache, bits_count)			\
	do {								\
		while (bits_count >= 8) {				\
			bits_count -= 8;				\
			*data_ptr++ = (uint8_t)				\
				(bits_cache >> bits_count);		\
		}							\
		if (bits_count > 0)					\
			*data_ptr++ = (uint8_t)				\
				(bits_cache << (8 - bits_count));	\
	} while (0)

/*
 * Packs the SBC frame from frame into the memory at data. At most len
 * bytes will be used, should more memory be needed an appropriate
 * error code will be returned. Returns the length of the packed frame
 * on success or a negative value on error.
 *
 * The error codes are:
 * -1 Not enough memory reserved
 * -2 Unsupported sampling rate
 * -3 Unsupported number of blocks
 * -4 Unsupported number of subbands
 * -5 Bitpool value out of bounds
 * -99 not implemented
 */

static SBC_ALWAYS_INLINE ssize_t sbc_pack_frame_internal(uint8_t *data,
					struct sbc_frame *frame, size_t len,
					int frame_subbands, int frame_channels,
					int joint)
{
	/* Bitstream writer starts from the fourth byte */
	uint8_t *data_ptr = data + 4;
	uint32_t bits_cache = 0;
	uint32_t bits_count = 0;

	/* Will copy the header parts for CRC-8 calculation here */
	uint8_t crc_header[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	int crc_pos = 0;

	uint32_t audio_sample;

	int ch, sb, blk;	/* channel, subband, block and bit counters */
	int bits[2][8];		/* bits distribution */
	uint32_t levels[2][8];	/* levels are derived from that */
	uint32_t sb_sample_delta[2][8];

	data[0] = SBC_SYNCWORD;

	data[1] = (frame->frequency & 0x03) << 6;

	data[1] |= (frame->block_mode & 0x03) << 4;

	data[1] |= (frame->mode & 0x03) << 2;

	data[1] |= (frame->allocation & 0x01) << 1;

	switch (frame_subbands) {
	case 4:
		/* Nothing to do */
		break;
	case 8:
		data[1] |= 0x01;
		break;
	default:
		return -4;
		break;
	}

	data[2] = frame->bitpool;

	if ((frame->mode == MONO || frame->mode == DUAL_CHANNEL) &&
			frame->bitpool > frame_subbands << 4)
		return -5;

	if ((frame->mode == STEREO || frame->mode == JOINT_STEREO) &&
			frame->bitpool > frame_subbands << 5)
		return -5;

	/* Can't fill in crc yet */

	crc_header[0] = data[1];
	crc_header[1] = data[2];
	crc_pos = 16;

	if (frame->mode == JOINT_STEREO) {
		PUT_BITS(data_ptr, bits_cache, bits_count,
			joint, frame_subbands);
		crc_header[crc_pos >> 3] = joint;
		crc_pos += frame_subbands;
	}

	for (ch = 0; ch < frame_channels; ch++) {
		for (sb = 0; sb < frame_subbands; sb++) {
			PUT_BITS(data_ptr, bits_cache, bits_count,
				frame->scale_factor[ch][sb] & 0x0F, 4);
			crc_header[crc_pos >> 3] <<= 4;
			crc_header[crc_pos >> 3] |= frame->scale_factor[ch][sb] & 0x0F;
			crc_pos += 4;
		}
	}

	/* align the last crc byte */
	if (crc_pos % 8)
		crc_header[crc_pos >> 3] <<= 8 - (crc_pos % 8);

	data[3] = sbc_crc8(crc_header, crc_pos);

	sbc_calculate_bits(frame, bits);

	for (ch = 0; ch < frame_channels; ch++) {
		for (sb = 0; sb < frame_subbands; sb++) {
			levels[ch][sb] = ((1 << bits[ch][sb]) - 1) <<
				(32 - (frame->scale_factor[ch][sb] +
					SCALE_OUT_BITS + 2));
			sb_sample_delta[ch][sb] = (uint32_t) 1 <<
				(frame->scale_factor[ch][sb] +
					SCALE_OUT_BITS + 1);
		}
	}

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame_channels; ch++) {
			for (sb = 0; sb < frame_subbands; sb++) {

				if (bits[ch][sb] == 0)
					continue;

				audio_sample = ((uint64_t) levels[ch][sb] *
					(sb_sample_delta[ch][sb] +
					frame->sb_sample_f[blk][ch][sb])) >> 32;

				PUT_BITS(data_ptr, bits_cache, bits_count,
					audio_sample, bits[ch][sb]);
			}
		}
	}

	FLUSH_BITS(data_ptr, bits_cache, bits_count);

	return data_ptr - data;
}

static ssize_t sbc_pack_frame(uint8_t *data, struct sbc_frame *frame, size_t len,
								int joint)
{
	if (frame->subbands == 4) {
		if (frame->channels == 1)
			return sbc_pack_frame_internal(
				data, frame, len, 4, 1, joint);
		else
			return sbc_pack_frame_internal(
				data, frame, len, 4, 2, joint);
	} else {
		if (frame->channels == 1)
			return sbc_pack_frame_internal(
				data, frame, len, 8, 1, joint);
		else
			return sbc_pack_frame_internal(
				data, frame, len, 8, 2, joint);
	}
}

static void sbc_encoder_init(struct sbc_encoder_state *state,
					const struct sbc_frame *frame)
{
	memset(&state->X, 0, sizeof(state->X));
	state->position = (SBC_X_BUFFER_SIZE - frame->subbands * 9) & ~7;

	sbc_init_primitives(state);
}

struct sbc_priv {
	int init;
	struct SBC_ALIGNED sbc_frame frame;
	struct SBC_ALIGNED sbc_decoder_state dec_state;
	struct SBC_ALIGNED sbc_encoder_state enc_state;
};

static void sbc_set_defaults(sbc_t *sbc, unsigned long flags)
{
	sbc->frequency = SBC_FREQ_44100;
	sbc->mode = SBC_MODE_STEREO;
	sbc->subbands = SBC_SB_8;
	sbc->blocks = SBC_BLK_16;
	sbc->bitpool = 32;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	sbc->endian = SBC_LE;
#elif __BYTE_ORDER == __BIG_ENDIAN
	sbc->endian = SBC_BE;
#else
#error "Unknown byte order"
#endif
}

int sbc_init(sbc_t *sbc, unsigned long flags)
{
	if (!sbc)
		return -EIO;

	memset(sbc, 0, sizeof(sbc_t));

	sbc->priv_alloc_base = malloc(sizeof(struct sbc_priv) + SBC_ALIGN_MASK);
	if (!sbc->priv_alloc_base)
		return -ENOMEM;

	sbc->priv = (void *) (((uintptr_t) sbc->priv_alloc_base +
			SBC_ALIGN_MASK) & ~((uintptr_t) SBC_ALIGN_MASK));

	memset(sbc->priv, 0, sizeof(struct sbc_priv));

	sbc_set_defaults(sbc, flags);

	return 0;
}

ssize_t sbc_parse(sbc_t *sbc, const void *input, size_t input_len)
{
	return sbc_decode(sbc, input, input_len, NULL, 0, NULL);
}

ssize_t sbc_decode(sbc_t *sbc, const void *input, size_t input_len,
			void *output, size_t output_len, size_t *written)
{
	struct sbc_priv *priv;
	char *ptr;
	int i, ch, framelen, samples;

	if (!sbc || !input)
		return -EIO;

	priv = sbc->priv;

	framelen = sbc_unpack_frame(input, &priv->frame, input_len);

	if (!priv->init) {
		sbc_decoder_init(&priv->dec_state, &priv->frame);
		priv->init = 1;

		sbc->frequency = priv->frame.frequency;
		sbc->mode = priv->frame.mode;
		sbc->subbands = priv->frame.subband_mode;
		sbc->blocks = priv->frame.block_mode;
		sbc->allocation = priv->frame.allocation;
		sbc->bitpool = priv->frame.bitpool;

		priv->frame.codesize = sbc_get_codesize(sbc);
		priv->frame.length = framelen;
	} else if (priv->frame.bitpool != sbc->bitpool) {
		priv->frame.length = framelen;
		sbc->bitpool = priv->frame.bitpool;
	}

	if (!output)
		return framelen;

	if (written)
		*written = 0;

	if (framelen <= 0)
		return framelen;

	samples = sbc_synthesize_audio(&priv->dec_state, &priv->frame);

	ptr = output;

	if (output_len < (size_t) (samples * priv->frame.channels * 2))
		samples = output_len / (priv->frame.channels * 2);

	for (i = 0; i < samples; i++) {
		for (ch = 0; ch < priv->frame.channels; ch++) {
			int16_t s;
			s = priv->frame.pcm_sample[ch][i];

			if (sbc->endian == SBC_BE) {
				*ptr++ = (s & 0xff00) >> 8;
				*ptr++ = (s & 0x00ff);
			} else {
				*ptr++ = (s & 0x00ff);
				*ptr++ = (s & 0xff00) >> 8;
			}
		}
	}

	if (written)
		*written = samples * priv->frame.channels * 2;

	return framelen;
}

ssize_t sbc_encode(sbc_t *sbc, const void *input, size_t input_len,
			void *output, size_t output_len, ssize_t *written)
{
	struct sbc_priv *priv;
	int samples;
	ssize_t framelen;
	int (*sbc_enc_process_input)(int position,
			const uint8_t *pcm, int16_t X[2][SBC_X_BUFFER_SIZE],
			int nsamples, int nchannels);

	if (!sbc || !input)
		return -EIO;

	priv = sbc->priv;

	if (written)
		*written = 0;

	if (!priv->init) {
		priv->frame.frequency = sbc->frequency;
		priv->frame.mode = sbc->mode;
		priv->frame.channels = sbc->mode == SBC_MODE_MONO ? 1 : 2;
		priv->frame.allocation = sbc->allocation;
		priv->frame.subband_mode = sbc->subbands;
		priv->frame.subbands = sbc->subbands ? 8 : 4;
		priv->frame.block_mode = sbc->blocks;
		priv->frame.blocks = 4 + (sbc->blocks * 4);
		priv->frame.bitpool = sbc->bitpool;
		priv->frame.codesize = sbc_get_codesize(sbc);
		priv->frame.length = sbc_get_frame_length(sbc);

		sbc_encoder_init(&priv->enc_state, &priv->frame);
		priv->init = 1;
	} else if (priv->frame.bitpool != sbc->bitpool) {
		priv->frame.length = sbc_get_frame_length(sbc);
		priv->frame.bitpool = sbc->bitpool;
	}

	/* input must be large enough to encode a complete frame */
	if (input_len < priv->frame.codesize)
		return 0;

	/* output must be large enough to receive the encoded frame */
	if (!output || output_len < priv->frame.length)
		return -ENOSPC;

	/* Select the needed input data processing function and call it */
	if (priv->frame.subbands == 8) {
		if (sbc->endian == SBC_BE)
			sbc_enc_process_input =
				priv->enc_state.sbc_enc_process_input_8s_be;
		else
			sbc_enc_process_input =
				priv->enc_state.sbc_enc_process_input_8s_le;
	} else {
		if (sbc->endian == SBC_BE)
			sbc_enc_process_input =
				priv->enc_state.sbc_enc_process_input_4s_be;
		else
			sbc_enc_process_input =
				priv->enc_state.sbc_enc_process_input_4s_le;
	}

	priv->enc_state.position = sbc_enc_process_input(
		priv->enc_state.position, (const uint8_t *) input,
		priv->enc_state.X, priv->frame.subbands * priv->frame.blocks,
		priv->frame.channels);

	samples = sbc_analyze_audio(&priv->enc_state, &priv->frame);

	if (priv->frame.mode == JOINT_STEREO) {
		int j = priv->enc_state.sbc_calc_scalefactors_j(
			priv->frame.sb_sample_f, priv->frame.scale_factor,
			priv->frame.blocks, priv->frame.subbands);
		framelen = sbc_pack_frame(output, &priv->frame, output_len, j);
	} else {
		priv->enc_state.sbc_calc_scalefactors(
			priv->frame.sb_sample_f, priv->frame.scale_factor,
			priv->frame.blocks, priv->frame.channels,
			priv->frame.subbands);
		framelen = sbc_pack_frame(output, &priv->frame, output_len, 0);
	}

	if (written)
		*written = framelen;

	return samples * priv->frame.channels * 2;
}

void sbc_finish(sbc_t *sbc)
{
	if (!sbc)
		return;

	free(sbc->priv_alloc_base);

	memset(sbc, 0, sizeof(sbc_t));
}

size_t sbc_get_frame_length(sbc_t *sbc)
{
	int ret;
	uint8_t subbands, channels, blocks, joint, bitpool;
	struct sbc_priv *priv;

	priv = sbc->priv;
	if (priv->init && priv->frame.bitpool == sbc->bitpool)
		return priv->frame.length;

	subbands = sbc->subbands ? 8 : 4;
	blocks = 4 + (sbc->blocks * 4);
	channels = sbc->mode == SBC_MODE_MONO ? 1 : 2;
	joint = sbc->mode == SBC_MODE_JOINT_STEREO ? 1 : 0;
	bitpool = sbc->bitpool;

	ret = 4 + (4 * subbands * channels) / 8;
	/* This term is not always evenly divide so we round it up */
	if (channels == 1)
		ret += ((blocks * channels * bitpool) + 7) / 8;
	else
		ret += (((joint ? subbands : 0) + blocks * bitpool) + 7) / 8;

	return ret;
}

unsigned sbc_get_frame_duration(sbc_t *sbc)
{
	uint8_t subbands, blocks;
	uint16_t frequency;
	struct sbc_priv *priv;

	priv = sbc->priv;
	if (!priv->init) {
		subbands = sbc->subbands ? 8 : 4;
		blocks = 4 + (sbc->blocks * 4);
	} else {
		subbands = priv->frame.subbands;
		blocks = priv->frame.blocks;
	}

	switch (sbc->frequency) {
	case SBC_FREQ_16000:
		frequency = 16000;
		break;

	case SBC_FREQ_32000:
		frequency = 32000;
		break;

	case SBC_FREQ_44100:
		frequency = 44100;
		break;

	case SBC_FREQ_48000:
		frequency = 48000;
		break;
	default:
		return 0;
	}

	return (1000000 * blocks * subbands) / frequency;
}

size_t sbc_get_codesize(sbc_t *sbc)
{
	uint16_t subbands, channels, blocks;
	struct sbc_priv *priv;

	priv = sbc->priv;
	if (!priv->init) {
		subbands = sbc->subbands ? 8 : 4;
		blocks = 4 + (sbc->blocks * 4);
		channels = sbc->mode == SBC_MODE_MONO ? 1 : 2;
	} else {
		subbands = priv->frame.subbands;
		blocks = priv->frame.blocks;
		channels = priv->frame.channels;
	}

	return subbands * blocks * channels * 2;
}

const char *sbc_get_implementation_info(sbc_t *sbc)
{
	struct sbc_priv *priv;

	if (!sbc)
		return NULL;

	priv = sbc->priv;
	if (!priv)
		return NULL;

	return priv->enc_state.implementation_info;
}

int sbc_reinit(sbc_t *sbc, unsigned long flags)
{
	struct sbc_priv *priv;

	if (!sbc || !sbc->priv)
		return -EIO;

	priv = sbc->priv;

	if (priv->init == 1)
		memset(sbc->priv, 0, sizeof(struct sbc_priv));

	sbc_set_defaults(sbc, flags);

	return 0;
}
