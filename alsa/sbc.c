/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2004-2005  Henryk Ploetz <henryk@ploetzli.ch>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>

#include "sbc.h"

/* A2DP specification: Appendix B, page 69 */
static const int sbc_offset4[4][4] = {
	{ -1, 0, 0, 0 },
	{ -2, 0, 0, 1 },
	{ -2, 0, 0, 1 },
	{ -2, 0, 0, 1 }
};

/* A2DP specification: Appendix B, page 69 */
static const int sbc_offset8[4][8] = {
	{ -2, 0, 0, 0, 0, 0, 0, 1 },
	{ -3, 0, 0, 0, 0, 0, 1, 2 },
	{ -4, 0, 0, 0, 0, 0, 1, 2 },
	{ -4, 0, 0, 0, 0, 0, 1, 2 }
};

/* A2DP specification: Appendix B, page 70 */
static const float sbc_proto_4_40[40] = {
	 0.00000000E+00,  5.36548976E-04,  1.49188357E-03,  2.73370904E-03,
	 3.83720193E-03,  3.89205149E-03,  1.86581691E-03, -3.06012286E-03,
	 1.09137620E-02,  2.04385087E-02,  2.88757392E-02,  3.21939290E-02,
	 2.58767811E-02,  6.13245186E-03, -2.88217274E-02, -7.76463494E-02,
	 1.35593274E-01,  1.94987841E-01,  2.46636662E-01,  2.81828203E-01,
	 2.94315332E-01,  2.81828203E-01,  2.46636662E-01,  1.94987841E-01,
	-1.35593274E-01, -7.76463494E-02, -2.88217274E-02,  6.13245186E-03,
	 2.58767811E-02,  3.21939290E-02,  2.88757392E-02,  2.04385087E-02,
	-1.09137620E-02, -3.06012286E-03,  1.86581691E-03,  3.89205149E-03,
	 3.83720193E-03,  2.73370904E-03,  1.49188357E-03,  5.36548976E-04
};

/* A2DP specification: Appendix B, page 70 */
static const float sbc_proto_8_80[80] = {
	 0.00000000E+00,  1.56575398E-04,  3.43256425E-04,  5.54620202E-04,
	 8.23919506E-04,  1.13992507E-03,  1.47640169E-03,  1.78371725E-03,
	 2.01182542E-03,  2.10371989E-03,  1.99454554E-03,  1.61656283E-03,
	 9.02154502E-04, -1.78805361E-04, -1.64973098E-03, -3.49717454E-03,
	 5.65949473E-03,  8.02941163E-03,  1.04584443E-02,  1.27472335E-02,
	 1.46525263E-02,  1.59045603E-02,  1.62208471E-02,  1.53184106E-02,
	 1.29371806E-02,  8.85757540E-03,  2.92408442E-03, -4.91578024E-03,
	-1.46404076E-02, -2.61098752E-02, -3.90751381E-02, -5.31873032E-02,
	 6.79989431E-02,  8.29847578E-02,  9.75753918E-02,  1.11196689E-01,
	 1.23264548E-01,  1.33264415E-01,  1.40753505E-01,  1.45389847E-01,
	 1.46955068E-01,  1.45389847E-01,  1.40753505E-01,  1.33264415E-01,
	 1.23264548E-01,  1.11196689E-01,  9.75753918E-02,  8.29847578E-02,
	-6.79989431E-02, -5.31873032E-02, -3.90751381E-02, -2.61098752E-02,
	-1.46404076E-02, -4.91578024E-03,  2.92408442E-03,  8.85757540E-03,
	 1.29371806E-02,  1.53184106E-02,  1.62208471E-02,  1.59045603E-02,
	 1.46525263E-02,  1.27472335E-02,  1.04584443E-02,  8.02941163E-03,
	-5.65949473E-03, -3.49717454E-03, -1.64973098E-03, -1.78805361E-04,
	 9.02154502E-04,  1.61656283E-03,  1.99454554E-03,  2.10371989E-03,
	 2.01182542E-03,  1.78371725E-03,  1.47640169E-03,  1.13992507E-03,
	 8.23919506E-04,  5.54620202E-04,  3.43256425E-04,  1.56575398E-04
};

/* Precomputed: synmatrix4[k][i] = cos( (i+0.5) * (k+2.0) * pi/4.0 ) */
static const float synmatrix4[8][4] =  {
	{  0.707106781186548, -0.707106781186547, -0.707106781186548,  0.707106781186547 },
	{  0.38268343236509,  -0.923879532511287,  0.923879532511287, -0.38268343236509  },
	{  0,                  0,                  0,                  0                 },
	{ -0.38268343236509,   0.923879532511287, -0.923879532511287,  0.382683432365091 },
	{ -0.707106781186547,  0.707106781186548,  0.707106781186547, -0.707106781186547 },
	{ -0.923879532511287, -0.38268343236509,   0.382683432365091,  0.923879532511288 },
	{ -1,                 -1,                 -1,                 -1                 },
	{ -0.923879532511287, -0.382683432365091,  0.38268343236509,   0.923879532511287 }
};

/* Precomputed: synmatrix8[k][i] = cos( (i+0.5) * (k+4.0) * pi/8.0 ) */
static const float synmatrix8[16][8] = {
	{  0.707106781186548, -0.707106781186547, -0.707106781186548,  0.707106781186547,
	   0.707106781186548, -0.707106781186547, -0.707106781186547,  0.707106781186547 },
	{  0.555570233019602, -0.98078528040323,   0.195090322016128,  0.831469612302545,
	  -0.831469612302545, -0.195090322016128,  0.980785280403231, -0.555570233019602 },
	{  0.38268343236509,  -0.923879532511287,  0.923879532511287, -0.38268343236509,
	  -0.382683432365091,  0.923879532511287, -0.923879532511286,  0.38268343236509  },
	{  0.195090322016128, -0.555570233019602,  0.831469612302545, -0.980785280403231,
	   0.98078528040323,  -0.831469612302545,  0.555570233019602, -0.195090322016129 },
	{  0,                  0,                  0,                  0,
	   0,                  0,                  0,                  0                 },
	{ -0.195090322016128,  0.555570233019602, -0.831469612302545,  0.98078528040323,
	  -0.980785280403231,  0.831469612302545, -0.555570233019603,  0.19509032201613  },
	{ -0.38268343236509,   0.923879532511287, -0.923879532511287,  0.382683432365091,
	   0.38268343236509,  -0.923879532511287,  0.923879532511288, -0.382683432365091 },
	{ -0.555570233019602,  0.98078528040323,  -0.195090322016128, -0.831469612302545,
	   0.831469612302545,  0.195090322016128, -0.98078528040323,   0.555570233019606 },
	{ -0.707106781186547,  0.707106781186548,  0.707106781186547, -0.707106781186547,
	  -0.707106781186546,  0.707106781186548,  0.707106781186546, -0.707106781186548 },
	{ -0.831469612302545,  0.195090322016129,  0.980785280403231,  0.555570233019602,
	  -0.555570233019603, -0.98078528040323,  -0.195090322016128,  0.831469612302547 },
	{ -0.923879532511287, -0.38268343236509,   0.382683432365091,  0.923879532511288,
	   0.923879532511287,  0.382683432365089, -0.382683432365091, -0.923879532511287 },
	{ -0.98078528040323,  -0.831469612302545, -0.555570233019602, -0.195090322016129,
	   0.19509032201613,   0.555570233019606,  0.831469612302547,  0.980785280403231 },
	{ -1,                 -1,                 -1,                 -1,
	  -1,                 -1,                 -1,                 -1                 },
	{ -0.98078528040323,  -0.831469612302546, -0.555570233019603, -0.19509032201613,
	   0.195090322016128,  0.555570233019604,  0.831469612302545,  0.98078528040323  },
	{ -0.923879532511287, -0.382683432365091,  0.38268343236509,   0.923879532511287,
	   0.923879532511288,  0.382683432365088, -0.382683432365089, -0.923879532511285 },
	{ -0.831469612302545,  0.195090322016127,  0.98078528040323,   0.555570233019603,
	  -0.555570233019601, -0.98078528040323,  -0.195090322016131,  0.831469612302545 }
};

/* Precomputed: anamatrix4[i][k] = cos( (i+0.5) * (k-2) * pi/4 ) */
static const float anamatrix4[4][8] = {
	{  0.707106781186548,  0.923879532511287,  1,                  0.923879532511287,
	   0.707106781186548,  0.38268343236509,   0,                 -0.38268343236509  },
	{ -0.707106781186547,  0.38268343236509,   1,                  0.38268343236509,
	  -0.707106781186547, -0.923879532511287,  0,                  0.923879532511287 },
	{ -0.707106781186548, -0.38268343236509,   1,                 -0.38268343236509,
	  -0.707106781186548,  0.923879532511287,  0,                 -0.923879532511287 },
	{  0.707106781186547, -0.923879532511287,  1,                 -0.923879532511287,
	   0.707106781186547, -0.38268343236509,   0,                  0.382683432365091 }
};

/* Precomputed: anamatrix8[i][k] = cos( (i+0.5) * (k-4) * pi/8) */
static const float anamatrix8[8][16] = {
	{  0.923879532511287,  0.98078528040323,   1,                  0.98078528040323,
	   0.923879532511287,  0.831469612302545,  0.707106781186548,  0.555570233019602,
	   0.38268343236509,   0.195090322016128,  0,                 -0.195090322016128,
	  -0.38268343236509,  -0.555570233019602, -0.707106781186547, -0.831469612302545 },
	{  0.38268343236509,   0.831469612302545,  1,                  0.831469612302545,
	   0.38268343236509,  -0.195090322016128, -0.707106781186547, -0.98078528040323,
	  -0.923879532511287, -0.555570233019602,  0,                  0.555570233019602,
	   0.923879532511287,  0.98078528040323,   0.707106781186548,  0.195090322016129 },
	{ -0.38268343236509,   0.555570233019602,  1,                  0.555570233019602,
	  -0.38268343236509,  -0.98078528040323,  -0.707106781186548,  0.195090322016128,
	   0.923879532511287,  0.831469612302545,  0,                 -0.831469612302545,
	  -0.923879532511287, -0.195090322016128,  0.707106781186547,  0.980785280403231 },
	{ -0.923879532511287,  0.195090322016128,  1,                  0.195090322016128,
	  -0.923879532511287, -0.555570233019602,  0.707106781186547,  0.831469612302545,
	  -0.38268343236509,  -0.980785280403231,  0,                  0.98078528040323,
	   0.382683432365091, -0.831469612302545, -0.707106781186547,  0.555570233019602 },
	{ -0.923879532511287, -0.195090322016128,  1,                 -0.195090322016128,
	  -0.923879532511287,  0.555570233019602,  0.707106781186548, -0.831469612302545,
	  -0.382683432365091,  0.98078528040323,   0,                 -0.980785280403231,
	   0.38268343236509,   0.831469612302545, -0.707106781186546, -0.555570233019603 },
	{ -0.38268343236509,  -0.555570233019602,  1,                 -0.555570233019602,
	  -0.38268343236509,   0.98078528040323,  -0.707106781186547, -0.195090322016128,
	   0.923879532511287, -0.831469612302545,  0,                  0.831469612302545,
	  -0.923879532511287,  0.195090322016128,  0.707106781186548, -0.98078528040323  },
	{  0.38268343236509,  -0.831469612302545,  1,                 -0.831469612302545,
	   0.38268343236509,   0.195090322016129, -0.707106781186547,  0.980785280403231,
	  -0.923879532511286,  0.555570233019602,  0,                 -0.555570233019603,
	   0.923879532511288, -0.98078528040323,   0.707106781186546, -0.195090322016128 },
	{  0.923879532511287, -0.98078528040323,   1,                 -0.98078528040323,
	   0.923879532511287, -0.831469612302545,  0.707106781186547, -0.555570233019602,
	   0.38268343236509,  -0.195090322016129,  0,                  0.19509032201613,
	  -0.382683432365091,  0.555570233019606, -0.707106781186548,  0.831469612302547 }
};

#define fabs(x) ((x) < 0 ? (-x) : (x))

#define SBC_SYNCWORD 0x9C

/* sampling frequency */
#define SBC_FS_16	0x00
#define SBC_FS_32	0x01
#define SBC_FS_44	0x02
#define SBC_FS_48	0x03

/* nrof_blocks */
#define SBC_NB_4	0x00
#define SBC_NB_8	0x01
#define SBC_NB_12	0x02
#define SBC_NB_16	0x03

/* channel mode */
#define SBC_CM_MONO		0x00
#define SBC_CM_DUAL_CHANNEL	0x01
#define SBC_CM_STEREO		0x02
#define SBC_CM_JOINT_STEREO	0x03

/* allocation mode */
#define SBC_AM_LOUDNESS		0x00
#define SBC_AM_SNR		0x01

/* subbands */
#define SBC_SB_4	0x00
#define SBC_SB_8	0x01

/* This structure contains an unpacked SBC frame. 
   Yes, there is probably quite some unused space herein */
struct sbc_frame {
	double sampling_frequency;	/* in kHz */
	u_int8_t blocks;
	enum {
		MONO		= SBC_CM_MONO,
		DUAL_CHANNEL	= SBC_CM_DUAL_CHANNEL,
		STEREO		= SBC_CM_STEREO,
		JOINT_STEREO	= SBC_CM_JOINT_STEREO
	} channel_mode;
	u_int8_t channels;
	enum {
		LOUDNESS	= SBC_AM_LOUDNESS,
		SNR		= SBC_AM_SNR
	} allocation_method;
	u_int8_t subbands;
	u_int8_t bitpool;
	u_int8_t join;				/* bit number x set means joint stereo has been used in subband x */
	u_int8_t scale_factor[2][8];		/* only the lower 4 bits of every element are to be used */
	u_int16_t audio_sample[16][2][8];	/* raw integer subband samples in the frame */
	double sb_sample[16][2][8];		/* modified subband samples */
	double pcm_sample[2][16*8];		/* original pcm audio samples */
};

struct sbc_decoder_state {
	int subbands;
	float S[2][8];				/* Subband samples */
	float X[2][8];				/* Audio samples */
	float V[2][160], U[2][80], W[2][80];	/* Vectors */
};

struct sbc_encoder_state {
	int subbands;
	float S[2][8];				/* Subband samples */
	float X[2][80], Y[2][16], Z[2][80];	/* Vectors */
};

/*
 * Calculates the CRC-8 of the first len bits in data
 */
static const u_int8_t crc_table[256] = {
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

static u_int8_t sbc_crc8(const u_int8_t * data, size_t len)
{
	u_int8_t crc = 0x0f;
	size_t i;
	u_int8_t octet;

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
 * Takes a pointer to the frame in question, a pointer to the bits array and the sampling frequency (as 2 bit integer)
 */
static void sbc_calculate_bits(const struct sbc_frame *frame, int (*bits)[8], u_int8_t sf)
{
	if (frame->channel_mode == MONO || frame->channel_mode == DUAL_CHANNEL) {
		int bitneed[2][8], loudness, max_bitneed, bitcount, slicecount, bitslice;
		int ch, sb;

		for (ch = 0; ch < frame->channels; ch++) {
			if (frame->allocation_method == SNR) {
				for (sb = 0; sb < frame->subbands; sb++) {
					bitneed[ch][sb] = frame->scale_factor[ch][sb];
				}
			} else {
				for (sb = 0; sb < frame->subbands; sb++) {
					if (frame->scale_factor[ch][sb] == 0) {
						bitneed[ch][sb] = -5;
					} else {
						if (frame->subbands == 4) {
							loudness = frame->scale_factor[ch][sb] - sbc_offset4[sf][sb];
						} else {
							loudness = frame->scale_factor[ch][sb] - sbc_offset8[sf][sb];
						}
						if (loudness > 0) {
							bitneed[ch][sb] = loudness / 2;
						} else {
							bitneed[ch][sb] = loudness;
						}
					}
				}
			}

			max_bitneed = 0;
			for (sb = 0; sb < frame->subbands; sb++) {
				if (bitneed[ch][sb] > max_bitneed)
					max_bitneed = bitneed[ch][sb];
			}

			bitcount = 0;
			slicecount = 0;
			bitslice = max_bitneed + 1;
			do {
				bitslice--;
				bitcount += slicecount;
				slicecount = 0;
				for (sb = 0; sb < frame->subbands; sb++) {
					if ((bitneed[ch][sb] > bitslice + 1) && (bitneed[ch][sb] < bitslice + 16)) {
						slicecount++;
					} else if (bitneed[ch][sb] == bitslice + 1) {
						slicecount += 2;
					}
				}
			} while (bitcount + slicecount < frame->bitpool);

			if (bitcount + slicecount == frame->bitpool) {
				bitcount += slicecount;
				bitslice--;
			}

			for (sb = 0; sb < frame->subbands; sb++) {
				if (bitneed[ch][sb] < bitslice + 2) {
					bits[ch][sb] = 0;
				} else {
					bits[ch][sb] = bitneed[ch][sb] - bitslice;
					if (bits[ch][sb] > 16)
						bits[ch][sb] = 16;
				}
			}

			sb = 0;
			while (bitcount < frame->bitpool && sb < frame->subbands) {
				if ((bits[ch][sb] >= 2) && (bits[ch][sb] < 16)) {
					bits[ch][sb]++;
					bitcount++;
				} else if ((bitneed[ch][sb] == bitslice + 1) && (frame->bitpool > bitcount + 1)) {
					bits[ch][sb] = 2;
					bitcount += 2;
				}
				sb++;
			}

			sb = 0;
			while (bitcount < frame->bitpool && sb < frame->subbands) {
				if (bits[ch][sb] < 16) {
					bits[ch][sb]++;
					bitcount++;
				}
				sb++;
			}

		}

	} else if (frame->channel_mode == STEREO || frame->channel_mode == JOINT_STEREO) {
		int bitneed[2][8], loudness, max_bitneed, bitcount, slicecount, bitslice;
		int ch, sb;

		if (frame->allocation_method == SNR) {
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < frame->subbands; sb++) {
					bitneed[ch][sb] = frame->scale_factor[ch][sb];
				}
			}
		} else {
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < frame->subbands; sb++) {
					if (frame->scale_factor[ch][sb] == 0) {
						bitneed[ch][sb] = -5;
					} else {
						if (frame->subbands == 4) {
							loudness = frame->scale_factor[ch][sb] - sbc_offset4[sf][sb];
						} else {
							loudness = frame->scale_factor[ch][sb] - sbc_offset8[sf][sb];
						}
						if (loudness > 0) {
							bitneed[ch][sb] = loudness / 2;
						} else {
							bitneed[ch][sb] = loudness;
						}
					}
				}
			}
		}

		max_bitneed = 0;
		for (ch = 0; ch < 2; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
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
			for (ch = 0; ch < 2; ch++) {
				for (sb = 0; sb < frame->subbands; sb++) {
					if ((bitneed[ch][sb] > bitslice + 1) && (bitneed[ch][sb] < bitslice + 16)) {
						slicecount++;
					} else if (bitneed[ch][sb] == bitslice + 1) {
						slicecount += 2;
					}
				}
			}
		} while (bitcount + slicecount < frame->bitpool);
		if (bitcount + slicecount == frame->bitpool) {
			bitcount += slicecount;
			bitslice--;
		}

		for (ch = 0; ch < 2; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
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
		while ((bitcount < frame->bitpool) && (sb < frame->subbands)) {
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
			} else {
				ch = 1;
			}
		}

		ch = 0;
		sb = 0;
		while ((bitcount < frame->bitpool) && (sb < frame->subbands)) {
			if (bits[ch][sb] < 16) {
				bits[ch][sb]++;
				bitcount++;
			}
			if (ch == 1) {
				ch = 0;
				sb++;
			} else {
				ch = 1;
			}
		}

	}

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
static int sbc_unpack_frame(const u_int8_t * data, struct sbc_frame *frame, size_t len)
{
	int consumed;
	/* Will copy the parts of the header that are relevant to crc calculation here */
	u_int8_t crc_header[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	int crc_pos = 0;

	u_int8_t sf;		/* sampling_frequency, temporarily needed as array index */

	int ch, sb, blk, bit;	/* channel, subband, block and bit standard counters */
	int bits[2][8];		/* bits distribution */
	int levels[2][8];	/* levels derived from that */

	double scalefactor[2][8];	/* derived from frame->scale_factors */

	if (len < 4) {
		return -1;
	}

	if (data[0] != SBC_SYNCWORD) {
		return -2;
	}

	sf = (data[1] >> 6) & 0x03;
	switch (sf) {
	case SBC_FS_16:
		frame->sampling_frequency = 16;
		break;
	case SBC_FS_32:
		frame->sampling_frequency = 32;
		break;
	case SBC_FS_44:
		frame->sampling_frequency = 44.1;
		break;
	case SBC_FS_48:
		frame->sampling_frequency = 48;
		break;
	}

	switch ((data[1] >> 4) & 0x03) {
	case SBC_NB_4:
		frame->blocks = 4;
		break;
	case SBC_NB_8:
		frame->blocks = 8;
		break;
	case SBC_NB_12:
		frame->blocks = 12;
		break;
	case SBC_NB_16:
		frame->blocks = 16;
		break;
	}

	frame->channel_mode = (data[1] >> 2) & 0x03;
	switch (frame->channel_mode) {
	case MONO:
		frame->channels = 1;
		break;
	case DUAL_CHANNEL:	/* fall-through */
	case STEREO:
	case JOINT_STEREO:
		frame->channels = 2;
		break;
	}

	frame->allocation_method = (data[1] >> 1) & 0x01;

	frame->subbands = (data[1] & 0x01) ? 8 : 4;

	frame->bitpool = data[2];

	if (((frame->channel_mode == MONO || frame->channel_mode == DUAL_CHANNEL)
	     && frame->bitpool > 16 * frame->subbands)
	    || ((frame->channel_mode == STEREO || frame->channel_mode == JOINT_STEREO)
		&& frame->bitpool > 32 * frame->subbands)) {
		return -4;
	}

	/* data[3] is crc, we're checking it later */

	consumed = 32;

	crc_header[0] = data[1];
	crc_header[1] = data[2];
	crc_pos = 16;

	if (frame->channel_mode == JOINT_STEREO) {
		if (len * 8 < consumed + frame->subbands) {
			return -1;
		} else {
			frame->join = 0x00;
			for (sb = 0; sb < frame->subbands - 1; sb++) {
				frame->join |= ((data[4] >> (7 - sb)) & 0x01) << sb;
			}
			if (frame->subbands == 4) {
				crc_header[crc_pos / 8] = data[4] & 0xf0;
			} else {
				crc_header[crc_pos / 8] = data[4];
			}

			consumed += frame->subbands;
			crc_pos += frame->subbands;
		}
	}

	if (len * 8 < consumed + (4 * frame->subbands * frame->channels)) {
		return -1;
	} else {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				/* FIXME assert(consumed % 4 == 0); */
				frame->scale_factor[ch][sb] = (data[consumed / 8] >> (4 - (consumed % 8))) & 0x0F;
				crc_header[crc_pos / 8] |= frame->scale_factor[ch][sb] << (4 - (crc_pos % 8));

				consumed += 4;
				crc_pos += 4;
			}
		}
	}

	if (data[3] != sbc_crc8(crc_header, crc_pos)) {
		return -3;
	}

	sbc_calculate_bits(frame, bits, sf);

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				frame->audio_sample[blk][ch][sb] = 0;
				if (bits[ch][sb] != 0) {
					for (bit = 0; bit < bits[ch][sb]; bit++) {
						int b;	/* A bit */
						if (consumed > len * 8) {
							return -1;
						}

						b = (data[consumed / 8] >> (7 - (consumed % 8))) & 0x01;
						frame->audio_sample[blk][ch][sb] |= b << (bits[ch][sb] - bit - 1);

						consumed++;
					}
				}
			}
		}
	}

	for (ch = 0; ch < frame->channels; ch++) {
		for (sb = 0; sb < frame->subbands; sb++) {
			levels[ch][sb] = (1 << bits[ch][sb]) - 1;
			scalefactor[ch][sb] = 2 << frame->scale_factor[ch][sb];
		}
	}

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (levels[ch][sb] > 0) {
					frame->sb_sample[blk][ch][sb] =
					    scalefactor[ch][sb] * ((frame->audio_sample[blk][ch][sb] * 2.0 + 1.0) /
								   levels[ch][sb] - 1.0);
				} else {
					frame->sb_sample[blk][ch][sb] = 0;
				}
			}
		}
	}

	if (frame->channel_mode == JOINT_STEREO) {
		for (blk = 0; blk < frame->blocks; blk++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (frame->join & (0x01 << sb)) {
					frame->sb_sample[blk][0][sb] =
					    frame->sb_sample[blk][0][sb] + frame->sb_sample[blk][1][sb];
					frame->sb_sample[blk][1][sb] =
					    frame->sb_sample[blk][0][sb] - 2 * frame->sb_sample[blk][1][sb];
				}
			}
		}
	}

	if (consumed % 8 != 0)
		consumed += 8 - (consumed % 8);

	return consumed / 8;
}

static void sbc_decoder_init(struct sbc_decoder_state *state, const struct sbc_frame *frame)
{
	memset(&state->S, 0, sizeof(state->S));
	memset(&state->X, 0, sizeof(state->X));
	memset(&state->V, 0, sizeof(state->V));
	memset(&state->U, 0, sizeof(state->U));
	memset(&state->W, 0, sizeof(state->W));
	state->subbands = frame->subbands;
}

static inline void sbc_synthesize_four(struct sbc_decoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, j, k;

	/* Input 4 New Subband Samples */
	for (i = 0; i < 4; i++)
		state->S[ch][i] = frame->sb_sample[blk][ch][i];

	/* Shifting */
	for (i = 79; i >= 8; i--)
		state->V[ch][i] = state->V[ch][i - 8];

	/* Matrixing */
	for (k = 0; k < 8; k++) {
		state->V[ch][k] = 0;
		for (i = 0; i < 4; i++)
			state->V[ch][k] += synmatrix4[k][i] * state->S[ch][i];
	}

	/* Build a 40 values vector U */
	for (i = 0; i <= 4; i++) {
		for (j = 0; j < 4; j++) {
			state->U[ch][i * 8 + j] = state->V[ch][i * 16 + j];
			state->U[ch][i * 8 + j + 4] = state->V[ch][i * 16 + j + 12];
		}
	}

	/* Window by 40 coefficients */
	for (i = 0; i < 40; i++)
		state->W[ch][i] = state->U[ch][i] * sbc_proto_4_40[i] * (-4);

	/* Calculate 4 audio samples */
	for (j = 0; j < 4; j++) {
		state->X[ch][j] = 0;
		for (i = 0; i < 10; i++)
			state->X[ch][j] += state->W[ch][j + 4 * i];
	}

	/* Output 4 reconstructed Audio Samples */
	for (i = 0; i < 4; i++)
		frame->pcm_sample[ch][blk * 4 + i] = state->X[ch][i];
}

static inline void sbc_synthesize_eight(struct sbc_decoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, j, k;

	/* Input 8 New Subband Samples */
	for (i = 0; i < 8; i++)
		state->S[ch][i] = frame->sb_sample[blk][ch][i];

	/* Shifting */
	for (i = 159; i >= 16; i--)
		state->V[ch][i] = state->V[ch][i - 16];

	/* Matrixing */
	for (k = 0; k < 16; k++) {
		state->V[ch][k] = 0;
		for (i = 0; i < 8; i++) {
			state->V[ch][k] += synmatrix8[k][i] * state->S[ch][i];
		}
	}

	/* Build a 80 values vector U */
	for (i = 0; i <= 4; i++) {
		for (j = 0; j < 8; j++) {
			state->U[ch][i * 16 + j] = state->V[ch][i * 32 + j];
			state->U[ch][i * 16 + j + 8] = state->V[ch][i * 32 + j + 24];
		}
	}

	/* Window by 80 coefficients */
	for (i = 0; i < 80; i++)
		state->W[ch][i] = state->U[ch][i] * sbc_proto_8_80[i] * (-4);

	/* Calculate 8 audio samples */
	for (j = 0; j < 8; j++) {
		state->X[ch][j] = 0;
		for (i = 0; i < 10; i++)
			state->X[ch][j] += state->W[ch][j + 8 * i];
	}

	/* Ouput 8 reconstructed Audio Samples */
	for (i = 0; i < 8; i++)
		frame->pcm_sample[ch][blk * 8 + i] = state->X[ch][i];
}

static int sbc_synthesize_audio(struct sbc_decoder_state *state, struct sbc_frame *frame)
{
	int ch, blk;

	switch (frame->subbands) {
	case 4:
		for (ch = 0; ch < frame->channels; ch++) {
			memset(frame->pcm_sample[ch], 0,
				sizeof(frame->pcm_sample[ch]));

			for (blk = 0; blk < frame->blocks; blk++)
				sbc_synthesize_four(state, frame, ch, blk);
		}

		return frame->blocks * 4;

	case 8:
		for (ch = 0; ch < frame->channels; ch++) {
			memset(frame->pcm_sample[ch], 0,
				sizeof(frame->pcm_sample[ch]));

			for (blk = 0; blk < frame->blocks; blk++)
				sbc_synthesize_eight(state, frame, ch, blk);
		}

		return frame->blocks * 8;

	default:
		return -EIO;
	}
}

static void sbc_encoder_init(struct sbc_encoder_state *state, const struct sbc_frame *frame)
{
	memset(&state->S, 0, sizeof(state->S));
	memset(&state->X, 0, sizeof(state->X));
	memset(&state->Y, 0, sizeof(state->Y));
	memset(&state->Z, 0, sizeof(state->Z));
	state->subbands = frame->subbands;
}

static inline void sbc_analyze_four(struct sbc_encoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, k;

	/* Input 4 New Audio Samples */
	for (i = 39; i >= 4; i--)
		state->X[ch][i] = state->X[ch][i - 4];
	for (i = 3; i >= 0; i--)
		state->X[ch][i] = frame->pcm_sample[ch][blk * 4 + (3 - i)];

	/* Windowing by 40 coefficients */
	for (i = 0; i < 40; i++)
		state->Z[ch][i] = sbc_proto_4_40[i] * state->X[ch][i];

	/* Partial calculation */
	for (i = 0; i < 8; i++) {
		state->Y[ch][i] = 0;
		for (k = 0; k < 5; k++)
			state->Y[ch][i] += state->Z[ch][i + k * 8];
	}

	/* Calculate 4 subband samples by Matrixing */
	for (i = 0; i < 4; i++) {
		state->S[ch][i] = 0;
		for (k = 0; k < 8; k++)
			state->S[ch][i] += anamatrix4[i][k] * state->Y[ch][k];
	}

	/* Output 4 Subband Samples */
	for (i = 0; i < 4; i++)
		frame->sb_sample[blk][ch][i] = state->S[ch][i];
}

static inline void sbc_analyze_eight(struct sbc_encoder_state *state,
				struct sbc_frame *frame, int ch, int blk)
{
	int i, k;

	/* Input 8 Audio Samples */
	for (i = 79; i >= 8; i--)
		state->X[ch][i] = state->X[ch][i - 8];
	for (i = 7; i >= 0; i--)
		state->X[ch][i] = frame->pcm_sample[ch][blk * 8 + (7 - i)];

	/* Windowing by 80 coefficients */
	for (i = 0; i < 80; i++)
		state->Z[ch][i] = sbc_proto_8_80[i] * state->X[ch][i];

	/* Partial calculation */
	for (i = 0; i < 16; i++) {
		state->Y[ch][i] = 0;
		for (k = 0; k < 5; k++)
			state->Y[ch][i] += state->Z[ch][i + k * 16];
	}

	/* Calculate 8 subband samples by Matrixing */
	for (i = 0; i < 8; i++) {
		state->S[ch][i] = 0;
		for (k = 0; k < 16; k++)
			state->S[ch][i] += anamatrix8[i][k] * state->Y[ch][k];
	}

	/* Output 8 Subband Samples */
	for (i = 0; i < 8; i++)
		frame->sb_sample[blk][ch][i] = state->S[ch][i];
}

static int sbc_analyze_audio(struct sbc_encoder_state *state, struct sbc_frame *frame)
{
	int ch, blk;

	switch (frame->subbands) {
	case 4:
		for (ch = 0; ch < frame->channels; ch++)
			for (blk = 0; blk < frame->blocks; blk++) {
				memset(frame->sb_sample[blk][ch], 0,
					sizeof(frame->sb_sample[blk][ch]));
				sbc_analyze_four(state, frame, ch, blk);
			}

		return frame->blocks * 4;

	case 8:
		for (ch = 0; ch < frame->channels; ch++)
			for (blk = 0; blk < frame->blocks; blk++) {
				memset(frame->sb_sample[blk][ch], 0,
					sizeof(frame->sb_sample[blk][ch]));
				sbc_analyze_eight(state, frame, ch, blk);
			}

		return frame->blocks * 8;

	default:
		return -EIO;
	}
}

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

static int sbc_pack_frame(u_int8_t * data, struct sbc_frame *frame, size_t len)
{
	int produced;
	/* Will copy the header parts for CRC-8 calculation here */
	u_int8_t crc_header[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	int crc_pos = 0;

	u_int8_t sf;		/* Sampling frequency as temporary value for table lookup */

	int ch, sb, blk, bit;	/* channel, subband, block and bit counters */
	int bits[2][8];		/* bits distribution */
	int levels[2][8];	/* levels are derived from that */

	double scalefactor[2][8];	/* derived from frame->scale_factor */

	if (len < 4) {
		return -1;
	}

	/* Clear first 4 bytes of data (that's the constant length part of the SBC header) */
	memset(data, 0, 4);

	data[0] = SBC_SYNCWORD;

	if (frame->sampling_frequency == 16) {
		data[1] |= (SBC_FS_16 & 0x03) << 6;
		sf = SBC_FS_16;
	} else if (frame->sampling_frequency == 32) {
		data[1] |= (SBC_FS_32 & 0x03) << 6;
		sf = SBC_FS_32;
	} else if (frame->sampling_frequency == 44.1) {
		data[1] |= (SBC_FS_44 & 0x03) << 6;
		sf = SBC_FS_44;
	} else if (frame->sampling_frequency == 48) {
		data[1] |= (SBC_FS_48 & 0x03) << 6;
		sf = SBC_FS_48;
	} else {
		return -2;
	}

	switch (frame->blocks) {
	case 4:
		data[1] |= (SBC_NB_4 & 0x03) << 4;
		break;
	case 8:
		data[1] |= (SBC_NB_8 & 0x03) << 4;
		break;
	case 12:
		data[1] |= (SBC_NB_12 & 0x03) << 4;
		break;
	case 16:
		data[1] |= (SBC_NB_16 & 0x03) << 4;
		break;
	default:
		return -3;
		break;
	}

	data[1] |= (frame->channel_mode & 0x03) << 2;

	data[1] |= (frame->allocation_method & 0x01) << 1;

	switch (frame->subbands) {
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
	if (((frame->channel_mode == MONO || frame->channel_mode == DUAL_CHANNEL)
	     && frame->bitpool > 16 * frame->subbands)
	    || ((frame->channel_mode == STEREO || frame->channel_mode == JOINT_STEREO)
		&& frame->bitpool > 32 * frame->subbands)) {
		return -5;
	}

	/* Can't fill in crc yet */

	produced = 32;

	crc_header[0] = data[1];
	crc_header[1] = data[2];
	crc_pos = 16;


	for (ch = 0; ch < frame->channels; ch++) {
		for (sb = 0; sb < frame->subbands; sb++) {
			frame->scale_factor[ch][sb] = 0;
			scalefactor[ch][sb] = 2;
			for (blk = 0; blk < frame->blocks; blk++) {
				while (scalefactor[ch][sb] < fabs(frame->sb_sample[blk][ch][sb])) {
					frame->scale_factor[ch][sb]++;
					scalefactor[ch][sb] *= 2;
				}
			}
		}
	}

	if (frame->channel_mode == JOINT_STEREO) {
		float sb_sample_j[16][2][7]; /* like frame->sb_sample but joint stereo */
		int scalefactor_j[2][7], scale_factor_j[2][7]; /* scalefactor and scale_factor in joint case */

		/* Calculate joint stereo signal */
		for (sb = 0; sb < frame->subbands - 1; sb++) {
			for (blk = 0; blk < frame->blocks; blk++) {
				sb_sample_j[blk][0][sb] = (frame->sb_sample[blk][0][sb] 
							   + frame->sb_sample[blk][1][sb]) / 2;
				sb_sample_j[blk][1][sb] = (frame->sb_sample[blk][0][sb] 
							   - frame->sb_sample[blk][1][sb]) / 2;
			}
		}

		/* calculate scale_factor_j and scalefactor_j for joint case */
		for (ch = 0; ch < 2; ch++) {
			for (sb = 0; sb < frame->subbands - 1; sb++) {
				scale_factor_j[ch][sb] = 0;
				scalefactor_j[ch][sb] = 2;
				for (blk = 0; blk < frame->blocks; blk++) {
					while (scalefactor_j[ch][sb] < fabs(sb_sample_j[blk][ch][sb])) {
						scale_factor_j[ch][sb]++;
						scalefactor_j[ch][sb] *= 2;
					}
				}
			}
		}

		/* decide which subbands to join */
		frame->join = 0;
		for (sb = 0; sb < frame->subbands - 1; sb++) {
			if ( (scalefactor[0][sb] + scalefactor[1][sb]) > 
			     (scalefactor_j[0][sb] + scalefactor_j[1][sb]) ) {
				/* use joint stereo for this subband */
				frame->join |= 1 << sb;
				frame->scale_factor[0][sb] = scale_factor_j[0][sb];
				frame->scale_factor[1][sb] = scale_factor_j[1][sb];
				scalefactor[0][sb] = scalefactor_j[0][sb];
				scalefactor[1][sb] = scalefactor_j[1][sb];
				for (blk = 0; blk < frame->blocks; blk++) {
					frame->sb_sample[blk][0][sb] = sb_sample_j[blk][0][sb];
					frame->sb_sample[blk][1][sb] = sb_sample_j[blk][1][sb];
				}
			}
		}
  
		if (len * 8 < produced + frame->subbands) {
			return -1;
		} else {
			data[4] = 0;
			for (sb = 0; sb < frame->subbands - 1; sb++) {
				data[4] |= ((frame->join >> sb) & 0x01) << (7 - sb);
			}
			if (frame->subbands == 4) {
				crc_header[crc_pos / 8] = data[4] & 0xf0;
			} else {
				crc_header[crc_pos / 8] = data[4];
			}

			produced += frame->subbands;
			crc_pos += frame->subbands;
		}
	}

	if (len * 8 < produced + (4 * frame->subbands * frame->channels)) {
		return -1;
	} else {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (produced % 8 == 0)
					data[produced / 8] = 0;
				data[produced / 8] |= ((frame->scale_factor[ch][sb] & 0x0F) << (4 - (produced % 8)));
				crc_header[crc_pos / 8] |=
				    ((frame->scale_factor[ch][sb] & 0x0F) << (4 - (crc_pos % 8)));

				produced += 4;
				crc_pos += 4;
			}
		}
	}

	data[3] = sbc_crc8(crc_header, crc_pos);

	sbc_calculate_bits(frame, bits, sf);

	for (ch = 0; ch < frame->channels; ch++) {
		for (sb = 0; sb < frame->subbands; sb++) {
			levels[ch][sb] = (1 << bits[ch][sb]) - 1;
		}
	}

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (levels[ch][sb] > 0) {
					frame->audio_sample[blk][ch][sb] =
					    (u_int16_t) (((frame->sb_sample[blk][ch][sb] / scalefactor[ch][sb] +
							   1.0) * levels[ch][sb]) / 2.0);
				} else {
					frame->audio_sample[blk][ch][sb] = 0;
				}
			}
		}
	}

	for (blk = 0; blk < frame->blocks; blk++) {
		for (ch = 0; ch < frame->channels; ch++) {
			for (sb = 0; sb < frame->subbands; sb++) {
				if (bits[ch][sb] != 0) {
					for (bit = 0; bit < bits[ch][sb]; bit++) {
						int b;	/* A bit */
						if (produced > len * 8) {
							return -1;
						}
						if (produced % 8 == 0) {
							data[produced / 8] = 0;
						}
						b = ((frame->audio_sample[blk][ch][sb]) >> (bits[ch][sb] - bit -
											    1)) & 0x01;
						data[produced / 8] |= b << (7 - (produced % 8));
						produced++;
					}
				}
			}
		}
	}

	if (produced % 8 != 0) {
		produced += 8 - (produced % 8);
	}

	return produced / 8;
}


struct sbc_priv {
	int init;
	struct sbc_frame frame;
	struct sbc_decoder_state dec_state;
	struct sbc_encoder_state enc_state;
};

int sbc_init(sbc_t *sbc, unsigned long flags)
{
	if (!sbc)
		return -EIO;

	memset(sbc, 0, sizeof(sbc_t));

	sbc->priv = malloc(sizeof(struct sbc_priv));
	if (!sbc->priv)
		return -ENOMEM;

	memset(sbc->priv, 0, sizeof(struct sbc_priv));

	sbc->rate     = 44100;
	sbc->channels = 2;
	sbc->subbands = 8;
	sbc->blocks   = 16;
	sbc->bitpool  = 32;

	return 0;
}

int sbc_decode(sbc_t *sbc, void *data, int count)
{
	struct sbc_priv *priv;
	char *ptr;
	int i, ch, framelen, samples;

	if (!sbc)
		return -EIO;

	priv = sbc->priv;

	framelen = sbc_unpack_frame(data, &priv->frame, count);

	if (!priv->init) {
		sbc_decoder_init(&priv->dec_state, &priv->frame);
		priv->init = 1;

		sbc->rate     = priv->frame.sampling_frequency * 1000;
		sbc->channels = priv->frame.channels;
		sbc->subbands = priv->frame.subbands;
		sbc->blocks   = priv->frame.blocks;
		sbc->bitpool  = priv->frame.bitpool;
	}

	samples = sbc_synthesize_audio(&priv->dec_state, &priv->frame);

	if (!sbc->data) {
		sbc->size = samples * priv->frame.channels * 2;
		sbc->data = malloc(sbc->size);
	}

	if (sbc->size < samples * priv->frame.channels * 2) {
		sbc->size = samples * priv->frame.channels * 2;
		sbc->data = realloc(sbc->data, sbc->size);
	}

	if (!sbc->data) {
		sbc->size = 0;
		return -ENOMEM;
	}

	ptr = sbc->data;

	for (i = 0; i < samples; i++) {
		for (ch = 0; ch < priv->frame.channels; ch++) {
			int16_t s = (int16_t)(priv->frame.pcm_sample[ch][i]);
			*ptr++ = (s & 0xff00) >> 8;
			*ptr++ = (s & 0x00ff);
		}
	}

	sbc->len = samples * priv->frame.channels * 2;

	sbc->duration = (1000000 * priv->frame.subbands * priv->frame.blocks) / sbc->rate;

	return framelen;
}

int sbc_encode(sbc_t *sbc, void *data, int count)
{
	struct sbc_priv *priv;
	char *ptr;
	int i, ch, framelen, samples;

	if (!sbc)
		return -EIO;

	priv = sbc->priv;

	if (!priv->init) {
		priv->frame.sampling_frequency = ((double) sbc->rate) / 1000;
		priv->frame.channels = sbc->channels;

		if (sbc->channels > 1)
			priv->frame.channel_mode = STEREO;
		else
			priv->frame.channel_mode = MONO;

		priv->frame.allocation_method = SNR;
		priv->frame.subbands = sbc->subbands;
		priv->frame.blocks   = sbc->blocks;
		priv->frame.bitpool  = sbc->bitpool;

		sbc_encoder_init(&priv->enc_state, &priv->frame);
		priv->init = 1;
	}

	ptr = data;

	for (i = 0; i < priv->frame.subbands * priv->frame.blocks; i++) {
		for (ch = 0; ch < sbc->channels; ch++) {
			//int16_t s = (ptr[0] & 0xff) << 8 | (ptr[1] & 0xff);
			int16_t s = (ptr[1] & 0xff) << 8 | (ptr[2] & 0xff);
			ptr += 2;
			priv->frame.pcm_sample[ch][i] = ((double) s);
		}
	}

	samples = sbc_analyze_audio(&priv->enc_state, &priv->frame);

	if (!sbc->data) {
		sbc->size = 1024;
		sbc->data = malloc(sbc->size);
	}

	if (!sbc->data) {
		sbc->size = 0;
		return -ENOMEM;
	}

	framelen = sbc_pack_frame(sbc->data, &priv->frame, sbc->size);

	sbc->len = framelen;

	sbc->duration = (1000000 * priv->frame.subbands * priv->frame.blocks) / sbc->rate;

	return samples * sbc->channels * 2;
}

void sbc_finish(sbc_t *sbc)
{
	if (!sbc)
		return;

	if (sbc->data)
		free(sbc->data);

	if (sbc->priv)
		free(sbc->priv);

	memset(sbc, 0, sizeof(sbc_t));
}
