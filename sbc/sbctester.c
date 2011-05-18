/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2008-2010  Nokia Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2007-2008  Frederic Dalleau <fdalleau@free.fr>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sndfile.h>
#include <math.h>
#include <string.h>

#define MAXCHANNELS 2
#define DEFACCURACY 7

static double sampletobits(short sample16, int verbose)
{
	double bits = 0;
	unsigned short bit;
	int i;

	if (verbose)
		printf("===> sampletobits(%hd, %04hX)\n", sample16, sample16);

	/* Bit 0 is MSB */
	if (sample16 < 0)
		bits = -1;

	if (verbose)
		printf("%d", (sample16 < 0) ? 1 : 0);

	/* Bit 15 is LSB */
	for (i = 1; i < 16; i++) {
		bit = (unsigned short) sample16;
		bit >>= 15 - i;
		bit %= 2;

		if (verbose)
			printf("%d", bit);

		if (bit)
			bits += (1.0 / pow(2.0, i));
	}

	if (verbose)
		printf("\n");

	return bits;
}

static int calculate_rms_level(SNDFILE * sndref, SF_INFO * infosref,
				SNDFILE * sndtst, SF_INFO * infostst,
						int accuracy, char *csvname)
{
	short refsample[MAXCHANNELS], tstsample[MAXCHANNELS];
	double refbits, tstbits;
	double rms_accu[MAXCHANNELS];
	double rms_level[MAXCHANNELS];
	double rms_limit = 1.0 / (pow(2.0, accuracy - 1) * pow(12.0, 0.5));
	FILE *csv = NULL;
	int i, j, r1, r2, verdict;

	if (csvname)
		csv = fopen(csvname, "wt");

	if (csv) {
		fprintf(csv, "num;");
		for (j = 0; j < infostst->channels; j++)
			fprintf(csv, "ref channel %d;tst channel %d;", j, j);
		fprintf(csv, "\r\n");
	}

	sf_seek(sndref, 0, SEEK_SET);
	sf_seek(sndtst, 0, SEEK_SET);

	memset(rms_accu, 0, sizeof(rms_accu));
	memset(rms_level, 0, sizeof(rms_level));

	for (i = 0; i < infostst->frames; i++) {
		if (csv)
			fprintf(csv, "%d;", i);

		r1 = sf_read_short(sndref, refsample, infostst->channels);
		if (r1 != infostst->channels) {
			printf("Failed to read reference data: %s "
					"(r1=%d, channels=%d)",
					sf_strerror(sndref), r1,
					infostst->channels);
			if (csv)
				fclose(csv);
			return -1;
		}

		r2 = sf_read_short(sndtst, tstsample, infostst->channels);
		if (r2 != infostst->channels) {
			printf("Failed to read test data: %s "
					"(r2=%d, channels=%d)\n",
					sf_strerror(sndtst), r2,
					infostst->channels);
			if (csv)
				fclose(csv);
			return -1;
		}

		for (j = 0; j < infostst->channels; j++) {
			if (csv)
				fprintf(csv, "%d;%d;", refsample[j],
						tstsample[j]);

			refbits = sampletobits(refsample[j], 0);
			tstbits = sampletobits(tstsample[j], 0);

			rms_accu[j] += pow(tstbits - refbits, 2.0);
		}

		if (csv)
			fprintf(csv, "\r\n");
	}

	printf("Limit: %f\n", rms_limit);

	for (j = 0; j < infostst->channels; j++) {
		printf("Channel %d\n", j);
		printf("Accumulated %f\n", rms_accu[j]);
		rms_accu[j] /= (double) infostst->frames;
		printf("Accumulated / %f = %f\n", (double) infostst->frames,
				rms_accu[j]);
		rms_level[j] = sqrt(rms_accu[j]);
		printf("Level = %f (%f x %f = %f)\n",
				rms_level[j], rms_level[j], rms_level[j],
						rms_level[j] * rms_level[j]);
	}

	verdict = 1;

	for (j = 0; j < infostst->channels; j++) {
		printf("Channel %d: %f\n", j, rms_level[j]);

		if (rms_level[j] > rms_limit)
			verdict = 0;
	}

	printf("%s return %d\n", __FUNCTION__, verdict);

	return verdict;
}

static int check_absolute_diff(SNDFILE * sndref, SF_INFO * infosref,
				SNDFILE * sndtst, SF_INFO * infostst,
				int accuracy)
{
	short refsample[MAXCHANNELS], tstsample[MAXCHANNELS];
	short refmax[MAXCHANNELS], tstmax[MAXCHANNELS];
	double refbits, tstbits;
	double rms_absolute = 1.0 / (pow(2, accuracy - 2));
	double calc_max[MAXCHANNELS];
	int calc_count = 0;
	short r1, r2;
	double cur_diff;
	int i, j, verdict;

	memset(&refmax, 0, sizeof(refmax));
	memset(&tstmax, 0, sizeof(tstmax));
	memset(&calc_max, 0, sizeof(calc_max));
	memset(&refsample, 0, sizeof(refsample));
	memset(&tstsample, 0, sizeof(tstsample));

	sf_seek(sndref, 0, SEEK_SET);
	sf_seek(sndtst, 0, SEEK_SET);

	verdict = 1;

	printf("Absolute max: %f\n", rms_absolute);
	for (i = 0; i < infostst->frames; i++) {
		r1 = sf_read_short(sndref, refsample, infostst->channels);

		if (r1 != infostst->channels) {
			printf("Failed to read reference data: %s "
					"(r1=%d, channels=%d)",
					sf_strerror(sndref), r1,
					infostst->channels);
			return -1;
		}

		r2 = sf_read_short(sndtst, tstsample, infostst->channels);
		if (r2 != infostst->channels) {
			printf("Failed to read test data: %s "
					"(r2=%d, channels=%d)\n",
					sf_strerror(sndtst), r2,
					infostst->channels);
			return -1;
		}

		for (j = 0; j < infostst->channels; j++) {
			refbits = sampletobits(refsample[j], 0);
			tstbits = sampletobits(tstsample[j], 0);

			cur_diff = fabs(tstbits - refbits);

			if (cur_diff > rms_absolute) {
				calc_count++;
				/* printf("Channel %d exceeded : fabs(%f - %f) = %f > %f\n", j, tstbits, refbits, cur_diff, rms_absolute); */
				verdict = 0;
			}

			if (cur_diff > calc_max[j]) {
				calc_max[j] = cur_diff;
				refmax[j] = refsample[j];
				tstmax[j] = tstsample[j];
			}
		}
	}

	for (j = 0; j < infostst->channels; j++) {
		printf("Calculated max: %f (%hd-%hd=%hd)\n",
			calc_max[j], tstmax[j], refmax[j],
			tstmax[j] - refmax[j]);
	}

	printf("%s return %d\n", __FUNCTION__, verdict);

	return verdict;
}

static void usage(void)
{
	printf("SBC conformance test ver %s\n", VERSION);
	printf("Copyright (c) 2007-2010  Marcel Holtmann\n");
	printf("Copyright (c) 2007-2008  Frederic Dalleau\n\n");

	printf("Usage:\n"
		"\tsbctester reference.wav checkfile.wav\n"
		"\tsbctester integer\n"
		"\n");

	printf("To test the encoder:\n");
	printf("\tUse a reference codec to encode original.wav to reference.sbc\n");
	printf("\tUse sbcenc to encode original.wav to checkfile.sbc\n");
	printf("\tDecode both file using the reference decoder\n");
	printf("\tRun sbctester with these two wav files to get the result\n\n");

	printf("\tA file called out.csv is generated to use the data in a\n");
	printf("\tspreadsheet application or database.\n\n");
}

int main(int argc, char *argv[])
{
	SNDFILE *sndref = NULL;
	SNDFILE *sndtst = NULL;
	SF_INFO infosref;
	SF_INFO infostst;
	char *ref;
	char *tst;
	int pass_rms, pass_absolute, pass, accuracy;

	if (argc == 2) {
		double db;

		printf("Test sampletobits\n");
		db = sampletobits((short) atoi(argv[1]), 1);
		printf("db = %f\n", db);
		exit(0);
	}

	if (argc < 3) {
		usage();
		exit(1);
	}

	ref = argv[1];
	tst = argv[2];

	printf("opening reference %s\n", ref);

	sndref = sf_open(ref, SFM_READ, &infosref);
	if (!sndref) {
		printf("Failed to open reference file\n");
		exit(1);
	}

	printf("opening testfile %s\n", tst);
	sndtst = sf_open(tst, SFM_READ, &infostst);
	if (!sndtst) {
		printf("Failed to open test file\n");
		sf_close(sndref);
		exit(1);
	}

	printf("reference:\n\t%d frames,\n\t%d hz,\n\t%d channels\n",
		(int) infosref.frames, (int) infosref.samplerate,
		(int) infosref.channels);
	printf("testfile:\n\t%d frames,\n\t%d hz,\n\t%d channels\n",
		(int) infostst.frames, (int) infostst.samplerate,
		(int) infostst.channels);

	/* check number of channels */
	if (infosref.channels > 2 || infostst.channels > 2) {
		printf("Too many channels\n");
		goto error;
	}

	/* compare number of samples */
	if (infosref.samplerate != infostst.samplerate ||
				infosref.channels != infostst.channels) {
		printf("Cannot compare files with different charasteristics\n");
		goto error;
	}

	accuracy = DEFACCURACY;
	printf("Accuracy: %d\n", accuracy);

	/* Condition 1 rms level */
	pass_rms = calculate_rms_level(sndref, &infosref, sndtst, &infostst,
					accuracy, "out.csv");
	if (pass_rms < 0)
		goto error;

	/* Condition 2 absolute difference */
	pass_absolute = check_absolute_diff(sndref, &infosref, sndtst,
						&infostst, accuracy);
	if (pass_absolute < 0)
		goto error;

	/* Verdict */
	pass = pass_rms && pass_absolute;
	printf("Verdict: %s\n", pass ? "pass" : "fail");

	return 0;

error:
	sf_close(sndref);
	sf_close(sndtst);

	exit(1);
}
