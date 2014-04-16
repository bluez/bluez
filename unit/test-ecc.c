/*
 * Copyright (c) 2013, Kenneth MacKay
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "src/shared/ecc.h"

static void vli_print(uint8_t *vli, size_t size)
{
	while (size) {
		printf("%02X ", vli[size - 1]);
		size--;
	}
}

#define PAIR_COUNT 200

static void test_basic(void)
{
	uint8_t public1[64], public2[64];
	uint8_t private1[32], private2[32];
	uint8_t shared1[32], shared2[32];
	int i;

	printf("Testing %u random private key pairs\n", PAIR_COUNT);

	for (i = 0; i < PAIR_COUNT; i++) {
		printf(".");
		fflush(stdout);

		ecc_make_key(public1, private1);
		ecc_make_key(public2, private2);

		ecdh_shared_secret(public1, private2, shared1);
		ecdh_shared_secret(public2, private1, shared2);

		if (memcmp(shared1, shared2, sizeof(shared1)) != 0) {
			printf("Shared secrets are not identical!\n");
			printf("Shared secret 1 = ");
			vli_print(shared1, sizeof(shared1));
			printf("\n");
			printf("Shared secret 2 = ");
			vli_print(shared2, sizeof(shared2));
			printf("\n");
			printf("Private key 1 = ");
			vli_print(private1, sizeof(private1));
			printf("\n");
			printf("Private key 2 = ");
			vli_print(private2, sizeof(private2));
			printf("\n");
			g_assert_not_reached();
		}
	}

	printf("\n");
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/ecdh", test_basic);

	return g_test_run();
}
