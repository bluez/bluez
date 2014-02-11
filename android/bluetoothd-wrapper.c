/*
 * Copyright (C) 2014 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/properties.h>

#define PROPERTY_NAME "persist.sys.bluetooth.valgrind"

#define VALGRIND_BIN "/system/bin/valgrind"

#define BLUETOOTHD_BIN "/system/bin/bluetoothd-main"

static void run_valgrind(void)
{
	char *prg_argv[4];
	char *prg_envp[3];

	prg_argv[0] = VALGRIND_BIN;
	prg_argv[1] = "--leak-check=full";
	prg_argv[2] = BLUETOOTHD_BIN;
	prg_argv[3] = NULL;

	prg_envp[0] = "G_SLICE=always-malloc";
	prg_envp[1] = "G_DEBUG=gc-friendly";
	prg_envp[2] = NULL;

	execve(prg_argv[0], prg_argv, prg_envp);
}

static void run_bluetoothd(void)
{
	char *prg_argv[2];
	char *prg_envp[1];

	prg_argv[0] = BLUETOOTHD_BIN;
	prg_argv[1] = NULL;

	prg_envp[0] = NULL;

	execve(prg_argv[0], prg_argv, prg_envp);
}

int main(int argc, char *argv[])
{
	char value[PROPERTY_VALUE_MAX];

	if (property_get(PROPERTY_NAME, value, "") > 0 &&
			(!strcasecmp(value, "true") || atoi(value) > 0))
		run_valgrind();

	/* In case we failed to execute Valgrind, try to run bluetoothd
	 * without it
	 */

	run_bluetoothd();

	return 0;
}
