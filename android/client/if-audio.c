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

#include "if-main.h"
#include "../hal-utils.h"

audio_hw_device_t *if_audio = NULL;

static void init_p(int argc, const char **argv)
{
	int err;
	const hw_module_t *module;
	audio_hw_device_t *device;

	err = hw_get_module_by_class(AUDIO_HARDWARE_MODULE_ID,
					AUDIO_HARDWARE_MODULE_ID_A2DP, &module);
	if (err) {
		haltest_error("hw_get_module_by_class returned %d\n", err);
		return;
	}

	err = audio_hw_device_open(module, &device);
	if (err)
		haltest_error("audio_hw_device_open returned %d\n", err);

	if_audio = device;
}

static void cleanup_p(int argc, const char **argv)
{
	int err;

	RETURN_IF_NULL(if_audio);

	err = audio_hw_device_close(if_audio);
	if (err < 0) {
		haltest_error("audio_hw_device_close returned %d\n", err);
		return;
	}

	if_audio = NULL;
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHOD(cleanup),
	END_METHOD
};

const struct interface audio_if = {
	.name = "audio",
	.methods = methods
};
