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
struct audio_stream_out *stream_out = NULL;

static size_t buffer_size = 0;

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
	if (err) {
		haltest_error("audio_hw_device_open returned %d\n", err);
		return;
	}

	if_audio = device;
}

static void open_output_stream_p(int argc, const char **argv)
{
	int err;

	RETURN_IF_NULL(if_audio);

	err = if_audio->open_output_stream(if_audio,
						0,
						AUDIO_DEVICE_OUT_ALL_A2DP,
						AUDIO_OUTPUT_FLAG_NONE,
						NULL,
						&stream_out);
	if (err < 0) {
		haltest_error("open output stream returned %d\n", err);
		return;
	}

	buffer_size = stream_out->common.get_buffer_size(&stream_out->common);
	if (buffer_size == 0)
		haltest_error("Invalid buffer size received!\n");
	else
		haltest_info("Using buffer size: %d\n", buffer_size);
}

static void close_output_stream_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_audio);
	RETURN_IF_NULL(stream_out);

	if_audio->close_output_stream(if_audio, stream_out);
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
	STD_METHOD(open_output_stream),
	STD_METHOD(close_output_stream),
	END_METHOD
};

const struct interface audio_if = {
	.name = "audio",
	.methods = methods
};
