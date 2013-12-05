/*
 * Copyright (C) 2013 Intel Corporation
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hardware/audio.h>
#include <hardware/hardware.h>

#include "hal-log.h"

static ssize_t out_write(struct audio_stream_out *stream, const void *buffer,
								size_t bytes)
{
	DBG("");
	return -ENOSYS;
}

static uint32_t out_get_sample_rate(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int out_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	DBG("");
	return -ENOSYS;
}

static size_t out_get_buffer_size(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static uint32_t out_get_channels(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static audio_format_t out_get_format(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int out_set_format(struct audio_stream *stream, audio_format_t format)
{
	DBG("");
	return -ENOSYS;
}

static int out_standby(struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
	DBG("");
	return -ENOSYS;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	DBG("");
	return -ENOSYS;
}

static char *out_get_parameters(const struct audio_stream *stream,
							const char *keys)
{
	DBG("");
	return strdup("");
}

static uint32_t out_get_latency(const struct audio_stream_out *stream)
{
	DBG("");
	return -ENOSYS;
}

static int out_set_volume(struct audio_stream_out *stream, float left,
								float right)
{
	DBG("");
	/* volume controlled in audioflinger mixer (digital) */
	return -ENOSYS;
}

static int out_get_render_position(const struct audio_stream_out *stream,
							uint32_t *dsp_frames)
{
	DBG("");
	return -ENOSYS;
}

static int out_add_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");
	return -ENOSYS;
}

static int out_remove_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");
	return -ENOSYS;
}

static uint32_t in_get_sample_rate(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int in_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	DBG("");
	return -ENOSYS;
}

static size_t in_get_buffer_size(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static uint32_t in_get_channels(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static audio_format_t in_get_format(const struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int in_set_format(struct audio_stream *stream, audio_format_t format)
{
	DBG("");
	return -ENOSYS;
}

static int in_standby(struct audio_stream *stream)
{
	DBG("");
	return -ENOSYS;
}

static int in_dump(const struct audio_stream *stream, int fd)
{
	DBG("");
	return -ENOSYS;
}

static int in_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	DBG("");
	return -ENOSYS;
}

static char *in_get_parameters(const struct audio_stream *stream,
							const char *keys)
{
	DBG("");
	return strdup("");
}

static int in_set_gain(struct audio_stream_in *stream, float gain)
{
	DBG("");
	return -ENOSYS;
}

static ssize_t in_read(struct audio_stream_in *stream, void *buffer,
								size_t bytes)
{
	DBG("");
	return -ENOSYS;
}

static uint32_t in_get_input_frames_lost(struct audio_stream_in *stream)
{
	DBG("");
	return -ENOSYS;
}

static int in_add_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");
	return -ENOSYS;
}

static int in_remove_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");
	return -ENOSYS;
}

static int audio_open_output_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					audio_output_flags_t flags,
					struct audio_config *config,
					struct audio_stream_out **stream_out)

{
	struct audio_stream_out *out;

	out = calloc(1, sizeof(struct audio_stream_out));
	if (!out)
		return -ENOMEM;

	DBG("");

	out->common.get_sample_rate = out_get_sample_rate;
	out->common.set_sample_rate = out_set_sample_rate;
	out->common.get_buffer_size = out_get_buffer_size;
	out->common.get_channels = out_get_channels;
	out->common.get_format = out_get_format;
	out->common.set_format = out_set_format;
	out->common.standby = out_standby;
	out->common.dump = out_dump;
	out->common.set_parameters = out_set_parameters;
	out->common.get_parameters = out_get_parameters;
	out->common.add_audio_effect = out_add_audio_effect;
	out->common.remove_audio_effect = out_remove_audio_effect;
	out->get_latency = out_get_latency;
	out->set_volume = out_set_volume;
	out->write = out_write;
	out->get_render_position = out_get_render_position;

	*stream_out = out;

	return 0;
}

static void audio_close_output_stream(struct audio_hw_device *dev,
					struct audio_stream_out *stream)
{
	DBG("");
}

static int audio_set_parameters(struct audio_hw_device *dev,
							const char *kvpairs)
{
	DBG("");
	return -ENOSYS;
}

static char *audio_get_parameters(const struct audio_hw_device *dev,
							const char *keys)
{
	DBG("");
	return strdup("");
}

static int audio_init_check(const struct audio_hw_device *dev)
{
	DBG("");
	return -ENOSYS;
}

static int audio_set_voice_volume(struct audio_hw_device *dev, float volume)
{
	DBG("");
	return -ENOSYS;
}

static int audio_set_master_volume(struct audio_hw_device *dev, float volume)
{
	DBG("");
	return -ENOSYS;
}

static int audio_set_mode(struct audio_hw_device *dev, int mode)
{
	DBG("");
	return -ENOSYS;
}

static int audio_set_mic_mute(struct audio_hw_device *dev, bool state)
{
	DBG("");
	return -ENOSYS;
}

static int audio_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
	DBG("");
	return -ENOSYS;
}

static size_t audio_get_input_buffer_size(const struct audio_hw_device *dev,
					const struct audio_config *config)
{
	DBG("");
	return -ENOSYS;
}

static int audio_open_input_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					struct audio_config *config,
					struct audio_stream_in **stream_in)
{
	struct audio_stream_in *in;

	DBG("");

	in = calloc(1, sizeof(struct audio_stream_in));
	if (!in)
		return -ENOMEM;

	in->common.get_sample_rate = in_get_sample_rate;
	in->common.set_sample_rate = in_set_sample_rate;
	in->common.get_buffer_size = in_get_buffer_size;
	in->common.get_channels = in_get_channels;
	in->common.get_format = in_get_format;
	in->common.set_format = in_set_format;
	in->common.standby = in_standby;
	in->common.dump = in_dump;
	in->common.set_parameters = in_set_parameters;
	in->common.get_parameters = in_get_parameters;
	in->common.add_audio_effect = in_add_audio_effect;
	in->common.remove_audio_effect = in_remove_audio_effect;
	in->set_gain = in_set_gain;
	in->read = in_read;
	in->get_input_frames_lost = in_get_input_frames_lost;

	*stream_in = in;

	return 0;
}

static void audio_close_input_stream(struct audio_hw_device *dev,
					struct audio_stream_in *stream_in)
{
	DBG("");
	free(stream_in);
}

static int audio_dump(const audio_hw_device_t *device, int fd)
{
	DBG("");
	return -ENOSYS;
}

static int audio_close(hw_device_t *device)
{
	DBG("");
	free(device);
	return 0;
}

static int audio_open(const hw_module_t *module, const char *name,
							hw_device_t **device)
{
	struct audio_hw_device *audio;

	DBG("");

	if (strcmp(name, AUDIO_HARDWARE_INTERFACE)) {
		error("interface %s not matching [%s]", name,
						AUDIO_HARDWARE_INTERFACE);
		return -EINVAL;
	}

	audio = calloc(1, sizeof(struct audio_hw_device));
	if (!audio)
		return -ENOMEM;

	audio->common.version = AUDIO_DEVICE_API_VERSION_CURRENT;
	audio->common.module = (struct hw_module_t *) module;
	audio->common.close = audio_close;

	audio->init_check = audio_init_check;
	audio->set_voice_volume = audio_set_voice_volume;
	audio->set_master_volume = audio_set_master_volume;
	audio->set_mode = audio_set_mode;
	audio->set_mic_mute = audio_set_mic_mute;
	audio->get_mic_mute = audio_get_mic_mute;
	audio->set_parameters = audio_set_parameters;
	audio->get_parameters = audio_get_parameters;
	audio->get_input_buffer_size = audio_get_input_buffer_size;
	audio->open_output_stream = audio_open_output_stream;
	audio->close_output_stream = audio_close_output_stream;
	audio->open_input_stream = audio_open_input_stream;
	audio->close_input_stream = audio_close_input_stream;
	audio->dump = audio_dump;

	*device = &audio->common;

	return 0;
}

static struct hw_module_methods_t hal_module_methods = {
	.open = audio_open,
};

struct audio_module HAL_MODULE_INFO_SYM = {
	.common = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = AUDIO_HARDWARE_MODULE_ID,
	.name = "A2DP Bluez HW HAL",
	.author = "Intel Corporation",
	.methods = &hal_module_methods,
	},
};
