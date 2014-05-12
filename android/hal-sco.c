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
#include <unistd.h>

#include <hardware/audio.h>
#include <hardware/hardware.h>

#include "hal-log.h"

#define AUDIO_STREAM_DEFAULT_RATE	44100
#define AUDIO_STREAM_DEFAULT_FORMAT	AUDIO_FORMAT_PCM_16_BIT

#define OUT_BUFFER_SIZE			2560

struct sco_audio_config {
	uint32_t rate;
	uint32_t channels;
	audio_format_t format;
};

struct sco_stream_out {
	struct audio_stream_out stream;
	struct sco_audio_config cfg;
};

struct sco_dev {
	struct audio_hw_device dev;
	struct sco_stream_out *out;
};

/* Audio stream functions */

static ssize_t out_write(struct audio_stream_out *stream, const void *buffer,
								size_t bytes)
{
	/* write data */

	return bytes;
}

static uint32_t out_get_sample_rate(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;

	DBG("rate %u", out->cfg.rate);

	return out->cfg.rate;
}

static int out_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	DBG("rate %u", rate);

	return 0;
}

static size_t out_get_buffer_size(const struct audio_stream *stream)
{
	DBG("buf size %u", OUT_BUFFER_SIZE);

	return OUT_BUFFER_SIZE;
}

static uint32_t out_get_channels(const struct audio_stream *stream)
{
	DBG("");

	/* AudioFlinger can only provide stereo stream, so we return it here and
	 * later we'll downmix this to mono in case codec requires it
	 */
	return AUDIO_CHANNEL_OUT_STEREO;
}

static audio_format_t out_get_format(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;

	DBG("");

	return out->cfg.format;
}

static int out_set_format(struct audio_stream *stream, audio_format_t format)
{
	DBG("");

	return -ENOSYS;
}

static int out_standby(struct audio_stream *stream)
{
	DBG("");

	return 0;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
	DBG("");

	return -ENOSYS;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	DBG("%s", kvpairs);

	return 0;
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

	return 0;
}

static int out_set_volume(struct audio_stream_out *stream, float left,
								float right)
{
	DBG("");

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

static int sco_open_output_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					audio_output_flags_t flags,
					struct audio_config *config,
					struct audio_stream_out **stream_out)
{
	struct sco_dev *adev = (struct sco_dev *) dev;
	struct sco_stream_out *out;

	DBG("");

	out = calloc(1, sizeof(struct sco_stream_out));
	if (!out)
		return -ENOMEM;

	out->stream.common.get_sample_rate = out_get_sample_rate;
	out->stream.common.set_sample_rate = out_set_sample_rate;
	out->stream.common.get_buffer_size = out_get_buffer_size;
	out->stream.common.get_channels = out_get_channels;
	out->stream.common.get_format = out_get_format;
	out->stream.common.set_format = out_set_format;
	out->stream.common.standby = out_standby;
	out->stream.common.dump = out_dump;
	out->stream.common.set_parameters = out_set_parameters;
	out->stream.common.get_parameters = out_get_parameters;
	out->stream.common.add_audio_effect = out_add_audio_effect;
	out->stream.common.remove_audio_effect = out_remove_audio_effect;
	out->stream.get_latency = out_get_latency;
	out->stream.set_volume = out_set_volume;
	out->stream.write = out_write;
	out->stream.get_render_position = out_get_render_position;

	out->cfg.format = AUDIO_STREAM_DEFAULT_FORMAT;
	out->cfg.channels = AUDIO_CHANNEL_OUT_MONO;
	out->cfg.rate = AUDIO_STREAM_DEFAULT_RATE;

	*stream_out = &out->stream;
	adev->out = out;

	return 0;
}

static void sco_close_output_stream(struct audio_hw_device *dev,
					struct audio_stream_out *stream_out)
{
	DBG("");

	free(stream_out);
}

static int sco_set_parameters(struct audio_hw_device *dev,
							const char *kvpairs)
{
	DBG("%s", kvpairs);

	return 0;
}

static char *sco_get_parameters(const struct audio_hw_device *dev,
							const char *keys)
{
	DBG("");

	return strdup("");
}

static int sco_init_check(const struct audio_hw_device *dev)
{
	DBG("");

	return 0;
}

static int sco_set_voice_volume(struct audio_hw_device *dev, float volume)
{
	DBG("%f", volume);

	return 0;
}

static int sco_set_master_volume(struct audio_hw_device *dev, float volume)
{
	DBG("%f", volume);

	return 0;
}

static int sco_set_mode(struct audio_hw_device *dev, int mode)
{
	DBG("");

	return -ENOSYS;
}

static int sco_set_mic_mute(struct audio_hw_device *dev, bool state)
{
	DBG("");

	return -ENOSYS;
}

static int sco_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
	DBG("");

	return -ENOSYS;
}

static size_t sco_get_input_buffer_size(const struct audio_hw_device *dev,
					const struct audio_config *config)
{
	DBG("");

	return -ENOSYS;
}

static int sco_open_input_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					struct audio_config *config,
					struct audio_stream_in **stream_in)
{
	DBG("");

	return 0;
}

static void sco_close_input_stream(struct audio_hw_device *dev,
					struct audio_stream_in *stream_in)
{
	DBG("");

	free(stream_in);
}

static int sco_dump(const audio_hw_device_t *device, int fd)
{
	DBG("");

	return 0;
}

static int sco_close(hw_device_t *device)
{
	DBG("");

	free(device);

	return 0;
}

static int sco_open(const hw_module_t *module, const char *name,
							hw_device_t **device)
{
	struct sco_dev *dev;

	DBG("");

	if (strcmp(name, AUDIO_HARDWARE_INTERFACE)) {
		error("SCO: interface %s not matching [%s]", name,
						AUDIO_HARDWARE_INTERFACE);
		return -EINVAL;
	}

	dev = calloc(1, sizeof(struct sco_dev));
	if (!dev)
		return -ENOMEM;

	dev->dev.common.tag = HARDWARE_DEVICE_TAG;
	dev->dev.common.version = AUDIO_DEVICE_API_VERSION_CURRENT;
	dev->dev.common.module = (struct hw_module_t *) module;
	dev->dev.common.close = sco_close;

	dev->dev.init_check = sco_init_check;
	dev->dev.set_voice_volume = sco_set_voice_volume;
	dev->dev.set_master_volume = sco_set_master_volume;
	dev->dev.set_mode = sco_set_mode;
	dev->dev.set_mic_mute = sco_set_mic_mute;
	dev->dev.get_mic_mute = sco_get_mic_mute;
	dev->dev.set_parameters = sco_set_parameters;
	dev->dev.get_parameters = sco_get_parameters;
	dev->dev.get_input_buffer_size = sco_get_input_buffer_size;
	dev->dev.open_output_stream = sco_open_output_stream;
	dev->dev.close_output_stream = sco_close_output_stream;
	dev->dev.open_input_stream = sco_open_input_stream;
	dev->dev.close_input_stream = sco_close_input_stream;
	dev->dev.dump = sco_dump;

	*device = &dev->dev.common;

	return 0;
}

static struct hw_module_methods_t hal_module_methods = {
	.open = sco_open,
};

struct audio_module HAL_MODULE_INFO_SYM = {
	.common = {
		.tag = HARDWARE_MODULE_TAG,
		.version_major = 1,
		.version_minor = 0,
		.id = AUDIO_HARDWARE_MODULE_ID,
		.name = "SCO Audio HW HAL",
		.author = "Intel Corporation",
		.methods = &hal_module_methods,
	},
};
