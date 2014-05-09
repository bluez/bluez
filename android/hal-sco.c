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

struct sco_dev {
	struct audio_hw_device dev;
};

static int sco_open_output_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					audio_output_flags_t flags,
					struct audio_config *config,
					struct audio_stream_out **stream_out)

{
	DBG("");

	return -EINVAL;
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
