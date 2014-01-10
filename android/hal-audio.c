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
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <hardware/audio.h>
#include <hardware/hardware.h>

#include "audio-msg.h"
#include "hal-log.h"

static int audio_sk = -1;
static bool close_thread = false;

static pthread_t ipc_th = 0;
static pthread_mutex_t close_mutex = PTHREAD_MUTEX_INITIALIZER;

struct a2dp_audio_dev {
	struct audio_hw_device dev;
	struct audio_stream_out *out;
};

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
	struct a2dp_audio_dev *a2dp_dev = (struct a2dp_audio_dev *) dev;
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
	a2dp_dev->out = out;

	return 0;
}

static void audio_close_output_stream(struct audio_hw_device *dev,
					struct audio_stream_out *stream)
{
	struct a2dp_audio_dev *a2dp_dev = (struct a2dp_audio_dev *) dev;

	DBG("");

	free(stream);
	a2dp_dev->out = NULL;
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
	struct a2dp_audio_dev *a2dp_dev = (struct a2dp_audio_dev *)device;

	DBG("");

	pthread_mutex_lock(&close_mutex);
	shutdown(audio_sk, SHUT_RDWR);
	close_thread = true;
	pthread_mutex_unlock(&close_mutex);

	pthread_join(ipc_th, NULL);

	free(a2dp_dev);
	return 0;
}

static bool create_audio_ipc(void)
{
	struct sockaddr_un addr;
	int err;
	int sk;

	DBG("");

	sk = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		err = errno;
		error("audio: Failed to create socket: %d (%s)", err,
								strerror(err));
		return false;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_AUDIO_SK_PATH,
					sizeof(BLUEZ_AUDIO_SK_PATH));

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("audio: Failed to bind socket: %d (%s)", err,
								strerror(err));
		goto failed;
	}

	if (listen(sk, 1) < 0) {
		err = errno;
		error("audio: Failed to listen on the socket: %d (%s)", err,
								strerror(err));
		goto failed;
	}

	audio_sk = accept(sk, NULL, NULL);
	if (audio_sk < 0) {
		err = errno;
		error("audio: Failed to accept socket: %d (%s)", err, strerror(err));
		goto failed;
	}

	close(sk);
	return true;

failed:
	close(sk);
	return false;
}

static void *ipc_handler(void *data)
{
	bool done = false;
	struct pollfd pfd;

	DBG("");

	while (!done) {
		if(!create_audio_ipc()) {
			error("audio: Failed to create listening socket");
			sleep(1);
			continue;
		}

		DBG("Audio IPC: Connected");

		/* TODO: Register ENDPOINT here */

		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = audio_sk;
		pfd.events = POLLHUP | POLLERR | POLLNVAL;

		/* Check if socket is still alive. Empty while loop.*/
		while (poll(&pfd, 1, -1) < 0 && errno == EINTR);

		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			info("Audio HAL: Socket closed");
			audio_sk = -1;
		}

		/*Check if audio_dev is closed */
		pthread_mutex_lock(&close_mutex);
		done = close_thread;
		close_thread = false;
		pthread_mutex_unlock(&close_mutex);
	}

	info("Closing bluetooth_watcher thread");
	return NULL;
}

static int audio_open(const hw_module_t *module, const char *name,
							hw_device_t **device)
{
	struct a2dp_audio_dev *a2dp_dev;
	int err;

	DBG("");

	if (strcmp(name, AUDIO_HARDWARE_INTERFACE)) {
		error("audio: interface %s not matching [%s]", name,
						AUDIO_HARDWARE_INTERFACE);
		return -EINVAL;
	}

	a2dp_dev = calloc(1, sizeof(struct a2dp_audio_dev));
	if (!a2dp_dev)
		return -ENOMEM;

	a2dp_dev->dev.common.version = AUDIO_DEVICE_API_VERSION_CURRENT;
	a2dp_dev->dev.common.module = (struct hw_module_t *) module;
	a2dp_dev->dev.common.close = audio_close;

	a2dp_dev->dev.init_check = audio_init_check;
	a2dp_dev->dev.set_voice_volume = audio_set_voice_volume;
	a2dp_dev->dev.set_master_volume = audio_set_master_volume;
	a2dp_dev->dev.set_mode = audio_set_mode;
	a2dp_dev->dev.set_mic_mute = audio_set_mic_mute;
	a2dp_dev->dev.get_mic_mute = audio_get_mic_mute;
	a2dp_dev->dev.set_parameters = audio_set_parameters;
	a2dp_dev->dev.get_parameters = audio_get_parameters;
	a2dp_dev->dev.get_input_buffer_size = audio_get_input_buffer_size;
	a2dp_dev->dev.open_output_stream = audio_open_output_stream;
	a2dp_dev->dev.close_output_stream = audio_close_output_stream;
	a2dp_dev->dev.open_input_stream = audio_open_input_stream;
	a2dp_dev->dev.close_input_stream = audio_close_input_stream;
	a2dp_dev->dev.dump = audio_dump;

	/* Note that &a2dp_dev->dev.common is the same pointer as a2dp_dev.
	 * This results from the structure of following structs:a2dp_audio_dev,
	 * audio_hw_device. We will rely on this later in the code.*/
	*device = &a2dp_dev->dev.common;

	err = pthread_create(&ipc_th, NULL, ipc_handler, NULL);
	if (err) {
		ipc_th = 0;
		error("audio: Failed to start Audio IPC thread: %d (%s)",
							err, strerror(err));
		return (-err);
	}

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
