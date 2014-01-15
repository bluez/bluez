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
#include "hal-msg.h"
#include "../profiles/audio/a2dp-codecs.h"

static const uint8_t a2dp_src_uuid[] = {
		0x00, 0x00, 0x11, 0x0a, 0x00, 0x00, 0x10, 0x00,
		0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb };

static int listen_sk = -1;
static int audio_sk = -1;
static bool close_thread = false;

static pthread_t ipc_th = 0;
static pthread_mutex_t close_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sk_mutex = PTHREAD_MUTEX_INITIALIZER;

struct audio_input_config {
	uint32_t rate;
	uint32_t channels;
	audio_format_t format;
};

static int sbc_get_presets(struct audio_preset *preset, size_t *len);

struct audio_codec {
	uint8_t type;

	int (*get_presets) (struct audio_preset *preset, size_t *len);

	int (*init) (struct audio_preset *preset, void **codec_data);
	int (*cleanup) (void *codec_data);
	int (*get_config) (void *codec_data,
					struct audio_input_config *config);
	ssize_t (*write_data) (void *codec_data, const void *buffer,
				size_t bytes);
};

static const struct audio_codec audio_codecs[] = {
	{
		.type = A2DP_CODEC_SBC,

		.get_presets = sbc_get_presets,
	}
};

#define NUM_CODECS (sizeof(audio_codecs) / sizeof(audio_codecs[0]))

#define MAX_AUDIO_ENDPOINTS NUM_CODECS

struct audio_endpoint {
	uint8_t id;
	const struct audio_codec *codec;
	void *codec_data;
	int fd;
};

static struct audio_endpoint audio_endpoints[MAX_AUDIO_ENDPOINTS];

struct a2dp_audio_dev {
	struct audio_hw_device dev;
	struct audio_stream_out *out;
};

static const a2dp_sbc_t sbc_presets[] = {
	{
		.frequency = SBC_SAMPLING_FREQ_44100 | SBC_SAMPLING_FREQ_48000,
		.channel_mode = SBC_CHANNEL_MODE_MONO |
				SBC_CHANNEL_MODE_DUAL_CHANNEL |
				SBC_CHANNEL_MODE_STEREO |
				SBC_CHANNEL_MODE_JOINT_STEREO,
		.subbands = SBC_SUBBANDS_4 | SBC_SUBBANDS_8,
		.allocation_method = SBC_ALLOCATION_SNR |
					SBC_ALLOCATION_LOUDNESS,
		.block_length = SBC_BLOCK_LENGTH_4 | SBC_BLOCK_LENGTH_8 |
				SBC_BLOCK_LENGTH_12 | SBC_BLOCK_LENGTH_16,
		.min_bitpool = MIN_BITPOOL,
		.max_bitpool = MAX_BITPOOL
	},
	{
		.frequency = SBC_SAMPLING_FREQ_44100,
		.channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO,
		.subbands = SBC_SUBBANDS_8,
		.allocation_method = SBC_ALLOCATION_LOUDNESS,
		.block_length = SBC_BLOCK_LENGTH_16,
		.min_bitpool = MIN_BITPOOL,
		.max_bitpool = MAX_BITPOOL
	},
	{
		.frequency = SBC_SAMPLING_FREQ_48000,
		.channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO,
		.subbands = SBC_SUBBANDS_8,
		.allocation_method = SBC_ALLOCATION_LOUDNESS,
		.block_length = SBC_BLOCK_LENGTH_16,
		.min_bitpool = MIN_BITPOOL,
		.max_bitpool = MAX_BITPOOL
	},
};

static int sbc_get_presets(struct audio_preset *preset, size_t *len)
{
	int i;
	int count;
	size_t new_len = 0;
	uint8_t *ptr = (uint8_t *) preset;
	size_t preset_size = sizeof(*preset) + sizeof(a2dp_sbc_t);

	DBG("");

	count = sizeof(sbc_presets) / sizeof(sbc_presets[0]);

	for (i = 0; i < count; i++) {
		preset = (struct audio_preset *) ptr;

		if (new_len + preset_size > *len)
			break;

		preset->len = sizeof(a2dp_sbc_t);
		memcpy(preset->data, &sbc_presets[i], preset->len);

		new_len += preset_size;
		ptr += preset_size;
	}

	*len = new_len;

	return i;
}

static void audio_ipc_cleanup(void)
{
	if (audio_sk >= 0) {
		shutdown(audio_sk, SHUT_RDWR);
		audio_sk = -1;
	}
}

static int audio_ipc_cmd(uint8_t service_id, uint8_t opcode, uint16_t len,
			void *param, size_t *rsp_len, void *rsp, int *fd)
{
	ssize_t ret;
	struct msghdr msg;
	struct iovec iv[2];
	struct hal_hdr cmd;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct hal_status s;
	size_t s_len = sizeof(s);

	if (audio_sk < 0) {
		error("audio: Invalid cmd socket passed to audio_ipc_cmd");
		goto failed;
	}

	if (!rsp || !rsp_len) {
		memset(&s, 0, s_len);
		rsp_len = &s_len;
		rsp = &s;
	}

	memset(&msg, 0, sizeof(msg));
	memset(&cmd, 0, sizeof(cmd));

	cmd.service_id = service_id;
	cmd.opcode = opcode;
	cmd.len = len;

	iv[0].iov_base = &cmd;
	iv[0].iov_len = sizeof(cmd);

	iv[1].iov_base = param;
	iv[1].iov_len = len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	pthread_mutex_lock(&sk_mutex);

	ret = sendmsg(audio_sk, &msg, 0);
	if (ret < 0) {
		error("audio: Sending command failed:%s", strerror(errno));
		pthread_mutex_unlock(&sk_mutex);
		goto failed;
	}

	/* socket was shutdown */
	if (ret == 0) {
		error("audio: Command socket closed");
		goto failed;
	}

	memset(&msg, 0, sizeof(msg));
	memset(&cmd, 0, sizeof(cmd));

	iv[0].iov_base = &cmd;
	iv[0].iov_len = sizeof(cmd);

	iv[1].iov_base = rsp;
	iv[1].iov_len = *rsp_len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	if (fd) {
		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
	}

	ret = recvmsg(audio_sk, &msg, 0);
	if (ret < 0) {
		error("audio: Receiving command response failed:%s",
							strerror(errno));
		pthread_mutex_unlock(&sk_mutex);
		goto failed;
	}

	pthread_mutex_unlock(&sk_mutex);

	if (ret < (ssize_t) sizeof(cmd)) {
		error("audio: Too small response received(%zd bytes)", ret);
		goto failed;
	}

	if (cmd.service_id != service_id) {
		error("audio: Invalid service id (%u vs %u)", cmd.service_id,
								service_id);
		goto failed;
	}

	if (ret != (ssize_t) (sizeof(cmd) + cmd.len)) {
		error("audio: Malformed response received(%zd bytes)", ret);
		goto failed;
	}

	if (cmd.opcode != opcode && cmd.opcode != AUDIO_OP_STATUS) {
		error("audio: Invalid opcode received (%u vs %u)",
						cmd.opcode, opcode);
		goto failed;
	}

	if (cmd.opcode == AUDIO_OP_STATUS) {
		struct hal_status *s = rsp;

		if (sizeof(*s) != cmd.len) {
			error("audio: Invalid status length");
			goto failed;
		}

		if (s->code == AUDIO_STATUS_SUCCESS) {
			error("audio: Invalid success status response");
			goto failed;
		}

		return s->code;
	}

	/* Receive auxiliary data in msg */
	if (fd) {
		struct cmsghdr *cmsg;

		*fd = -1;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET
					&& cmsg->cmsg_type == SCM_RIGHTS) {
				memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
				break;
			}
		}
	}

	if (rsp_len)
		*rsp_len = cmd.len;

	return AUDIO_STATUS_SUCCESS;

failed:
	/* Some serious issue happen on IPC - recover */
	shutdown(audio_sk, SHUT_RDWR);
	audio_sk = -1;
	return AUDIO_STATUS_FAILED;
}

static int ipc_open_cmd(const struct audio_codec *codec)
{
	uint8_t buf[BLUEZ_AUDIO_MTU];
	struct audio_cmd_open *cmd = (struct audio_cmd_open *) buf;
	struct audio_rsp_open rsp;
	size_t cmd_len = sizeof(buf) - sizeof(*cmd);
	size_t rsp_len = sizeof(rsp);
	int result;

	DBG("");

	memcpy(cmd->uuid, a2dp_src_uuid, sizeof(a2dp_src_uuid));

	cmd->codec = codec->type;
	cmd->presets = codec->get_presets(cmd->preset, &cmd_len);

	cmd_len += sizeof(*cmd);

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_OPEN, cmd_len, cmd,
				&rsp_len, &rsp, NULL);

	if (result != AUDIO_STATUS_SUCCESS)
		return 0;

	return rsp.id;
}

static int ipc_close_cmd(uint8_t endpoint_id)
{
	struct audio_cmd_close cmd;
	int result;

	DBG("");

	cmd.id = endpoint_id;

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_CLOSE,
				sizeof(cmd), &cmd, NULL, NULL, NULL);

	return result;
}

static int register_endpoints(void)
{
	struct audio_endpoint *ep = &audio_endpoints[0];
	size_t i;

	for (i = 0; i < NUM_CODECS; i++, ep++) {
		const struct audio_codec *codec = &audio_codecs[i];

		ep->id = ipc_open_cmd(codec);

		if (!ep->id)
			return AUDIO_STATUS_FAILED;

		ep->codec = codec;
		ep->codec_data = NULL;
		ep->fd = -1;
	}

	return AUDIO_STATUS_SUCCESS;
}

static void unregister_endpoints(void)
{
	size_t i;

	for (i = 0; i < MAX_AUDIO_ENDPOINTS; i++) {
		struct audio_endpoint *ep = &audio_endpoints[i];

		if (ep->id) {
			ipc_close_cmd(ep->id);
			memset(ep, 0, sizeof(*ep));
		}
	}
}

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
	audio_ipc_cleanup();
	close_thread = true;
	pthread_mutex_unlock(&close_mutex);

	pthread_join(ipc_th, NULL);

	close(listen_sk);
	listen_sk = -1;

	free(a2dp_dev);
	return 0;
}

static void *ipc_handler(void *data)
{
	bool done = false;
	struct pollfd pfd;

	DBG("");

	while (!done) {
		DBG("Waiting for connection ...");
		audio_sk = accept(listen_sk, NULL, NULL);
		if (audio_sk < 0) {
			int err = errno;
			error("audio: Failed to accept socket: %d (%s)", err,
								strerror(err));
			continue;
		}

		DBG("Audio IPC: Connected");

		if (register_endpoints() != AUDIO_STATUS_SUCCESS) {
			error("audio: Failed to register endpoints");

			unregister_endpoints();

			shutdown(audio_sk, SHUT_RDWR);
			continue;
		}

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

	unregister_endpoints();

	info("Closing Audio IPC thread");
	return NULL;
}

static int audio_ipc_init(void)
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
		return err;
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

	listen_sk = sk;

	err = pthread_create(&ipc_th, NULL, ipc_handler, NULL);
	if (err) {
		err = -err;
		ipc_th = 0;
		error("audio: Failed to start Audio IPC thread: %d (%s)",
							err, strerror(err));
		goto failed;
	}

	return 0;

failed:
	close(sk);
	return err;
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

	err = audio_ipc_init();
	if (err)
		return -err;

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
