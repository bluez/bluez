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
#include <arpa/inet.h>

#include <hardware/audio.h>
#include <hardware/hardware.h>

#include <sbc/sbc.h>

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

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct rtp_header {
	unsigned cc:4;
	unsigned x:1;
	unsigned p:1;
	unsigned v:2;

	unsigned pt:7;
	unsigned m:1;

	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} __attribute__ ((packed));

struct rtp_payload {
	unsigned frame_count:4;
	unsigned rfa0:1;
	unsigned is_last_fragment:1;
	unsigned is_first_fragment:1;
	unsigned is_fragmented:1;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct rtp_header {
	unsigned v:2;
	unsigned p:1;
	unsigned x:1;
	unsigned cc:4;

	unsigned m:1;
	unsigned pt:7;

	uint16_t sequence_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} __attribute__ ((packed));

struct rtp_payload {
	unsigned is_fragmented:1;
	unsigned is_first_fragment:1;
	unsigned is_last_fragment:1;
	unsigned rfa0:1;
	unsigned frame_count:4;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

struct media_packet {
	struct rtp_header hdr;
	struct rtp_payload payload;
	uint8_t data[0];
};

struct audio_input_config {
	uint32_t rate;
	uint32_t channels;
	audio_format_t format;
};

struct sbc_data {
	a2dp_sbc_t sbc;

	sbc_t enc;

	size_t in_frame_len;
	size_t in_buf_size;

	size_t out_buf_size;
	uint8_t *out_buf;

	unsigned frame_duration;

	struct timespec start;
	unsigned frames_sent;

	uint16_t seq;
};

static inline void timespec_diff(struct timespec *a, struct timespec *b,
					struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;

	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += 1000000000; /* 1sec */
	}
}

static int sbc_get_presets(struct audio_preset *preset, size_t *len);
static int sbc_codec_init(struct audio_preset *preset, uint16_t mtu,
				void **codec_data);
static int sbc_cleanup(void *codec_data);
static int sbc_get_config(void *codec_data,
					struct audio_input_config *config);
static size_t sbc_get_buffer_size(void *codec_data);
static void sbc_resume(void *codec_data);
static ssize_t sbc_write_data(void *codec_data, const void *buffer,
					size_t bytes, int fd);

struct audio_codec {
	uint8_t type;

	int (*get_presets) (struct audio_preset *preset, size_t *len);

	int (*init) (struct audio_preset *preset, uint16_t mtu,
				void **codec_data);
	int (*cleanup) (void *codec_data);
	int (*get_config) (void *codec_data,
					struct audio_input_config *config);
	size_t (*get_buffer_size) (void *codec_data);
	void (*resume) (void *codec_data);
	ssize_t (*write_data) (void *codec_data, const void *buffer,
				size_t bytes, int fd);
};

static const struct audio_codec audio_codecs[] = {
	{
		.type = A2DP_CODEC_SBC,

		.get_presets = sbc_get_presets,

		.init = sbc_codec_init,
		.cleanup = sbc_cleanup,
		.get_config = sbc_get_config,
		.get_buffer_size = sbc_get_buffer_size,
		.resume = sbc_resume,
		.write_data = sbc_write_data,
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

enum a2dp_state_t {
	AUDIO_A2DP_STATE_NONE,
	AUDIO_A2DP_STATE_STANDBY,
	AUDIO_A2DP_STATE_SUSPENDED,
	AUDIO_A2DP_STATE_STARTED
};

struct a2dp_stream_out {
	struct audio_stream_out stream;

	struct audio_endpoint *ep;
	enum a2dp_state_t audio_state;
	struct audio_input_config cfg;
};

struct a2dp_audio_dev {
	struct audio_hw_device dev;
	struct a2dp_stream_out *out;
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

static void sbc_init_encoder(struct sbc_data *sbc_data)
{
	a2dp_sbc_t *in = &sbc_data->sbc;
	sbc_t *out = &sbc_data->enc;

	DBG("");

	sbc_init_a2dp(out, 0L, in, sizeof(*in));

	out->endian = SBC_LE;
	out->bitpool = in->max_bitpool;
}

static int sbc_codec_init(struct audio_preset *preset, uint16_t mtu,
				void **codec_data)
{
	struct sbc_data *sbc_data;
	size_t hdr_len = sizeof(struct media_packet);
	size_t in_frame_len;
	size_t out_frame_len;
	size_t num_frames;

	DBG("");

	if (preset->len != sizeof(a2dp_sbc_t)) {
		DBG("preset size mismatch");
		return AUDIO_STATUS_FAILED;
	}

	sbc_data = calloc(sizeof(struct sbc_data), 1);

	memcpy(&sbc_data->sbc, preset->data, preset->len);

	sbc_init_encoder(sbc_data);

	in_frame_len = sbc_get_codesize(&sbc_data->enc);
	out_frame_len = sbc_get_frame_length(&sbc_data->enc);
	num_frames = (mtu - hdr_len) / out_frame_len;

	sbc_data->in_frame_len = in_frame_len;
	sbc_data->in_buf_size = num_frames * in_frame_len;

	sbc_data->out_buf_size = hdr_len + num_frames * out_frame_len;
	sbc_data->out_buf = calloc(1, sbc_data->out_buf_size);

	sbc_data->frame_duration = sbc_get_frame_duration(&sbc_data->enc);

	*codec_data = sbc_data;

	return AUDIO_STATUS_SUCCESS;
}

static int sbc_cleanup(void *codec_data)
{
	struct sbc_data *sbc_data = (struct sbc_data *) codec_data;

	DBG("");

	sbc_finish(&sbc_data->enc);
	free(sbc_data->out_buf);
	free(codec_data);

	return AUDIO_STATUS_SUCCESS;
}

static int sbc_get_config(void *codec_data,
					struct audio_input_config *config)
{
	struct sbc_data *sbc_data = (struct sbc_data *) codec_data;

	switch (sbc_data->sbc.frequency) {
	case SBC_SAMPLING_FREQ_16000:
		config->rate = 16000;
		break;
	case SBC_SAMPLING_FREQ_32000:
		config->rate = 32000;
		break;
	case SBC_SAMPLING_FREQ_44100:
		config->rate = 44100;
		break;
	case SBC_SAMPLING_FREQ_48000:
		config->rate = 48000;
		break;
	default:
		return AUDIO_STATUS_FAILED;
	}
	config->channels = sbc_data->sbc.channel_mode == SBC_CHANNEL_MODE_MONO ?
				AUDIO_CHANNEL_OUT_MONO :
				AUDIO_CHANNEL_OUT_STEREO;
	config->format = AUDIO_FORMAT_PCM_16_BIT;

	return AUDIO_STATUS_SUCCESS;
}

static size_t sbc_get_buffer_size(void *codec_data)
{
	struct sbc_data *sbc_data = (struct sbc_data *) codec_data;

	DBG("");

	return sbc_data->in_buf_size;
}

static void sbc_resume(void *codec_data)
{
	struct sbc_data *sbc_data = (struct sbc_data *) codec_data;

	DBG("");

	clock_gettime(CLOCK_MONOTONIC, &sbc_data->start);

	sbc_data->frames_sent = 0;
}

static ssize_t sbc_write_data(void *codec_data, const void *buffer,
				size_t bytes, int fd)
{
	struct sbc_data *sbc_data = (struct sbc_data *) codec_data;
	size_t consumed = 0;
	size_t encoded = 0;
	struct media_packet *mp = (struct media_packet *) sbc_data->out_buf;
	size_t free_space = sbc_data->out_buf_size - sizeof(*mp);
	struct timespec cur;
	struct timespec diff;
	unsigned expected_frames;
	int ret;

	mp->hdr.v = 2;
	mp->hdr.pt = 1;
	mp->hdr.sequence_number = htons(sbc_data->seq++);
	mp->hdr.ssrc = htonl(1);
	mp->payload.frame_count = 0;

	while (bytes - consumed >= sbc_data->in_frame_len) {
		ssize_t written = 0;

		ret = sbc_encode(&sbc_data->enc, buffer + consumed,
					sbc_data->in_frame_len,
					mp->data + encoded, free_space,
					&written);

		if (ret < 0) {
			DBG("failed to encode block");
			break;
		}

		mp->payload.frame_count++;

		consumed += ret;
		encoded += written;
		free_space -= written;
	}

	ret = write(fd, mp, sizeof(*mp) + encoded);
	if (ret < 0) {
		int err = errno;
		DBG("error writing data: %d (%s)", err, strerror(err));
	}

	if (consumed != bytes || free_space != 0) {
		/* we should encode all input data and fill output buffer
		 * if we did not, something went wrong but we can't really
		 * handle this so this is just sanity check
		 */
		DBG("some data were not encoded");
	}

	sbc_data->frames_sent += mp->payload.frame_count;

	clock_gettime(CLOCK_MONOTONIC, &cur);
	timespec_diff(&cur, &sbc_data->start, &diff);
	expected_frames = (diff.tv_sec * 1000000 + diff.tv_nsec / 1000) /
				sbc_data->frame_duration;

	/* AudioFlinger does not seem to provide any *working* API to provide
	 * data in some interval and will just send another buffer as soon as
	 * we process current one. To prevent overflowing L2CAP socket, we need
	 * to introduce some artificial delay here base on how many audio frames
	 * were sent so far, i.e. if we're not lagging behind audio stream, we
	 * can sleep for duration of single media packet.
	 */
	if (sbc_data->frames_sent >= expected_frames)
		usleep(sbc_data->frame_duration * mp->payload.frame_count);

	/* we always assume that all data was processed and sent */
	return bytes;
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

static int ipc_open_stream_cmd(uint8_t endpoint_id, uint16_t *mtu, int *fd,
					struct audio_preset **caps)
{
	char buf[BLUEZ_AUDIO_MTU];
	struct audio_cmd_open_stream cmd;
	struct audio_rsp_open_stream *rsp =
					(struct audio_rsp_open_stream *) &buf;
	size_t rsp_len = sizeof(buf);
	int result;

	DBG("");

	if (!caps)
		return AUDIO_STATUS_FAILED;

	cmd.id = endpoint_id;

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_OPEN_STREAM,
				sizeof(cmd), &cmd, &rsp_len, rsp, fd);

	if (result == AUDIO_STATUS_SUCCESS) {
		size_t buf_len = sizeof(struct audio_preset) +
					rsp->preset[0].len;
		*mtu = rsp->mtu;
		*caps = malloc(buf_len);
		memcpy(*caps, &rsp->preset, buf_len);
	} else {
		*caps = NULL;
	}

	return result;
}

static int ipc_close_stream_cmd(uint8_t endpoint_id)
{
	struct audio_cmd_close_stream cmd;
	int result;

	DBG("");

	cmd.id = endpoint_id;

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_CLOSE_STREAM,
				sizeof(cmd), &cmd, NULL, NULL, NULL);

	return result;
}

static int ipc_resume_stream_cmd(uint8_t endpoint_id)
{
	struct audio_cmd_resume_stream cmd;
	int result;

	DBG("");

	cmd.id = endpoint_id;

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_RESUME_STREAM,
				sizeof(cmd), &cmd, NULL, NULL, NULL);

	return result;
}

static int ipc_suspend_stream_cmd(uint8_t endpoint_id)
{
	struct audio_cmd_suspend_stream cmd;
	int result;

	DBG("");

	cmd.id = endpoint_id;

	result = audio_ipc_cmd(AUDIO_SERVICE_ID, AUDIO_OP_SUSPEND_STREAM,
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
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	/* We can auto-start only from standby */
	if (out->audio_state == AUDIO_A2DP_STATE_STANDBY) {
		DBG("stream in standby, auto-start");

		if (ipc_resume_stream_cmd(out->ep->id) != AUDIO_STATUS_SUCCESS)
			return -1;

		out->ep->codec->resume(out->ep->codec_data);

		out->audio_state = AUDIO_A2DP_STATE_STARTED;
	}

	if (out->audio_state != AUDIO_A2DP_STATE_STARTED) {
		DBG("stream not started");
		return -1;
	}

	if (out->ep->fd < 0) {
		DBG("no transport");
		return -1;
	}

	return out->ep->codec->write_data(out->ep->codec_data, buffer,
						bytes, out->ep->fd);
}

static uint32_t out_get_sample_rate(const struct audio_stream *stream)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	DBG("");

	return out->cfg.rate;
}

static int out_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	DBG("");

	if (rate != out->cfg.rate) {
		DBG("cannot set sample rate to %d", rate);
		return -1;
	}

	return 0;
}

static size_t out_get_buffer_size(const struct audio_stream *stream)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	DBG("");

	return out->ep->codec->get_buffer_size(out->ep->codec_data);
}

static uint32_t out_get_channels(const struct audio_stream *stream)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	DBG("");

	return out->cfg.channels;
}

static audio_format_t out_get_format(const struct audio_stream *stream)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

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
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;

	DBG("");

	if (out->audio_state == AUDIO_A2DP_STATE_STARTED) {
		if (ipc_suspend_stream_cmd(out->ep->id) != AUDIO_STATUS_SUCCESS)
			return -1;
		out->audio_state = AUDIO_A2DP_STATE_STANDBY;
	}

	return 0;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
	DBG("");
	return -ENOSYS;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	struct a2dp_stream_out *out = (struct a2dp_stream_out *) stream;
	char *kvpair;
	char *str;
	char *saveptr;
	bool enter_suspend = false;
	bool exit_suspend = false;

	DBG("%s", kvpairs);

	str = strdup(kvpairs);
	kvpair = strtok_r(str, ";", &saveptr);

	for (; kvpair && *kvpair; kvpair = strtok_r(NULL, ";", &saveptr)) {
		char *keyval;

		keyval = strchr(kvpair, '=');
		if (!keyval)
			continue;

		*keyval = '\0';
		keyval++;

		if (!strcmp(kvpair, "closing")) {
			if (!strcmp(keyval, "true"))
				out->audio_state = AUDIO_A2DP_STATE_NONE;
		} else if (!strcmp(kvpair, "A2dpSuspended")) {
			if (!strcmp(keyval, "true"))
				enter_suspend = true;
			else
				exit_suspend = true;
		}
	}

	free(str);

	if (enter_suspend && out->audio_state == AUDIO_A2DP_STATE_STARTED) {
		if (ipc_suspend_stream_cmd(out->ep->id) != AUDIO_STATUS_SUCCESS)
			return -1;
		out->audio_state = AUDIO_A2DP_STATE_SUSPENDED;
	}

	if (exit_suspend && out->audio_state == AUDIO_A2DP_STATE_SUSPENDED)
		out->audio_state = AUDIO_A2DP_STATE_STANDBY;

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
	struct a2dp_stream_out *out;
	struct audio_preset *preset;
	const struct audio_codec *codec;
	uint16_t mtu;
	int fd;

	out = calloc(1, sizeof(struct a2dp_stream_out));
	if (!out)
		return -ENOMEM;

	DBG("");

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

	/* TODO: for now we always use endpoint 0 */
	out->ep = &audio_endpoints[0];

	if (ipc_open_stream_cmd(out->ep->id, &mtu, &fd, &preset) !=
			AUDIO_STATUS_SUCCESS)
		goto fail;

	if (!preset || fd < 0)
		goto fail;

	out->ep->fd = fd;

	codec = out->ep->codec;

	codec->init(preset, mtu, &out->ep->codec_data);
	codec->get_config(out->ep->codec_data, &out->cfg);

	DBG("rate=%d channels=%d format=%d", out->cfg.rate,
			out->cfg.channels, out->cfg.format);

	free(preset);

	*stream_out = &out->stream;
	a2dp_dev->out = out;

	out->audio_state = AUDIO_A2DP_STATE_STANDBY;

	return 0;

fail:
	free(out);
	*stream_out = NULL;
	return -EIO;
}

static void audio_close_output_stream(struct audio_hw_device *dev,
					struct audio_stream_out *stream)
{
	struct a2dp_audio_dev *a2dp_dev = (struct a2dp_audio_dev *) dev;
	struct audio_endpoint *ep = a2dp_dev->out->ep;

	DBG("");

	ipc_close_stream_cmd(ep->id);

	if (ep->fd >= 0) {
		close(ep->fd);
		ep->fd = -1;
	}

	ep->codec->cleanup(ep->codec_data);
	ep->codec_data = NULL;

	free(stream);
	a2dp_dev->out = NULL;
}

static int audio_set_parameters(struct audio_hw_device *dev,
							const char *kvpairs)
{
	struct a2dp_audio_dev *a2dp_dev = (struct a2dp_audio_dev *) dev;
	struct a2dp_stream_out *out = a2dp_dev->out;

	DBG("");

	if (!out)
		return 0;

	return out->stream.common.set_parameters((struct audio_stream *) out,
							kvpairs);
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
	return 0;
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

	a2dp_dev->dev.common.tag = HARDWARE_DEVICE_TAG;
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
