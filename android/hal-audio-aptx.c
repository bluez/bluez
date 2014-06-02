/*
 * Copyright (C) 2014 Tieto Poland
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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

#include "audio-msg.h"
#include "hal-audio.h"
#include "hal-log.h"
#include "src/shared/util.h"
#include "profiles/audio/a2dp-codecs.h"

struct aptx_data {
	a2dp_aptx_t aptx;

	void *enc;
};

static const a2dp_aptx_t aptx_presets[] = {
	{
		.info = {
			.vendor_id = APTX_VENDOR_ID,
			.codec_id = APTX_CODEC_ID,
		},
		.frequency = APTX_SAMPLING_FREQ_44100 |
						APTX_SAMPLING_FREQ_48000,
		.channel_mode = APTX_CHANNEL_MODE_STEREO,
	},
	{
		.info = {
			.vendor_id = APTX_VENDOR_ID,
			.codec_id = APTX_CODEC_ID,
		},
		.frequency = APTX_SAMPLING_FREQ_48000,
		.channel_mode = APTX_CHANNEL_MODE_STEREO,
	},
	{
		.info = {
			.vendor_id = APTX_VENDOR_ID,
			.codec_id = APTX_CODEC_ID,
		},
		.frequency = APTX_SAMPLING_FREQ_44100,
		.channel_mode = APTX_CHANNEL_MODE_STEREO,
	},
};

static bool aptx_load(void)
{
	/* TODO: load aptX codec library */
	return false;
}

static void aptx_unload(void)
{
	/* TODO: unload aptX codec library */
}

static int aptx_get_presets(struct audio_preset *preset, size_t *len)
{
	int i;
	int count;
	size_t new_len = 0;
	uint8_t *ptr = (uint8_t *) preset;
	size_t preset_size = sizeof(*preset) + sizeof(a2dp_aptx_t);

	DBG("");

	count = sizeof(aptx_presets) / sizeof(aptx_presets[0]);

	for (i = 0; i < count; i++) {
		preset = (struct audio_preset *) ptr;

		if (new_len + preset_size > *len)
			break;

		preset->len = sizeof(a2dp_aptx_t);
		memcpy(preset->data, &aptx_presets[i], preset->len);

		new_len += preset_size;
		ptr += preset_size;
	}

	*len = new_len;

	return i;
}

static bool aptx_codec_init(struct audio_preset *preset, uint16_t payload_len,
							void **codec_data)
{
	struct aptx_data *aptx_data;

	DBG("");

	if (preset->len != sizeof(a2dp_aptx_t)) {
		error("APTX: preset size mismatch");
		return false;
	}

	aptx_data = new0(struct aptx_data, 1);
	if (!aptx_data)
		return false;

	memcpy(&aptx_data->aptx, preset->data, preset->len);

	/* TODO: initialize encoder */

	*codec_data = aptx_data;

	return true;
}

static bool aptx_cleanup(void *codec_data)
{
	struct aptx_data *aptx_data = (struct aptx_data *) codec_data;

	free(aptx_data->enc);
	free(codec_data);

	return true;
}

static bool aptx_get_config(void *codec_data, struct audio_input_config *config)
{
	struct aptx_data *aptx_data = (struct aptx_data *) codec_data;

	config->rate = aptx_data->aptx.frequency & APTX_SAMPLING_FREQ_48000 ?
								48000 : 44100;
	config->channels = AUDIO_CHANNEL_OUT_STEREO;
	config->format = AUDIO_FORMAT_PCM_16_BIT;

	return true;
}

static size_t aptx_get_buffer_size(void *codec_data)
{
	/* TODO: return actual value */
	return 0;
}

static size_t aptx_get_mediapacket_duration(void *codec_data)
{
	/* TODO: return actual value */
	return 0;
}

static ssize_t aptx_encode_mediapacket(void *codec_data, const uint8_t *buffer,
					size_t len, struct media_packet *mp,
					size_t mp_data_len, size_t *written)
{
	/* TODO: add encoding */

	return len;
}

static bool aptx_update_qos(void *codec_data, uint8_t op)
{
	/*
	 * aptX has constant bitrate of 352kbps (with constant 4:1 compression
	 * ratio) thus QoS is not possible here.
	 */

	return false;
}

static const struct audio_codec codec = {
	.type = A2DP_CODEC_VENDOR,
	.use_rtp = false,

	.load = aptx_load,
	.unload = aptx_unload,

	.get_presets = aptx_get_presets,

	.init = aptx_codec_init,
	.cleanup = aptx_cleanup,
	.get_config = aptx_get_config,
	.get_buffer_size = aptx_get_buffer_size,
	.get_mediapacket_duration = aptx_get_mediapacket_duration,
	.encode_mediapacket = aptx_encode_mediapacket,
	.update_qos = aptx_update_qos,
};

const struct audio_codec *codec_aptx(void)
{
	return &codec;
}
