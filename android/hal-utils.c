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

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hal-utils.h"

/*
 * converts uuid to string
 * buf should be at least 39 bytes
 *
 * returns string representation of uuid
 */
const char *bt_uuid_t2str(const uint8_t *uuid, char *buf)
{
	int shift = 0;
	unsigned int i;
	int is_bt;

	is_bt = !memcmp(&uuid[4], &BT_BASE_UUID[4], HAL_UUID_LEN - 4);

	for (i = 0; i < HAL_UUID_LEN; i++) {
		if (i == 4 && is_bt)
			break;

		if (i == 4 || i == 6 || i == 8 || i == 10) {
			buf[i * 2 + shift] = '-';
			shift++;
		}
		sprintf(buf + i * 2 + shift, "%02x", uuid[i]);
	}

	return buf;
}

const char *btuuid2str(const uint8_t *uuid)
{
	static char buf[MAX_UUID_STR_LEN];

	return bt_uuid_t2str(uuid, buf);
}
