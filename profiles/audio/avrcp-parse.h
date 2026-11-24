/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#ifndef __AVRCP_PARSE_H
#define __AVRCP_PARSE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#define NAME_MAX_LEN 255

/* player attributes */
#define AVRCP_ATTRIBUTE_ILLEGAL		0x00
#define AVRCP_ATTRIBUTE_EQUALIZER	0x01
#define AVRCP_ATTRIBUTE_REPEAT_MODE	0x02
#define AVRCP_ATTRIBUTE_SHUFFLE		0x03
#define AVRCP_ATTRIBUTE_SCAN		0x04
#define AVRCP_ATTRIBUTE_LAST		AVRCP_ATTRIBUTE_SCAN

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t packet_type:2;
	uint8_t rsvd:6;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avrcp_header {
	uint8_t company_id[3];
	uint8_t pdu_id;
	uint8_t rsvd:6;
	uint8_t packet_type:2;
	uint16_t params_len;
	uint8_t params[0];
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

#define AVRCP_HEADER_LENGTH 7

struct avrcp_browsing_header {
	uint8_t pdu_id;
	uint16_t param_len;
	uint8_t params[0];
} __attribute__ ((packed));
#define AVRCP_BROWSING_HEADER_LENGTH 3

struct avrcp_attribute {
	uint32_t id;
	uint16_t charset;
	uint16_t len;
	uint8_t *value;
};

struct avrcp_media_element {
	uint64_t uid;
	char name[NAME_MAX_LEN];
	uint8_t count;
};

struct avrcp_media_folder {
	uint64_t uid;
	uint8_t type;
	uint8_t playable;
	char name[NAME_MAX_LEN];
};

typedef void (*avrcp_attribute_func_t)(const struct avrcp_attribute *attr,
							void *user_data);

struct avrcp_header *avrcp_pull_header(struct iovec *iov);
struct avrcp_browsing_header *avrcp_pull_browsing_header(struct iovec *iov);

uint8_t avrcp_parse_player_attributes(struct iovec *iov, uint8_t *attrs,
							uint8_t max);

void avrcp_parse_attribute_list(struct iovec *iov, uint8_t count,
					avrcp_attribute_func_t func,
					void *user_data);

bool avrcp_parse_media_name(struct iovec *iov, char *name);
bool avrcp_parse_media_element(struct iovec *iov,
					struct avrcp_media_element *element);
bool avrcp_parse_media_folder(struct iovec *iov,
					struct avrcp_media_folder *folder);

#endif /* __AVRCP_PARSE_H */
