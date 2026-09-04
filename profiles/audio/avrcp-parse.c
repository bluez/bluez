// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>

#include "src/log.h"
#include "src/shared/util.h"

#include "avrcp-parse.h"

/*
 * Pull the AVRCP header out of iov and validate that the parameters length
 * it declares matches the number of bytes actually received, leaving iov
 * pointing at the parameters.
 */
struct avrcp_header *avrcp_pull_header(struct iovec *iov)
{
	struct avrcp_header *pdu;

	pdu = util_iov_pull_mem(iov, sizeof(*pdu));
	if (!pdu) {
		error("Invalid AVRCP header");
		return NULL;
	}

	if (be16_to_cpu(pdu->params_len) != iov->iov_len) {
		error("Invalid parameters");
		return NULL;
	}

	return pdu;
}

/*
 * Same as avrcp_pull_header() but for the browsing channel, which uses a
 * different header layout.
 */
struct avrcp_browsing_header *avrcp_pull_browsing_header(struct iovec *iov)
{
	struct avrcp_browsing_header *pdu;

	pdu = util_iov_pull_mem(iov, sizeof(*pdu));
	if (!pdu) {
		error("Invalid AVRCP browsing header");
		return NULL;
	}

	if (be16_to_cpu(pdu->param_len) != iov->iov_len) {
		error("Invalid parameters");
		return NULL;
	}

	return pdu;
}

/*
 * Pull a ListPlayerApplicationSettingAttributes response body out of iov,
 * skipping the attributes that cannot be queried. At most max attributes are
 * written to attrs, which is what bounds the write.
 */
uint8_t avrcp_parse_player_attributes(struct iovec *iov, uint8_t *attrs,
							uint8_t max)
{
	uint8_t len, count = 0;
	int i;

	if (!util_iov_pull_u8(iov, &len))
		return 0;

	len = MIN(len, max);

	for (i = 0; i < len; i++) {
		uint8_t attr;

		if (!util_iov_pull_u8(iov, &attr))
			break;

		/* Don't query invalid attributes */
		if (attr == AVRCP_ATTRIBUTE_ILLEGAL ||
					attr > AVRCP_ATTRIBUTE_LAST)
			continue;

		attrs[count++] = attr;
	}

	return count;
}

void avrcp_parse_attribute_list(struct iovec *iov, uint8_t count,
					avrcp_attribute_func_t func,
					void *user_data)
{
	for (; count > 0; count--) {
		struct avrcp_attribute attr;

		if (!util_iov_pull_be32(iov, &attr.id) ||
				!util_iov_pull_be16(iov, &attr.charset) ||
				!util_iov_pull_be16(iov, &attr.len))
			return;

		attr.value = util_iov_pull_mem(iov, attr.len);
		if (!attr.value)
			return;

		func(&attr, user_data);
	}
}

bool avrcp_parse_media_name(struct iovec *iov, char *name)
{
	uint16_t namelen;
	uint8_t *namebuf;

	if (!util_iov_pull_be16(iov, &namelen))
		return false;

	namebuf = util_iov_pull_mem(iov, namelen);
	if (!namebuf)
		return false;

	namelen = MIN(namelen, NAME_MAX_LEN - 1);

	memset(name, 0, NAME_MAX_LEN);
	memcpy(name, namebuf, namelen);
	strtoutf8(name, namelen);

	return true;
}

bool avrcp_parse_media_element(struct iovec *iov,
					struct avrcp_media_element *element)
{
	/* Skip the media type and character set */
	if (!util_iov_pull_be64(iov, &element->uid) || !util_iov_pull(iov, 3))
		return false;

	if (!avrcp_parse_media_name(iov, element->name))
		return false;

	if (!util_iov_pull_u8(iov, &element->count))
		return false;

	return true;
}

bool avrcp_parse_media_folder(struct iovec *iov,
					struct avrcp_media_folder *folder)
{
	/* Skip the character set */
	if (!util_iov_pull_be64(iov, &folder->uid) ||
			!util_iov_pull_u8(iov, &folder->type) ||
			!util_iov_pull_u8(iov, &folder->playable) ||
			!util_iov_pull(iov, 2))
		return false;

	if (!avrcp_parse_media_name(iov, folder->name))
		return false;

	return true;
}
