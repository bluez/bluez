/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include <stdint.h>
#include <stdbool.h>

struct l2cap_frame {
	uint16_t index;
	bool in;
	uint16_t handle;
	uint8_t ident;
	uint16_t cid;
	uint16_t psm;
	uint16_t chan;
	uint8_t mode;
	uint8_t seq_num;
	const void *data;
	uint16_t size;
};

void l2cap_frame_init(struct l2cap_frame *frame, uint16_t index, bool in,
				uint16_t handle, uint8_t ident,
				uint16_t cid, uint16_t psm,
				const void *data, uint16_t size);

static inline void l2cap_frame_clone_size(struct l2cap_frame *frame,
				const struct l2cap_frame *source,
				uint16_t size)
{
	if (frame != source) {
		frame->index   = source->index;
		frame->in      = source->in;
		frame->handle  = source->handle;
		frame->ident   = source->ident;
		frame->cid     = source->cid;
		frame->psm     = source->psm;
		frame->chan    = source->chan;
		frame->mode    = source->mode;
		frame->data    = source->data;
		frame->size    = size;
	}
}

static inline void l2cap_frame_clone(struct l2cap_frame *frame,
				const struct l2cap_frame *source)
{
	l2cap_frame_clone_size(frame, source, source->size);
}

static inline void *l2cap_frame_pull(struct l2cap_frame *frame,
				const struct l2cap_frame *source, uint16_t len)
{
	void *data;

	l2cap_frame_clone(frame, source);

	if (source->size < len)
		return NULL;

	data = (void *)frame->data;
	frame->data = source->data + len;
	frame->size = source->size - len;

	return data;
}

static inline bool l2cap_frame_get_u8(struct l2cap_frame *frame, uint8_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = *((uint8_t *) frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_u8(struct l2cap_frame *frame,
					const char *label)
{
	uint8_t u8;

	if (!l2cap_frame_get_u8(frame, &u8)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%2.2x", label, u8);

	return true;
}

static inline bool l2cap_frame_get_be16(struct l2cap_frame *frame,
								uint16_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_be16(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_be16(struct l2cap_frame *frame,
						const char *label)
{
	uint16_t u16;

	if (!l2cap_frame_get_be16(frame, &u16)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%4.4x", label, u16);

	return true;
}

static inline bool l2cap_frame_get_le16(struct l2cap_frame *frame,
								uint16_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_le16(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_le16(struct l2cap_frame *frame,
						const char *label)
{
	uint16_t u16;

	if (!l2cap_frame_get_le16(frame, &u16)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%4.4x", label, u16);

	return true;
}

static inline bool l2cap_frame_get_be24(struct l2cap_frame *frame,
								uint32_t *value)
{
	if (frame->size < sizeof(uint24_t))
		return false;

	if (value)
		*value = get_be24(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(uint24_t));

	return true;
}

static inline bool l2cap_frame_print_be24(struct l2cap_frame *frame,
						const char *label)
{
	uint32_t u24;

	if (!l2cap_frame_get_be24(frame, &u24)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%6.6x", label, u24);

	return true;
}

static inline bool l2cap_frame_get_le24(struct l2cap_frame *frame,
								uint32_t *value)
{
	if (frame->size < sizeof(uint24_t))
		return false;

	if (value)
		*value = get_le24(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(uint24_t));

	return true;
}

static inline bool l2cap_frame_print_le24(struct l2cap_frame *frame,
						const char *label)
{
	uint32_t u24;

	if (!l2cap_frame_get_le24(frame, &u24)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%6.6x", label, u24);

	return true;
}

static inline bool l2cap_frame_get_be32(struct l2cap_frame *frame,
								uint32_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_be32(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_be32(struct l2cap_frame *frame,
						const char *label)
{
	uint32_t u32;

	if (!l2cap_frame_get_be32(frame, &u32)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%8.8x", label, u32);

	return true;
}

static inline bool l2cap_frame_get_le32(struct l2cap_frame *frame,
								uint32_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_le32(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_le32(struct l2cap_frame *frame,
						const char *label)
{
	uint32_t u32;

	if (!l2cap_frame_get_le32(frame, &u32)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%8.8x", label, u32);

	return true;
}

static inline bool l2cap_frame_get_be64(struct l2cap_frame *frame,
								uint64_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_be64(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_be64(struct l2cap_frame *frame,
						const char *label)
{
	uint64_t u64;

	if (!l2cap_frame_get_be64(frame, &u64)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%" PRIx64, label, u64);

	return true;
}

static inline bool l2cap_frame_get_le64(struct l2cap_frame *frame,
								uint64_t *value)
{
	if (frame->size < sizeof(*value))
		return false;

	if (value)
		*value = get_le64(frame->data);

	l2cap_frame_pull(frame, frame, sizeof(*value));

	return true;
}

static inline bool l2cap_frame_print_le64(struct l2cap_frame *frame,
						const char *label)
{
	uint64_t u64;

	if (!l2cap_frame_get_le64(frame, &u64)) {
		print_text(COLOR_ERROR, "%s: invalid size", label);
		return false;
	}

	print_field("%s: 0x%" PRIx64, label, u64);

	return true;
}

static inline bool l2cap_frame_get_be128(struct l2cap_frame *frame,
					uint64_t *lvalue, uint64_t *rvalue)
{
	if (frame->size < (sizeof(*lvalue) + sizeof(*rvalue)))
		return false;

	if (lvalue && rvalue) {
		*lvalue = get_be64(frame->data);
		*rvalue = get_be64(frame->data);
	}

	l2cap_frame_pull(frame, frame, (sizeof(*lvalue) + sizeof(*rvalue)));

	return true;
}

void l2cap_frame(uint16_t index, bool in, uint16_t handle, uint16_t cid,
		uint16_t psm, const void *data, uint16_t size);

void l2cap_packet(uint16_t index, bool in, uint16_t handle, uint8_t flags,
					const void *data, uint16_t size);

void rfcomm_packet(const struct l2cap_frame *frame);
