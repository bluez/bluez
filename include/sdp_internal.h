/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifndef __SDP_INTERNAL_H
#define __SDP_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bluetooth/bluetooth.h>

#define SDPINF(fmt, arg...) syslog(LOG_INFO, fmt "\n", ## arg)
#define SDPERR(fmt, arg...) syslog(LOG_ERR, "%s: " fmt "\n", __func__ , ## arg)

#ifdef SDP_DEBUG
#define SDPDBG(fmt, arg...) syslog(LOG_DEBUG, "%s: " fmt "\n", __func__ , ## arg)
#else
#define SDPDBG(fmt...)
#endif

#define SDP_BASIC_ATTR_PDUFORM_SIZE 32
#define SDP_SEQ_PDUFORM_SIZE 128
#define SDP_UUID_SEQ_SIZE 256
#define SDP_MAX_ATTR_LEN 65535

/*
 * Generate unique transaction identifiers
 */
static inline uint16_t sdp_gen_tid(sdp_session_t *session)
{
	return session->tid++;
}

sdp_record_t *sdp_extract_pdu(const char *pdata, int *scanned);
sdp_data_t *sdp_extract_string(char *, int *);

void sdp_data_print(sdp_data_t *data);
void sdp_print_service_attr(sdp_list_t *alist);

int  sdp_attrid_comp_func(const void *key1, const void *key2);

void sdp_set_seq_len(char *ptr, int length);
void sdp_set_attrid(sdp_buf_t *pdu, uint16_t id);
void sdp_append_to_pdu(sdp_buf_t *dst, sdp_data_t *d);
void sdp_append_to_buf(sdp_buf_t *dst, char *data, int len);

int sdp_gen_pdu(sdp_buf_t *pdu, sdp_data_t *data);
int sdp_gen_record_pdu(const sdp_record_t *rec, sdp_buf_t *pdu);

int sdp_extract_seqtype(const char *buf, uint8_t *dtdp, int *seqlen);

sdp_data_t *sdp_extract_attr(const char *pdata, int *extractedLength, sdp_record_t *rec);

void sdp_pattern_add_uuid(sdp_record_t *rec, uuid_t *uuid);
void sdp_pattern_add_uuidseq(sdp_record_t *rec, sdp_list_t *seq);

int sdp_send_req_w4_rsp(sdp_session_t *session, char *req, char *rsp, int reqsize, int *rspsize);

typedef struct {
	uint8_t length;
	unsigned char data[16];
} __attribute__ ((packed)) sdp_cstate_t;

/* 
 * SDP unaligned access. 
 * based on linux/asm-<arch>/unaligned.h
 */
#if defined(__i386__)

#define sdp_get_unaligned(ptr) (*(ptr))
#define sdp_put_unaligned(val, ptr) ((void)( *(ptr) = (val) ))

#else

struct __una_u64 { uint64_t x; } __attribute__((packed));
struct __una_u32 { uint32_t x; } __attribute__((packed));
struct __una_u16 { uint16_t x; } __attribute__((packed));

static inline unsigned long long __uldq(const unsigned long *r11)
{
	const struct __una_u64 *ptr = (const struct __una_u64 *) r11;
	return ptr->x;
}

static inline unsigned long __uldl(const unsigned int * r11)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *) r11;
	return ptr->x;
}

static inline unsigned long __uldw(const unsigned short * r11)
{
	const struct __una_u16 *ptr = (const struct __una_u16 *) r11;
	return ptr->x;
}

static inline void __ustq(unsigned long r5, unsigned long * r11)
{
	struct __una_u64 *ptr = (struct __una_u64 *) r11;
	ptr->x = r5;
}

static inline void __ustl(unsigned long r5, unsigned int * r11)
{
	struct __una_u32 *ptr = (struct __una_u32 *) r11;
	ptr->x = r5;
}

static inline void __ustw(unsigned long r5, unsigned short * r11)
{
	struct __una_u16 *ptr = (struct __una_u16 *) r11;
	ptr->x = r5;
}

static inline unsigned long long __sdp_get_unaligned(const void *ptr, size_t size)
{
	unsigned long long val = 0;
	switch (size) {
	case 1:
		val = *(const unsigned char *)ptr;
		break;
	case 2:
		val = __uldw((const unsigned short *)ptr);
		break;
	case 4:
		val = __uldl((const unsigned int *)ptr);
		break;
	case 8:
		val = __uldq((const unsigned long *)ptr);
		break;
	}
	return val;
}

static inline void __sdp_put_unaligned(unsigned long val, void *ptr, size_t size)
{
	switch (size) {
	case 1:
		*(unsigned char *)ptr = (val);
		break;
	case 2:
		__ustw(val, (unsigned short *)ptr);
		break;
	case 4:
		__ustl(val, (unsigned int *)ptr);
		break;
	case 8:
		__ustq(val, (unsigned long *)ptr);
		break;
	}
}

#define sdp_get_unaligned(ptr) \
	((__typeof__(*(ptr)))__sdp_get_unaligned((ptr), sizeof(*(ptr))))

#define sdp_put_unaligned(x,ptr) \
	__sdp_put_unaligned((unsigned long)(x), (ptr), sizeof(*(ptr)))

#endif 

#if __BYTE_ORDER == __BIG_ENDIAN
#define ntoh64(x) x
static inline void ntoh128(uint128_t *src, uint128_t *dst)
{
	int i;
	for (i = 0; i < 16; i++)
		dst->data[i] = src->data[i];
}
#else
static inline uint64_t ntoh64(uint64_t n)
{
	uint64_t h;
	uint64_t tmp = ntohl(n & 0x00000000ffffffff);
	h = ntohl(n >> 32);
	h |= tmp << 32;
	return h;
}

static inline void ntoh128(uint128_t *src, uint128_t *dst)
{
	int i;
	for (i = 0; i < 16; i++)
		dst->data[15 - i] = src->data[i];
}
#endif

#define hton64(x) ntoh64(x)
#define hton128(x,y) ntoh128(x,y)

#ifdef __cplusplus
}
#endif

#endif /* __SDP_INTERNAL_H */
