/* 
   BlueZ - Bluetooth protocol stack for Linux
   Copyright (C) 2000-2001 Qualcomm Incorporated

   Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
   CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
   COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
   SOFTWARE IS DISCLAIMED.
*/

/*
 * $Id$
 */

#ifndef __HCI_LIB_H
#define __HCI_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

struct hci_request {
	uint16_t ogf;
	uint16_t ocf;
	int      event;
	void     *cparam;
	int      clen;
	void     *rparam;
	int      rlen;
};

struct hci_version {
	uint16_t manufacturer;
	uint8_t  hci_ver;
	uint16_t hci_rev;
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
};

int hci_open_dev(int dev_id);
int hci_close_dev(int dd);
int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param);
int hci_send_req(int dd, struct hci_request *req, int timeout);

int hci_create_connection(int dd, bdaddr_t *ba, uint16_t ptype, uint16_t clkoffset, uint8_t rswitch, uint16_t *handle, int to);
int hci_disconnect(int dd, uint16_t handle, uint8_t reason, int to);

int hci_inquiry(int dev_id, int len, int num_rsp, uint8_t *lap, inquiry_info **ii, long flags);
int hci_devinfo(int dev_id, struct hci_dev_info *di);
int hci_devba(int dev_id, bdaddr_t *ba);
int hci_devid(char *str);

// deprecated: preserve compatibility
int hci_local_name(int dd, int len, char *name, int to);
int hci_read_local_name(int dd, int len, char *name, int to);
int hci_write_local_name(int dd, char *name, int to);
int hci_remote_name(int dd, bdaddr_t *ba, int len, char *name, int to);
int hci_read_remote_name(int dd, bdaddr_t *ba, int len, char *name, int to);
int hci_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to);
int hci_read_remote_version(int dd, uint16_t handle, struct hci_version *ver, int to);
int hci_read_local_version(int dd, struct hci_version *ver, int to);
int hci_read_class_of_dev(int dd, uint8_t *cls, int to);
int hci_write_class_of_dev(int dd, uint32_t cls, int to);
int hci_read_voice_setting(int dd, uint16_t *vs, int to);
int hci_write_voice_setting(int dd, uint16_t vs, int to);
int hci_read_current_iac_lap(int dd, uint8_t *num_iac, uint8_t *lap, int to);
int hci_write_current_iac_lap(int dd, uint8_t num_iac, uint8_t *lap, int to);

int hci_for_each_dev(int flag, int(*func)(int s, int dev_id, long arg), long arg);
int hci_get_route(bdaddr_t *bdaddr);

char *hci_dtypetostr(int type);
char *hci_dflagstostr(uint32_t flags);
char *hci_ptypetostr(unsigned int ptype);
int   hci_strtoptype(char *str, unsigned int *val);
char *hci_lptostr(unsigned int ptype);
int   hci_strtolp(char *str, unsigned int *val);
char *hci_lmtostr(unsigned int ptype);
int   hci_strtolm(char *str, unsigned int *val);

char *hci_vertostr(unsigned int ver);
int   hci_strtover(char *str, unsigned int *ver);
char *lmp_vertostr(unsigned int ver);
int   lmp_strtover(char *str, unsigned int *ver);

char *lmp_featurestostr(uint8_t *features, char *pref, int width);

static inline void hci_set_bit(int nr, void *addr)
{
        *((uint32_t *) addr + (nr >> 5)) |= (1 << (nr & 31));
}

static inline void hci_clear_bit(int nr, void *addr)
{
	*((uint32_t *) addr + (nr >> 5)) &= ~(1 << (nr & 31));
}

static inline int hci_test_bit(int nr, void *addr)
{
	return *((uint32_t *) addr + (nr >> 5)) & (1 << (nr & 31));
}

/* HCI filter tools */
static inline void hci_filter_clear(struct hci_filter *f)
{
	memset(f, 0, sizeof(*f));
}
static inline void hci_filter_set_ptype(int t, struct hci_filter *f)
{
	hci_set_bit((t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_clear_ptype(int t, struct hci_filter *f)
{
	hci_clear_bit((t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline int hci_filter_test_ptype(int t, struct hci_filter *f)
{
	return hci_test_bit((t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_all_ptypes(struct hci_filter *f)
{
	memset((void *)&f->type_mask, 0xff, sizeof(f->type_mask));
}
static inline void hci_filter_set_event(int e, struct hci_filter *f)
{
	hci_set_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_clear_event(int e, struct hci_filter *f)
{
	hci_clear_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline int hci_filter_test_event(int e, struct hci_filter *f)
{
	return hci_test_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_all_events(struct hci_filter *f)
{
	memset((void *)f->event_mask, 0xff, sizeof(f->event_mask));
}
static inline void hci_filter_set_opcode(int opcode, struct hci_filter *f)
{
	f->opcode = opcode;
}
static inline void hci_filter_clear_opcode(struct hci_filter *f)
{
	f->opcode = 0;
}
static inline int hci_filter_test_opcode(int opcode, struct hci_filter *f)
{
	return (f->opcode == opcode);
}

#ifdef __cplusplus
}
#endif

#endif /* __HCI_LIB_H */
