/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2005  Marcel Holtmann <marcel@holtmann.org>
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

#define CSR_VARID_BUILDID		0x2819
#define CSR_VARID_CHIPVER		0x281a
#define CSR_VARID_CHIPREV		0x281b
#define CSR_VARID_MAX_CRYPT_KEY_LENGTH	0x282c

#define CSR_VARID_PANIC_ARG		0x6805
#define CSR_VARID_FAULT_ARG		0x6806

#define CSR_PSKEY_HOSTIO_MAP_SCO_PCM	0x01ab
#define CSR_PSKEY_HOST_INTERFACE	0x01f9
#define CSR_PSKEY_USB_VENDOR_ID		0x02be
#define CSR_PSKEY_USB_PRODUCT_ID	0x02bf
#define CSR_PSKEY_INITIAL_BOOTMODE	0x03cd

char *csr_buildidtostr(uint16_t id);
char *csr_chipvertostr(uint16_t ver, uint16_t rev);
char *csr_pskeytostr(uint16_t pskey);

int csr_read_varid_uint16(int dd, uint16_t seqnum, uint16_t varid, uint16_t *value);
int csr_read_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t *value);
int csr_write_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t value);
