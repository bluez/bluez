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

#define CSR_VARID_BC01_STATUS		0x2801		/* uint16 */
#define CSR_VARID_BUILDID		0x2819		/* uint16 */
#define CSR_VARID_CHIPVER		0x281a		/* uint16 */
#define CSR_VARID_CHIPREV		0x281b		/* uint16 */
#define CSR_VARID_INTERFACE_VERSION	0x2825		/* uint16 */
#define CSR_VARID_RAND			0x282a		/* uint16 */
#define CSR_VARID_MAX_CRYPT_KEY_LENGTH	0x282c		/* uint16 */
#define CSR_VARID_CHIPANAREV		0x2836		/* uint16 */
#define CSR_VARID_BUILDID_LOADER	0x2838		/* uint16 */
#define CSR_VARID_BT_CLOCK		0x2c00		/* uint32 */
#define CSR_VARID_CRYPT_KEY_LENGTH	0x3008		/* complex */
#define CSR_VARID_PICONET_INSTANCE	0x3009		/* complex */
#define CSR_VARID_GET_CLR_EVT		0x300a		/* complex */
#define CSR_VARID_GET_NEXT_BUILDDEF	0x300b		/* complex */
#define CSR_VARID_COLD_RESET		0x4001		/* valueless */
#define CSR_VARID_WARM_RESET		0x4002		/* valueless */
#define CSR_VARID_COLD_HALT		0x4003		/* valueless */
#define CSR_VARID_WARM_HALT		0x4004		/* valueless */
#define CSR_VARID_INIT_BT_STACK		0x4005		/* valueless */
#define CSR_VARID_ACTIVATE_BT_STACK	0x4006		/* valueless */
#define CSR_VARID_ENABLE_TX		0x4007		/* valueless */
#define CSR_VARID_DISABLE_TX		0x4008		/* valueless */
#define CSR_VARID_RECAL			0x4009		/* valueless */
#define CSR_VARID_CANCEL_PAGE		0x4012		/* valueless */
#define CSR_VARID_MAP_SCO_PCM		0x481c		/* uint16 */
#define CSR_VARID_NO_VARIABLE		0x6000		/* valueless */
#define CSR_VARID_CONFIG_UART		0x6802		/* uint16 */
#define CSR_VARID_PANIC_ARG		0x6805		/* uint16 */
#define CSR_VARID_FAULT_ARG		0x6806		/* uint16 */
#define CSR_VARID_MAX_TX_POWER		0x6827		/* int8 */
#define CSR_VARID_DEFAULT_TX_POWER	0x682b		/* int8 */

#define CSR_PSKEY_ENC_KEY_LMIN			0x00da	/* uint16 */
#define CSR_PSKEY_ENC_KEY_LMAX			0x00db	/* uint16 */
#define CSR_PSKEY_LOCAL_SUPPORTED_FEATURES	0x00ef	/* uint16[] = { 0xffff, 0xfe8f, 0xf99b, 0x8000 } */
#define CSR_PSKEY_LOCAL_SUPPORTED_COMMANDS	0x0106	/* uint16[] = { 0xffff, 0x03ff, 0xfffe, 0xffff, 0xffff, 0xffff, 0x0ff3, 0xfff8, 0x003f } */
#define CSR_PSKEY_HCI_LMP_LOCAL_VERSION		0x010d	/* uint16 */
#define CSR_PSKEY_LMP_REMOTE_VERSION		0x010e	/* uint8 */
#define CSR_PSKEY_HOSTIO_USE_HCI_EXTN		0x01a5	/* bool (uint16) */
#define CSR_PSKEY_HOSTIO_MAP_SCO_PCM		0x01ab	/* bool (uint16) */
#define CSR_PSKEY_UART_BAUDRATE			0x01be	/* uint16 */
#define CSR_PSKEY_ANA_FTRIM			0x01f6	/* uint16 */
#define CSR_PSKEY_HOST_INTERFACE		0x01f9	/* uint16 */
#define CSR_PSKEY_ANA_FREQ			0x01fe	/* uint16 */
#define CSR_PSKEY_USB_VENDOR_ID			0x02be	/* uint16 */
#define CSR_PSKEY_USB_PRODUCT_ID		0x02bf	/* uint16 */
#define CSR_PSKEY_USB_DFU_PRODUCT_ID		0x02cb	/* uint16 */
#define CSR_PSKEY_INITIAL_BOOTMODE		0x03cd	/* int16 */

char *csr_buildidtostr(uint16_t id);
char *csr_chipvertostr(uint16_t ver, uint16_t rev);
char *csr_pskeytostr(uint16_t pskey);

int csr_write_varid_valueless(int dd, uint16_t seqnum, uint16_t varid);
int csr_read_varid_complex(int dd, uint16_t seqnum, uint16_t varid, uint8_t *value, uint16_t length);
int csr_read_varid_uint16(int dd, uint16_t seqnum, uint16_t varid, uint16_t *value);
int csr_read_varid_uint32(int dd, uint16_t seqnum, uint16_t varid, uint32_t *value);
int csr_read_pskey_complex(int dd, uint16_t seqnum, uint16_t pskey, uint16_t store, uint8_t *value, uint16_t length);
int csr_write_pskey_complex(int dd, uint16_t seqnum, uint16_t pskey, uint16_t store, uint8_t *value, uint16_t length);
int csr_read_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t store, uint16_t *value);
int csr_write_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t store, uint16_t value);
