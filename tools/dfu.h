/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>

/* CRC interface */
uint32_t crc32_init(void);
uint32_t crc32_byte(uint32_t accum, uint8_t delta);

/* DFU descriptor */
struct usb_dfu_descriptor {
	u_int8_t  bLength;
	u_int8_t  bDescriptorType;
	u_int8_t  bmAttributes;
	u_int16_t wDetachTimeout;
	u_int16_t wTransferSize;
};

/* DFU commands */
#define DFU_DETACH		0
#define DFU_DNLOAD		1
#define DFU_UPLOAD		2
#define DFU_GETSTATUS		3
#define DFU_CLRSTATUS		4
#define DFU_GETSTATE		5
#define DFU_ABORT		6

/* DFU status */
struct dfu_status {
	uint8_t bStatus;
	uint8_t bwPollTimeout[3];
	uint8_t bState;
	uint8_t iString;
} __attribute__ ((packed));
#define DFU_STATUS_SIZE 6

/* DFU status */
#define DFU_OK			0x00
#define DFU_ERR_TARGET		0x01
#define DFU_ERR_FILE		0x02
#define DFU_ERR_WRITE		0x03
#define DFU_ERR_ERASE		0x04
#define DFU_ERR_CHECK_ERASED	0x05
#define DFU_ERR_PROG		0x06
#define DFU_ERR_VERIFY		0x07
#define DFU_ERR_ADDRESS		0x08
#define DFU_ERR_NOTDONE		0x09
#define DFU_ERR_FIRMWARE	0x0a
#define DFU_ERR_VENDOR		0x0b
#define DFU_ERR_USBR		0x0c
#define DFU_ERR_POR		0x0d
#define DFU_ERR_UNKNOWN		0x0e
#define DFU_ERR_STALLEDPKT	0x0f

/* DFU state */
#define DFU_STATE_APP_IDLE		0
#define DFU_STATE_APP_DETACH		1
#define DFU_STATE_DFU_IDLE		2
#define DFU_STATE_DFU_DNLOAD_SYNC	3
#define DFU_STATE_DFU_DNLOAD_BUSY	4
#define DFU_STATE_DFU_DNLOAD_IDLE	5
#define DFU_STATE_DFU_MANIFEST_SYNC	6
#define DFU_STATE_DFU_MANIFEST		7
#define DFU_STATE_MANIFEST_WAIT_RESET	8
#define DFU_STATE_UPLOAD_IDLE		9
#define DFU_STATE_ERROR			10

/* DFU suffix */
struct dfu_suffix {
	uint16_t bcdDevice;
	uint16_t idProduct;
	uint16_t idVendor;
	uint16_t bcdDFU;
	uint8_t  ucDfuSignature[3];
	uint8_t  bLength;
	uint32_t dwCRC;
} __attribute__ ((packed));
#define DFU_SUFFIX_SIZE 16

/* DFU interface */
int dfu_detach(struct usb_dev_handle *udev, int intf);
int dfu_upload(struct usb_dev_handle *udev, int intf, int block, char *buffer, int size);
int dfu_download(struct usb_dev_handle *udev, int intf, int block, char *buffer, int size);
int dfu_get_status(struct usb_dev_handle *udev, int intf, struct dfu_status *status);
int dfu_clear_status(struct usb_dev_handle *udev, int intf);
int dfu_get_state(struct usb_dev_handle *udev, int intf, uint8_t *state);
int dfu_abort(struct usb_dev_handle *udev, int intf);
