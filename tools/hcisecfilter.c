/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

int main(void)
{
	uint32_t type_mask;
	uint32_t event_mask[2];
	uint32_t ocf_mask[4];

	/* Packet types */
	memset((void *)&type_mask, 0, sizeof(type_mask));
	hci_set_bit(HCI_EVENT_PKT, &type_mask);

	printf("Type mask: { 0x%x }\n", type_mask); 

	/* Events */
	memset((void *)event_mask, 0, sizeof(event_mask));
	hci_set_bit(EVT_INQUIRY_COMPLETE, event_mask);
	hci_set_bit(EVT_INQUIRY_RESULT,   event_mask);

	hci_set_bit(EVT_CONN_COMPLETE, event_mask);
	hci_set_bit(EVT_CONN_REQUEST,  event_mask);
	hci_set_bit(EVT_DISCONN_COMPLETE, event_mask);

	hci_set_bit(EVT_AUTH_COMPLETE,  event_mask);
	hci_set_bit(EVT_ENCRYPT_CHANGE, event_mask);

	hci_set_bit(EVT_CMD_COMPLETE, event_mask);
	hci_set_bit(EVT_CMD_STATUS,   event_mask);

	hci_set_bit(EVT_READ_REMOTE_FEATURES_COMPLETE, event_mask);
	hci_set_bit(EVT_READ_REMOTE_VERSION_COMPLETE,  event_mask);
	hci_set_bit(EVT_REMOTE_NAME_REQ_COMPLETE,      event_mask);

	printf("Event mask: { 0x%x, 0x%x }\n", event_mask[0], event_mask[1]); 

	/* OGF_LINK_CTL */
	memset((void *) ocf_mask, 0, sizeof(ocf_mask));
	hci_set_bit(OCF_INQUIRY, ocf_mask);
	hci_set_bit(OCF_REMOTE_NAME_REQ, ocf_mask);
	hci_set_bit(OCF_READ_REMOTE_FEATURES, ocf_mask);
	hci_set_bit(OCF_READ_REMOTE_VERSION,  ocf_mask);

	printf("OGF_LINK_CTL: { 0x%x, 0x%x, 0x%x, 0x%x }\n",
			ocf_mask[0], ocf_mask[1], ocf_mask[2], ocf_mask[3]); 

	/* OGF_LINK_POLICY */
	memset((void *) ocf_mask, 0, sizeof(ocf_mask));
	hci_set_bit(OCF_ROLE_DISCOVERY,   ocf_mask);
	hci_set_bit(OCF_READ_LINK_POLICY, ocf_mask);

	printf("OGF_LINK_POLICY: { 0x%x, 0x%x, 0x%x, 0x%x }\n",
			ocf_mask[0], ocf_mask[1], ocf_mask[2], ocf_mask[3]);

	/* OGF_HOST_CTL */
	memset((void *) ocf_mask, 0, sizeof(ocf_mask));
	hci_set_bit(OCF_READ_AUTH_ENABLE, ocf_mask);
	hci_set_bit(OCF_READ_ENCRYPT_MODE, ocf_mask);
	hci_set_bit(OCF_READ_LOCAL_NAME, ocf_mask);
	hci_set_bit(OCF_READ_CLASS_OF_DEV, ocf_mask);
	hci_set_bit(OCF_READ_VOICE_SETTING, ocf_mask);
	hci_set_bit(OCF_READ_TRANSMIT_POWER_LEVEL, ocf_mask);

	printf("OGF_HOST_CTL: { 0x%x, 0x%x, 0x%x, 0x%x }\n",
			ocf_mask[0], ocf_mask[1], ocf_mask[2], ocf_mask[3]); 

	/* OGF_INFO_PARAM */
	memset((void *) ocf_mask, 0, sizeof(ocf_mask));
	hci_set_bit(OCF_READ_LOCAL_VERSION, ocf_mask);
	hci_set_bit(OCF_READ_LOCAL_FEATURES, ocf_mask);
	hci_set_bit(OCF_READ_BUFFER_SIZE, ocf_mask);
	hci_set_bit(OCF_READ_BD_ADDR, ocf_mask);
	hci_set_bit(OCF_READ_BD_ADDR, ocf_mask);

	printf("OGF_INFO_PARAM: { 0x%x, 0x%x, 0x%x, 0x%x}\n", 
			ocf_mask[0], ocf_mask[1], ocf_mask[2], ocf_mask[3]); 

	/* OGF_INFO_PARAM */
	memset((void *) ocf_mask, 0, sizeof(ocf_mask));
	hci_set_bit(OCF_READ_FAILED_CONTACT_COUNTER, ocf_mask);
	hci_set_bit(OCF_RESET_FAILED_CONTACT_COUNTER, ocf_mask);
	hci_set_bit(OCF_GET_LINK_QUALITY, ocf_mask);
	hci_set_bit(OCF_READ_RSSI, ocf_mask);

	printf("OGF_STATUS_PARAM: { 0x%x, 0x%x, 0x%x, 0x%x}\n", 
			ocf_mask[0], ocf_mask[1], ocf_mask[2], ocf_mask[3]); 

	return 0;
}
