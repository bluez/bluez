/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 ST-Ericsson SA
 *
 *  Author: Waldemar Rymarkiewicz <waldemar.rymarkiewicz@tieto.com>
 *          for ST-Ericsson
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
 */

#include "log.h"
#include "sap.h"

void sap_connect_req(void *sap_device, uint16_t maxmsgsize)
{
	sap_connect_rsp(sap_device, SAP_STATUS_OK, maxmsgsize);
	sap_status_ind(sap_device, SAP_STATUS_CHANGE_CARD_RESET);
}

void sap_disconnect_req(void *sap_device, uint8_t linkloss)
{
	sap_disconnect_rsp(sap_device);
}

void sap_transfer_apdu_req(void *sap_device, struct sap_parameter *param)
{
	sap_transfer_apdu_rsp(sap_device, SAP_RESULT_OK, NULL, 0);
}

void sap_transfer_atr_req(void *sap_device)
{
	sap_transfer_atr_rsp(sap_device, SAP_RESULT_OK, NULL, 0);
}

void sap_power_sim_off_req(void *sap_device)
{
	sap_power_sim_off_rsp(sap_device, SAP_RESULT_OK);
}

void sap_power_sim_on_req(void *sap_device)
{
	sap_power_sim_on_rsp(sap_device, SAP_RESULT_OK);
}

void sap_reset_sim_req(void *sap_device)
{
	sap_reset_sim_rsp(sap_device, SAP_RESULT_OK);
	sap_status_ind(sap_device, SAP_STATUS_CHANGE_CARD_RESET);
}

void sap_transfer_card_reader_status_req(void *sap_device)
{
	sap_transfer_card_reader_status_rsp(sap_device, SAP_RESULT_OK,
						ICC_READER_CARD_POWERED_ON);
}

void sap_set_transport_protocol_req(void *sap_device,
					struct sap_parameter *param)
{
	sap_transport_protocol_rsp(sap_device, SAP_RESULT_NOT_SUPPORTED);
}

int sap_init(void)
{
	DBG("SAP driver init.");
	return 0;
}

void sap_exit(void)
{
	DBG("SAP driver exit.");
}
