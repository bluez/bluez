/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_hh.h>
#include <hardware/bt_pan.h>
#include <hardware/bt_av.h>
#include <hardware/bt_rc.h>
#include <hardware/bt_hf.h>
#include <hardware/bt_gatt.h>
#include <hardware/bt_gatt_client.h>
#include <hardware/bt_gatt_server.h>
#include <hardware/bt_hl.h>

#ifdef BLUEZ_EXTENSIONS
#include <hardware/bt_hf_client.h>
#endif

btsock_interface_t *bt_get_socket_interface(void);
bthh_interface_t *bt_get_hidhost_interface(void);
btpan_interface_t *bt_get_pan_interface(void);
btav_interface_t *bt_get_a2dp_interface(void);
btrc_interface_t *bt_get_avrcp_interface(void);
bthf_interface_t *bt_get_handsfree_interface(void);
btgatt_interface_t *bt_get_gatt_interface(void);
bthl_interface_t *bt_get_health_interface(void);

#ifdef BLUEZ_EXTENSIONS
bthf_client_interface_t *bt_get_hf_client_interface(void);
#endif

void bt_thread_associate(void);
void bt_thread_disassociate(void);
