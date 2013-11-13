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

btsock_interface_t *bt_get_sock_interface(void);
bthh_interface_t *bt_get_hidhost_interface(void);
btpan_interface_t *bt_get_pan_interface(void);
btav_interface_t *bt_get_a2dp_interface(void);

void bt_notify_adapter(uint8_t opcode, void *buf, uint16_t len);
void bt_thread_associate(void);
void bt_thread_disassociate(void);
void bt_notify_hidhost(uint8_t opcode, void *buf, uint16_t len);
void bt_notify_a2dp(uint8_t opcode, void *buf, uint16_t len);
void bt_notify_pan(uint8_t opcode, void *buf, uint16_t len);
