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

/* PAN scripts & commands */
#define PAND_CONFIG_DIR  "/etc/bluetooth/pan"
#define PAND_DEVUP_CMD   "dev-up"

/* BNEP functions */
int bnep_init(void);
int bnep_cleanup(void);

int bnep_str2svc(char *svc, uint16_t *uuid);
char *bnep_svc2str(uint16_t uuid);

int bnep_show_connections(void);
int bnep_kill_connection(uint8_t *dst);
int bnep_kill_all_connections(void);

int bnep_accept_connection(int sk, uint16_t role, char *dev);
int bnep_create_connection(int sk, uint16_t role, uint16_t svc, char *dev);

/* SDP functions */
int  bnep_sdp_register(uint16_t role);
void bnep_sdp_unregister(void);
int  bnep_sdp_search(bdaddr_t *src, bdaddr_t *dst, uint16_t service);
