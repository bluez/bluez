/*
 * Copyright (C) 2014 Intel Corporation
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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const bthf_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

static void handle_conn_state(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_conn_state *ev = buf;

	if (cbs->connection_state_cb)
		cbs->connection_state_cb(ev->state,
						(bt_bdaddr_t *) (ev->bdaddr));
}

static void handle_audio_state(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_audio_state *ev = buf;

	if (cbs->audio_state_cb)
		cbs->audio_state_cb(ev->state, (bt_bdaddr_t *) (ev->bdaddr));
}

static void handle_vr_state(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_vr_state *ev = buf;

	if (cbs->vr_cmd_cb)
		cbs->vr_cmd_cb(ev->state);
}

static void handle_answer(void *buf, uint16_t len)
{
	if (cbs->answer_call_cmd_cb)
		cbs->answer_call_cmd_cb();
}

static void handle_hangup(void *buf, uint16_t len)
{
	if (cbs->hangup_call_cmd_cb)
		cbs->hangup_call_cmd_cb();
}

static void handle_volume(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_volume *ev = buf;

	if (cbs->volume_cmd_cb)
		cbs->volume_cmd_cb(ev->type, ev->volume);
}

static void handle_dial(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_dial *ev = buf;

	if (len != sizeof(*ev) + ev->number_len) {
		error("invalid dial event, aborting");
		exit(EXIT_FAILURE);
	}

	if (cbs->dial_call_cmd_cb)
		cbs->dial_call_cmd_cb((char *) ev->number);
}

static void handle_dtmf(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_dtmf *ev = buf;

	if (cbs->dtmf_cmd_cb)
		cbs->dtmf_cmd_cb(ev->tone);
}

static void handle_nrec(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_nrec *ev = buf;

	if (cbs->nrec_cmd_cb)
		cbs->nrec_cmd_cb(ev->nrec);
}

static void handle_chld(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_chld *ev = buf;

	if (cbs->chld_cmd_cb)
		cbs->chld_cmd_cb(ev->chld);
}

static void handle_cnum(void *buf, uint16_t len)
{
	if (cbs->cnum_cmd_cb)
		cbs->cnum_cmd_cb();
}

static void handle_cind(void *buf, uint16_t len)
{
	if (cbs->cind_cmd_cb)
		cbs->cind_cmd_cb();
}

static void handle_cops(void *buf, uint16_t len)
{
	if (cbs->cops_cmd_cb)
		cbs->cops_cmd_cb();
}

static void handle_clcc(void *buf, uint16_t len)
{
	if (cbs->clcc_cmd_cb)
		cbs->clcc_cmd_cb();
}

static void handle_unknown_at(void *buf, uint16_t len)
{
	struct hal_ev_handsfree_unknown_at *ev = buf;

	if (len != sizeof(*ev) + ev->len) {
		error("invalid dial event, aborting");
		exit(EXIT_FAILURE);
	}

	if (cbs->unknown_at_cmd_cb)
		cbs->unknown_at_cmd_cb((char *) ev->buf);
}

static void handle_hsp_key_press(void *buf, uint16_t len)
{
	if (cbs->key_pressed_cmd_cb)
		cbs->key_pressed_cmd_cb();
}

/* handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT' */
static const struct hal_ipc_handler ev_handlers[] = {
	/* HAL_EV_HANDSFREE_CONN_STATE */
	{handle_conn_state, false, sizeof(struct hal_ev_handsfree_conn_state)},
	/* HAL_EV_HANDSFREE_AUDIO_STATE */
	{handle_audio_state, false,
				sizeof(struct hal_ev_handsfree_audio_state)},
	/* HAL_EV_HANDSFREE_VR */
	{handle_vr_state, false, sizeof(struct hal_ev_handsfree_vr_state)},
	/*HAL_EV_HANDSFREE_ANSWER */
	{handle_answer, false, 0},
	/*HAL_EV_HANDSFREE_HANGUP */
	{handle_hangup, false, 0},
	/* HAL_EV_HANDSFREE_VOLUME */
	{handle_volume, false, sizeof(struct hal_ev_handsfree_volume)},
	/* HAL_EV_HANDSFREE_DIAL */
	{handle_dial, true, sizeof(struct hal_ev_handsfree_dial)},
	/* HAL_EV_HANDSFREE_DTMF */
	{handle_dtmf, false, sizeof(struct hal_ev_handsfree_dtmf)},
	/* HAL_EV_HANDSFREE_NREC */
	{handle_nrec, false, sizeof(struct hal_ev_handsfree_nrec)},
	/* HAL_EV_HANDSFREE_CHLD */
	{handle_chld, false, sizeof(struct hal_ev_handsfree_chld)},
	/* HAL_EV_HANDSFREE_CNUM */
	{handle_cnum, false, 0},
	/* HAL_EV_HANDSFREE_CIND */
	{handle_cind, false, 0},
	/* HAL_EV_HANDSFREE_COPS */
	{handle_cops, false, 0},
	/* HAL_EV_HANDSFREE_CLCC */
	{handle_clcc, false, 0},
	/* HAL_EV_HANDSFREE_UNKNOWN_AT */
	{handle_unknown_at, true, sizeof(struct hal_ev_handsfree_unknown_at)},
	/* HAL_EV_HANDSFREE_HSP_KEY_PRESS */
	{handle_hsp_key_press, false, 0},
};

static bt_status_t init(bthf_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_HANDSFREE, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE);
	}

	return ret;
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE);
}

static bthf_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.cleanup = cleanup
};

bthf_interface_t *bt_get_handsfree_interface(void)
{
	return &iface;
}
