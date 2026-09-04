/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include <stdint.h>

struct vendor_ocf;
struct evt_vendor;

const struct vendor_ocf *intel_vendor_ocf(uint16_t ocf);
const struct evt_vendor *intel_evt_vendor(const void *data, int *consumed_size);
