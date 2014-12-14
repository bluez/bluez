/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "phy.h"

struct bt_phy {
	volatile int ref_count;
};

struct bt_phy *bt_phy_new(void)
{
	struct bt_phy *phy;

	phy = calloc(1, sizeof(*phy));
	if (!phy)
		return NULL;

	return bt_phy_ref(phy);
}

struct bt_phy *bt_phy_ref(struct bt_phy *phy)
{
	if (!phy)
		return NULL;

	__sync_fetch_and_add(&phy->ref_count, 1);

	return phy;
}

void bt_phy_unref(struct bt_phy *phy)
{
	if (!phy)
		return;

	if (__sync_sub_and_fetch(&phy->ref_count, 1))
		return;

	free(phy);
}
