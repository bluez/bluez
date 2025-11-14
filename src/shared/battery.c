// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Open Mobile Platform LLC <community@omp.ru>
 *
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "src/shared/battery.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

struct bt_battery {
	struct queue *last_charges; /* last charges received */
	uint8_t avg_charge; /* average battery charge */
	bool is_fluctuating; /* true, if the battery sensor fluctuates */
};

struct bt_battery *bt_battery_new(void)
{
	struct bt_battery *battery;

	battery = new0(struct bt_battery, 1);
	battery->last_charges = queue_new();
	battery->avg_charge = 0;
	battery->is_fluctuating = false;

	return battery;
}

void bt_battery_free(struct bt_battery *battery)
{
	if (battery->last_charges)
		queue_destroy(battery->last_charges, NULL);
}

static void bt_battery_check_fluctuations(struct bt_battery *battery)
{
	const struct queue_entry *entry;
	uint8_t spikes = 0;
	int8_t step;
	int8_t direction = 0;
	int8_t prev_direction;
	uintptr_t prev_charge;
	uintptr_t next_charge = 0;
	uint16_t sum_charge = 0;

	for (entry = queue_get_entries(battery->last_charges); entry->next;
	     entry = entry->next) {
		prev_direction = direction;
		prev_charge = PTR_TO_UINT(entry->data);
		next_charge = PTR_TO_UINT(entry->next->data);
		step = next_charge - prev_charge;
		sum_charge += prev_charge;

		/*
		 * The battery charge fluctuates too much,
		 * which may indicate a battery problem, so
		 * the actual value should be displayed.
		 */
		if (abs(step) >= MAX_CHARGE_STEP) {
			battery->is_fluctuating = false;
			return;
		}

		if (step > 0)
			direction = 1;
		else if (step < 0)
			direction = -1;

		if (direction != prev_direction && prev_direction)
			spikes++;
	}

	sum_charge += next_charge;
	battery->avg_charge = sum_charge / LAST_CHARGES_SIZE;

	battery->is_fluctuating = (spikes > 1) ? true : false;
}

uint8_t bt_battery_charge(struct bt_battery *battery, uint8_t percentage)
{
	queue_push_tail(battery->last_charges, UINT_TO_PTR(percentage));

	if (queue_length(battery->last_charges) == LAST_CHARGES_SIZE) {
		bt_battery_check_fluctuations(battery);
		queue_pop_head(battery->last_charges);
	}

	return (battery->is_fluctuating) ? battery->avg_charge : percentage;
}
