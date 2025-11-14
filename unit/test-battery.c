// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Open Mobile Platform LLC <community@omp.ru>
 *
 *
 */

#include <glib.h>
#include <stdlib.h>

#include "src/shared/battery.h"
#include "src/shared/tester.h"

#define DATA_SIZE 10

static uint8_t calculate_average(const uint8_t *charges)
{
	uint16_t average = 0;

	for (int i = DATA_SIZE - LAST_CHARGES_SIZE; i < DATA_SIZE; i++)
		average += charges[i];

	return average / LAST_CHARGES_SIZE;
}

static uint8_t process_data(struct bt_battery *battery, uint8_t *charges)
{
	uint8_t battery_avg;

	for (int i = 0; i < DATA_SIZE; i++)
		battery_avg = bt_battery_charge(battery, charges[i]);

	return battery_avg;
}

static void test_discharging(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 84, 83, 83, 81, 80, 80, 80, 79, 79, 78 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_charging(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 48, 48, 48, 49, 49, 50, 51, 51, 51, 53 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_discharge_started(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 48, 48, 49, 50, 51, 51, 49, 48, 47, 45 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_charge_started(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 57, 57, 56, 56, 55, 54, 55, 57, 57, 58 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_fluctuations(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 74, 73, 75, 72, 74, 72, 73, 71, 75, 73 };
	uint8_t processed_charge, average;

	average = calculate_average(charges);
	processed_charge = process_data(battery, charges);

	g_assert(processed_charge == average);

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_fluctuations_with_anomaly(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 33, 33, 34, 32, 94, 33, 31, 33, 34, 32 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_fluctuations_with_old_anomaly(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 94, 22, 22, 21, 21, 20, 21, 20, 21, 20 };
	uint8_t processed_charge, average;

	average = calculate_average(charges);
	processed_charge = process_data(battery, charges);

	g_assert(processed_charge == average);

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_bad_battery(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 28, 38, 92, 34, 85, 34, 45, 41, 29, 40 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_device_report_5_percent(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 55, 55, 50, 50, 50, 55, 55, 55, 60, 60 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

static void test_device_report_10_percent(const void *data)
{
	struct bt_battery *battery = bt_battery_new();
	uint8_t charges[DATA_SIZE] = { 30, 30, 30, 40, 40, 50, 50, 50, 50, 60 };
	uint8_t processed_charge;

	for (int i = 0; i < DATA_SIZE; i++) {
		processed_charge = bt_battery_charge(battery, charges[i]);
		g_assert(processed_charge == charges[i]);
	}

	bt_battery_free(battery);
	free(battery);
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/battery/test_discharging", NULL, NULL,
			test_discharging, NULL);
	tester_add("/battery/test_charging", NULL, NULL,
			test_charging, NULL);
	tester_add("/battery/test_discharge_started", NULL, NULL,
			test_discharge_started, NULL);
	tester_add("/battery/test_charge_started", NULL, NULL,
			test_charge_started, NULL);
	tester_add("/battery/test_fluctuations", NULL, NULL,
			test_fluctuations, NULL);
	tester_add("/battery/test_fluctuations_with_anomaly", NULL, NULL,
			test_fluctuations_with_anomaly, NULL);
	tester_add("/battery/test_fluctuations_with_old_anomaly", NULL, NULL,
			test_fluctuations_with_old_anomaly, NULL);
	tester_add("/battery/test_bad_battery", NULL, NULL, test_bad_battery,
			NULL);
	tester_add("/battery/test_device_report_5_percent", NULL, NULL,
			test_device_report_5_percent, NULL);
	tester_add("/battery/test_device_report_10_percent", NULL, NULL,
			test_device_report_10_percent, NULL);

	return tester_run();
}
