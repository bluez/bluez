/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>

/* Time travel calendar for User Mode Linux (time-travel=ext) guests */

bool tt_open(const char *path);
void tt_close(void);
bool tt_enabled(void);

/* Let time advance up to msec beyond the earliest running guest, so guests
 * run in parallel; 0 (default) is lock-step.
 */
void tt_set_skew(unsigned int msec);

/* Current simulated time in nanoseconds */
uint64_t tt_now(void);

/* Called before advancing time, to process pending device input */
typedef void (*tt_flush_func_t)(void *user_data);
void tt_add_flush(tt_flush_func_t func, void *user_data);
void tt_remove_flush(tt_flush_func_t func, void *user_data);

/* While the hold function returns true, time advances no faster than real
 * time. Used while a peer outside the simulation, e.g. a test driver, has
 * not asked anything of the guests, so they don't run ahead of it.
 */
typedef bool (*tt_hold_func_t)(void *user_data);
void tt_set_hold(tt_hold_func_t func, void *user_data);

/* Advance time if every guest waits, e.g. after processing device input */
void tt_schedule(void);

/* Process pending calendar messages without advancing time, used while
 * waiting for a guest that may itself be waiting for the calendar.
 */
void tt_process(void);

typedef bool (*tt_timeout_func_t)(void *user_data);
typedef void (*tt_destroy_func_t)(void *user_data);
unsigned int tt_timeout_add(unsigned int msec, tt_timeout_func_t func,
				void *user_data, tt_destroy_func_t destroy);
void tt_timeout_remove(unsigned int id);

typedef void (*tt_debug_func_t)(const char *str, void *user_data);
void tt_set_debug(tt_debug_func_t callback, void *user_data);
