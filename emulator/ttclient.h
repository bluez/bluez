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

/* Time travel client: takes part in the scheduling of a calendar (the time
 * controller of User Mode Linux guests started with time-travel=ext), so
 * that input from outside the simulation is injected at simulated times
 * no guest has run past.
 *
 * The client keeps a request one quantum ahead of its time, so the
 * calendar never lets guests run (or run ahead with FREE_UNTIL) beyond
 * it, and only runs when the calendar grants it. Requesting the current
 * time instead is not safe: with FREE_UNTIL, guests may already be past
 * the calendar's current time.
 */

/* Quantum in microseconds, default (0) 100 */
bool ttc_open(const char *path, unsigned int id, unsigned int quantum_us);
bool ttc_enabled(void);

/* The calendar granted the client to run: injecting events is safe */
bool ttc_running(void);

/* Answer pending calendar messages, e.g. while waiting for a guest that
 * itself waits for the calendar
 */
void ttc_process(void);

/* Called each time the client runs */
typedef void (*ttc_run_func_t)(void *user_data);
void ttc_set_run(ttc_run_func_t func, void *user_data);

/* While the pace function returns true, the client lets the guests' time
 * advance no faster than real time, e.g. while a test driver outside the
 * simulation has not asked anything of the guests.
 */
typedef bool (*ttc_pace_func_t)(void *user_data);
void ttc_set_pace(ttc_pace_func_t func, void *user_data);

typedef void (*ttc_debug_func_t)(const char *str, void *user_data);
void ttc_set_debug(ttc_debug_func_t callback, void *user_data);
