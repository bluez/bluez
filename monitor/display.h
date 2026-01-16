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

#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>

bool use_color(void);

enum monitor_color { COLOR_AUTO, COLOR_ALWAYS, COLOR_NEVER };
void set_monitor_color(enum monitor_color);

#define COLOR_OFF	"\x1B[0m"
#define COLOR_BLACK	"\x1B[0;30m"
#define COLOR_RED	"\x1B[0;31m"
#define COLOR_GREEN	"\x1B[0;32m"
#define COLOR_YELLOW	"\x1B[0;33m"
#define COLOR_BLUE	"\x1B[0;34m"
#define COLOR_MAGENTA	"\x1B[0;35m"
#define COLOR_CYAN	"\x1B[0;36m"
#define COLOR_WHITE	"\x1B[0;37m"
#define COLOR_WHITE_BG	"\x1B[0;47;30m"
#define COLOR_HIGHLIGHT	"\x1B[1;39m"

#define COLOR_RED_BOLD		"\x1B[1;31m"
#define COLOR_GREEN_BOLD	"\x1B[1;32m"
#define COLOR_BLUE_BOLD		"\x1B[1;34m"
#define COLOR_MAGENTA_BOLD	"\x1B[1;35m"

#define COLOR_ERROR	"\x1B[1;31m"
#define COLOR_WARN	"\x1B[1m"
#define COLOR_INFO	COLOR_OFF
#define COLOR_DEBUG	COLOR_WHITE

#define FALLBACK_TERMINAL_WIDTH 80

#define print_indent(indent, color1, prefix, title, color2, fmt, args...) \
do { \
	printf("%*c%s%s%s%s" fmt "%s\n", (indent), ' ', \
		use_color() ? (color1) : "", prefix, title, \
		use_color() ? (color2) : "", ## args, \
		use_color() ? COLOR_OFF : ""); \
} while (0)

#define print_text(color, fmt, args...) \
		print_indent(8, COLOR_OFF, "", "", color, fmt, ## args)

#define print_field(fmt, args...) \
		print_indent(8, COLOR_OFF, "", "", COLOR_OFF, fmt, ## args)

struct bitfield_data {
	uint64_t bit;
	const char *str;
};

static inline uint64_t print_bitfield(int indent, uint64_t val,
					const struct bitfield_data *table)
{
	uint64_t mask = val;
	int i;

	for (i = 0; table[i].str; i++) {
		if (val & (((uint64_t) 1) << table[i].bit)) {
			print_field("%*c%s", indent, ' ', table[i].str);
			mask &= ~(((uint64_t) 1) << table[i].bit);
		}
	}

	return mask;
}

static inline void print_hexdump(const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			print_text(COLOR_WHITE, "%s", str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		print_text(COLOR_WHITE, "%s", str);
	}
}

static inline void print_hex_field(const char *label, const uint8_t *data,
								uint8_t len)
{
	print_field("%s[%u]:", label, len);
	print_hexdump(data, len);
}

void set_default_pager_num_columns(int num_columns);
int num_columns(void);

void open_pager(void);
void close_pager(void);
