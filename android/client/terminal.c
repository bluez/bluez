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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <termios.h>
#include <stdlib.h>

#include "terminal.h"
#include "history.h"

/*
 * Character sequences recognized by code in this file
 * Leading ESC 0x1B is not included
 */
#define SEQ_INSERT "[2~"
#define SEQ_DELETE "[3~"
#define SEQ_HOME   "OH"
#define SEQ_END    "OF"
#define SEQ_PGUP   "[5~"
#define SEQ_PGDOWN "[6~"
#define SEQ_LEFT   "[D"
#define SEQ_RIGHT  "[C"
#define SEQ_UP     "[A"
#define SEQ_DOWN   "[B"
#define SEQ_STAB   "[Z"
#define SEQ_M_n    "n"
#define SEQ_M_p    "p"
#define SEQ_CLEFT  "[1;5D"
#define SEQ_CRIGHT "[1;5C"
#define SEQ_CUP    "[1;5A"
#define SEQ_CDOWN  "[1;5B"
#define SEQ_SLEFT  "[1;2D"
#define SEQ_SRIGHT "[1;2C"
#define SEQ_SUP    "[1;2A"
#define SEQ_SDOWN  "[1;2B"
#define SEQ_MLEFT  "[1;3D"
#define SEQ_MRIGHT "[1;3C"
#define SEQ_MUP    "[1;3A"
#define SEQ_MDOWN  "[1;3B"

#define KEY_SEQUENCE(k) { KEY_##k, SEQ_##k }
struct ansii_sequence {
	int code;
	const char *sequence;
};

/* Table connects single int key codes with character sequences */
static const struct ansii_sequence ansii_sequnces[] = {
	KEY_SEQUENCE(INSERT),
	KEY_SEQUENCE(DELETE),
	KEY_SEQUENCE(HOME),
	KEY_SEQUENCE(END),
	KEY_SEQUENCE(PGUP),
	KEY_SEQUENCE(PGDOWN),
	KEY_SEQUENCE(LEFT),
	KEY_SEQUENCE(RIGHT),
	KEY_SEQUENCE(UP),
	KEY_SEQUENCE(DOWN),
	KEY_SEQUENCE(CLEFT),
	KEY_SEQUENCE(CRIGHT),
	KEY_SEQUENCE(CUP),
	KEY_SEQUENCE(CDOWN),
	KEY_SEQUENCE(SLEFT),
	KEY_SEQUENCE(SRIGHT),
	KEY_SEQUENCE(SUP),
	KEY_SEQUENCE(SDOWN),
	KEY_SEQUENCE(MLEFT),
	KEY_SEQUENCE(MRIGHT),
	KEY_SEQUENCE(MUP),
	KEY_SEQUENCE(MDOWN),
	KEY_SEQUENCE(STAB),
	KEY_SEQUENCE(M_p),
	KEY_SEQUENCE(M_n),
	{ 0, NULL }
};

#define KEY_SEQUNCE_NOT_FINISHED -1
#define KEY_C_C 3
#define KEY_C_D 4
#define KEY_C_L 12

#define isseqence(c) ((c) == 0x1B)

/*
 * Number of characters that consist of ANSI sequence
 * Should not be less then longest string in ansi_sequences
 */
#define MAX_ASCII_SEQUENCE 10

static char current_sequence[MAX_ASCII_SEQUENCE];
static int current_sequence_len = -1;

/* single line typed by user goes here */
static char line_buf[LINE_BUF_MAX];
/* index of cursor in input line */
static int line_buf_ix = 0;
/* current length of input line */
static int line_len = 0;

/* line index used for fetching lines from history */
static int line_index = 0;

static char prompt_buf[10] = "> ";
static const char *prompt = prompt_buf;
/*
 * Moves cursor to right or left
 *
 * n - positive - moves cursor right
 * n - negative - moves cursor left
 */
static void terminal_move_cursor(int n)
{
	if (n < 0) {
		for (; n < 0; n++)
			putchar('\b');
	} else if (n > 0) {
		printf("%*s", n, line_buf + line_buf_ix);
	}
}

/* Draw command line */
void terminal_draw_command_line(void)
{
	/*
	 * this needs to be checked here since line_buf is not cleared
	 * before parsing event though line_len and line_buf_ix are
	 */
	if (line_len > 0)
		printf("%s%s", prompt, line_buf);
	else
		printf("%s", prompt);

	/* move cursor to it's place */
	terminal_move_cursor(line_buf_ix - line_len);
}

/* inserts string into command line at cursor position */
void terminal_insert_into_command_line(const char *p)
{
	int len = strlen(p);

	if (line_len == line_buf_ix) {
		strcat(line_buf, p);
		printf("%s", p);
		line_len = line_len + len;
		line_buf_ix = line_len;
	} else {
		memmove(line_buf + line_buf_ix + len,
			line_buf + line_buf_ix, line_len - line_buf_ix + 1);
		memmove(line_buf + line_buf_ix, p, len);
		printf("%s", line_buf + line_buf_ix);
		line_buf_ix += len;
		line_len += len;
		terminal_move_cursor(line_buf_ix - line_len);
	}
}

/* Prints string and redraws command line */
int terminal_print(const char *format, ...)
{
	va_list args;
	int ret;

	va_start(args, format);

	ret = terminal_vprint(format, args);

	va_end(args);
	return ret;
}

/* Prints string and redraws command line */
int terminal_vprint(const char *format, va_list args)
{
	int ret;

	printf("\r%*s\r", (int) line_len + 1, " ");

	ret = vprintf(format, args);

	terminal_draw_command_line();

	fflush(stdout);

	return ret;
}

/*
 * Call this when text in line_buf was changed
 * and line needs to be redrawn
 */
static void terminal_line_replaced(void)
{
	int len = strlen(line_buf);

	/* line is shorter that previous */
	if (len < line_len) {
		/* if new line is shorter move cursor to end of new end */
		while (line_buf_ix > len) {
			putchar('\b');
			line_buf_ix--;
		}

		/* If cursor was not at the end, move it to the end */
		if (line_buf_ix < line_len)
			printf("%.*s", line_len - line_buf_ix,
					line_buf + line_buf_ix);
		/* over write end of previous line */
		while (line_len >= len++)
			putchar(' ');
	}

	/* draw new line */
	printf("\r%s%s", prompt, line_buf);
	/* set up indexes to new line */
	line_len = strlen(line_buf);
	line_buf_ix = line_len;
}

static void terminal_clear_line(void)
{
	line_buf[0] = '\0';
	terminal_line_replaced();
}

static void terminal_clear_screen(void)
{
	line_buf[0] = '\0';
	line_buf_ix = 0;
	line_len = 0;

	printf("\x1b[2J\x1b[1;1H%s", prompt);
}

static void terminal_delete_char(void)
{
	/* delete character under cursor if not at the very end */
	if (line_buf_ix >= line_len)
		return;
	/*
	 * Prepare buffer with one character missing
	 * trailing 0 is moved
	 */
	line_len--;
	memmove(line_buf + line_buf_ix, line_buf + line_buf_ix + 1,
						line_len - line_buf_ix + 1);
	/* print rest of line from current cursor position */
	printf("%s \b", line_buf + line_buf_ix);
	/* move back cursor */
	terminal_move_cursor(line_buf_ix - line_len);
}

/*
 * Function tries to replace current line with specified line in history
 * new_line_index - new line to show, -1 to show oldest
 */
static void terminal_get_line_from_history(int new_line_index)
{
	new_line_index = history_get_line(new_line_index,
						line_buf, LINE_BUF_MAX);

	if (new_line_index >= 0) {
		terminal_line_replaced();
		line_index = new_line_index;
	}
}

/*
 * Function searches history back or forward for command line that starts
 * with characters up to cursor position
 *
 * back - true - searches backward
 * back - false - searches forward (more recent commands)
 */
static void terminal_match_hitory(bool back)
{
	char buf[line_buf_ix + 1];
	int line;
	int matching_line = -1;
	int dir = back ? 1 : -1;

	line = line_index + dir;
	while (matching_line == -1 && line >= 0) {
		int new_line_index;

		new_line_index = history_get_line(line, buf, line_buf_ix + 1);
		if (new_line_index < 0)
			break;

		if (0 == strncmp(line_buf, buf, line_buf_ix))
			matching_line = line;
		line += dir;
	}

	if (matching_line >= 0) {
		int pos = line_buf_ix;
		terminal_get_line_from_history(matching_line);
		/* move back to cursor position to original place */
		line_buf_ix = pos;
		terminal_move_cursor(pos - line_len);
	}
}

/*
 * Converts terminal character sequences to single value representing
 * keyboard keys
 */
static int terminal_convert_sequence(int c)
{
	int i;

	/* Not in sequence yet? */
	if (current_sequence_len == -1) {
		/* Is ansi sequence detected by 0x1B ? */
		if (isseqence(c)) {
			current_sequence_len++;
			return KEY_SEQUNCE_NOT_FINISHED;
		}

		return c;
	}

	/* Inside sequence */
	current_sequence[current_sequence_len++] = c;
	current_sequence[current_sequence_len] = '\0';
	for (i = 0; ansii_sequnces[i].code; ++i) {
		/* Matches so far? */
		if (0 != strncmp(current_sequence, ansii_sequnces[i].sequence,
							current_sequence_len))
			continue;

		/* Matches as a whole? */
		if (ansii_sequnces[i].sequence[current_sequence_len] == 0) {
			current_sequence_len = -1;
			return ansii_sequnces[i].code;
		}

		/* partial match (not whole sequence yet) */
		return KEY_SEQUNCE_NOT_FINISHED;
	}

	terminal_print("ansi char 0x%X %c\n", c);
	/*
	 * Sequence does not match
	 * mark that no in sequence any more, return char
	 */
	current_sequence_len = -1;
	return c;
}

void terminal_process_char(int c, void (*process_line)(char *line))
{
	int refresh_from = -1;
	int old_pos;

	c = terminal_convert_sequence(c);

	switch (c) {
	case KEY_SEQUNCE_NOT_FINISHED:
		break;
	case KEY_LEFT:
		/* if not at the beginning move to previous character */
		if (line_buf_ix <= 0)
			break;
		line_buf_ix--;
		terminal_move_cursor(-1);
		break;
	case KEY_RIGHT:
		/*
		 * If not at the end, just print current character
		 * and modify position
		 */
		if (line_buf_ix < line_len)
			putchar(line_buf[line_buf_ix++]);
		break;
	case KEY_HOME:
		/* move to beginning of line and update position */
		printf("\r%s", prompt);
		line_buf_ix = 0;
		break;
	case KEY_END:
		/* if not at the end of line */
		if (line_buf_ix < line_len) {
			/* print everything from cursor */
			printf("%s", line_buf + line_buf_ix);
			/* just modify current position */
			line_buf_ix = line_len;
		}
		break;
	case KEY_DELETE:
		terminal_delete_char();
		break;
	case KEY_CLEFT:
		/*
		 * Move by word left
		 *
		 * Are we at the beginning of line?
		 */
		if (line_buf_ix <= 0)
			break;

		old_pos = line_buf_ix;
		line_buf_ix--;
		/* skip spaces left */
		while (line_buf_ix && isspace(line_buf[line_buf_ix]))
			line_buf_ix--;
		/* skip all non spaces to the left */
		while (line_buf_ix > 0 &&
			!isspace(line_buf[line_buf_ix - 1]))
			line_buf_ix--;
		/* move cursor to new position */
		terminal_move_cursor(line_buf_ix - old_pos);
		break;
	case KEY_CRIGHT:
		/*
		 * Move by word right
		 *
		 * are we at the end of line?
		 */
		if (line_buf_ix >= line_len)
			break;

		old_pos = line_buf_ix;
		/* skip all spaces */
		while (line_buf_ix < line_len &&
			isspace(line_buf[line_buf_ix]))
			line_buf_ix++;
		/* skip all non spaces */
		while (line_buf_ix < line_len &&
			!isspace(line_buf[line_buf_ix]))
			line_buf_ix++;
		/*
		 * Move cursor to right by printing text
		 * between old cursor and new
		 */
		if (line_buf_ix > old_pos)
			printf("%.*s", (int) (line_buf_ix - old_pos),
							line_buf + old_pos);
		break;
	case KEY_SUP:
		terminal_get_line_from_history(-1);
		break;
	case KEY_SDOWN:
		if (line_index > 0)
			terminal_get_line_from_history(0);
		break;
	case KEY_UP:
		terminal_get_line_from_history(line_index + 1);
		break;
	case KEY_DOWN:
		if (line_index > 0)
			terminal_get_line_from_history(line_index - 1);
		break;
	case '\n':
	case '\r':
		/*
		 * On new line add line to history
		 * forget history position
		 */
		history_add_line(line_buf);
		line_len = 0;
		line_buf_ix = 0;
		line_index = -1;
		/* print new line */
		putchar(c);
		prompt = "";
		process_line(line_buf);
		/* clear current line */
		line_buf[0] = '\0';
		prompt = prompt_buf;
		printf("%s", prompt);
		break;
	case '\t':
		/* tab processing */
		process_tab(line_buf, line_buf_ix);
		break;
	case KEY_BACKSPACE:
		if (line_buf_ix <= 0)
			break;

		if (line_buf_ix == line_len) {
			printf("\b \b");
			line_len = --line_buf_ix;
			line_buf[line_len] = 0;
		} else {
			putchar('\b');
			refresh_from = --line_buf_ix;
			line_len--;
			memmove(line_buf + line_buf_ix,
				line_buf + line_buf_ix + 1,
				line_len - line_buf_ix + 1);
		}
		break;
	case KEY_INSERT:
	case KEY_PGUP:
	case KEY_PGDOWN:
	case KEY_CUP:
	case KEY_CDOWN:
	case KEY_SLEFT:
	case KEY_SRIGHT:
	case KEY_MLEFT:
	case KEY_MRIGHT:
	case KEY_MUP:
	case KEY_MDOWN:
	case KEY_STAB:
	case KEY_M_n:
		/* Search history forward */
		terminal_match_hitory(false);
		break;
	case KEY_M_p:
		/* Search history backward */
		terminal_match_hitory(true);
		break;
	case KEY_C_C:
		terminal_clear_line();
		break;
	case KEY_C_D:
		if (line_len > 0) {
			terminal_delete_char();
		} else  {
			puts("");
			exit(0);
		}
		break;
	case KEY_C_L:
		terminal_clear_screen();
		break;
	default:
		if (!isprint(c)) {
			/*
			 * TODO: remove this print once all meaningful sequences
			 * are identified
			 */
			printf("char-0x%02x\n", c);
			break;
		}

		if (line_buf_ix < LINE_BUF_MAX - 1) {
			if (line_len == line_buf_ix) {
				putchar(c);
				line_buf[line_buf_ix++] = (char) c;
				line_len++;
				line_buf[line_len] = '\0';
			} else {
				memmove(line_buf + line_buf_ix + 1,
					line_buf + line_buf_ix,
					line_len - line_buf_ix + 1);
				line_buf[line_buf_ix] = c;
				refresh_from = line_buf_ix++;
				line_len++;
			}
		}
		break;
	}

	if (refresh_from >= 0) {
		printf("%s \b", line_buf + refresh_from);
		terminal_move_cursor(line_buf_ix - line_len);
	}

	/* Flush output after all user input */
	fflush(stdout);
}

static struct termios origianl_tios;

static void terminal_cleanup(void)
{
	tcsetattr(0, TCSANOW, &origianl_tios);
}

void terminal_setup(void)
{
	struct termios tios;
	tcgetattr(0, &origianl_tios);
	tios = origianl_tios;

	/*
	 * Turn off echo since all editing is done by hand,
	 * Ctrl-c handled internally
	 */
	tios.c_lflag &= ~(ICANON | ECHO | BRKINT | IGNBRK);
	tcsetattr(0, TCSANOW, &tios);

	/* Restore terminal at exit */
	atexit(terminal_cleanup);

	printf("%s", prompt);
	fflush(stdout);
}
