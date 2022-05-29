#pragma once

#include <stivale.h>
#include <stddef.h>
#include <stdbool.h>

struct tty {
	uint32_t cursor_foreground;
	uint32_t text_foreground;
	uint32_t text_background; 

	size_t cursor_x;
	size_t cursor_y;
	size_t tab_size;

	size_t rows;
	size_t cols;

	volatile bool new_key;
	volatile char last_char;

	char *char_grid;
};

extern struct tty *current_tty;

void tty_init();
void tty_putchar(struct tty *tty, char c);
