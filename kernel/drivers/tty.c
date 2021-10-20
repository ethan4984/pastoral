#include <drivers/tty.h>
#include <font.h>
#include <cpu.h>
#include <mm/pmm.h>
#include <string.h>
#include <mm/slab.h>
#include <debug.h>

static size_t fb_pitch;
static size_t fb_width;
static size_t fb_height;
static size_t fb_bpp;
static size_t fb_size;

static volatile uint32_t *framebuffer;
static uint32_t *double_buffer;

struct tty *current_tty;

#define DEFAULT_TAB_SIZE 4
#define DEFAULT_TEXT_FG 0xFFC0CB
#define DEFAULT_TEXT_BG 0xffffff
#define DEFAULT_CURSOR_FG DEFAULT_TEXT_FG

static inline void fb_set_pixel(size_t x, size_t y, uint32_t colour) {
	size_t index = x + fb_pitch / (fb_bpp / 8) * y;

	framebuffer[index] = colour;
	double_buffer[index] = colour;
}

void fb_render_char(size_t x, size_t y, uint32_t fg, uint32_t bg, char c) {
	uint16_t offset = ((uint8_t)c - 0x20) * FONT_HEIGHT;
	for(uint8_t i = 0, i_cnt = 8; i < FONT_WIDTH && i_cnt > 0; i++, i_cnt--) {
		for(uint8_t j = 0; j < FONT_HEIGHT; j++) {
			if((font[offset + j] >> i) & 1) {
				fb_set_pixel(x + i_cnt, y + j, fg);
			} else {
				fb_set_pixel(x + i_cnt, y + j, bg);
			}
		}
	}
}

void tty_plot_char(struct tty *tty, size_t x, size_t y, uint32_t fg, uint32_t bg, char c) {
	fb_render_char(x * FONT_WIDTH, y * FONT_HEIGHT, fg, bg, c);
	tty->char_grid[x + y * tty->cols] = c;
}

void tty_clear_cursor(struct tty *tty) {
	for(size_t i = 0; i < FONT_HEIGHT; i++) {
		for(size_t j = 0; j < FONT_WIDTH; j++) {
			fb_set_pixel(j + tty->cursor_x * FONT_WIDTH, i + tty->cursor_y * FONT_HEIGHT, tty->text_background);
		}
	}
}

void tty_draw_cursor(struct tty *tty) {
	for(size_t i = 0; i < FONT_HEIGHT; i++) {
		for(size_t j = 0; j < FONT_WIDTH; j++) {
			fb_set_pixel(j + tty->cursor_x * FONT_WIDTH, i + tty->cursor_y * FONT_HEIGHT, tty->cursor_foreground);
		}
	}
}

void tty_update_cursor(struct tty *tty, size_t x, size_t y) {
	tty_clear_cursor(tty);
	tty->cursor_x = x;
	tty->cursor_y = y;
	tty_draw_cursor(tty);
}

void tty_scroll(struct tty *tty) {
	tty_clear_cursor(tty);

	for(ssize_t i = tty->cols; i < tty->rows * tty->cols; i++) {
		tty->char_grid[i - tty->cols] = tty->char_grid[i];
	}

	for(ssize_t i = tty->rows * tty->cols - tty->cols; i < tty->rows * tty->cols; i++) {
		tty->char_grid[i] = 0;
	}

	memcpy64((uint64_t*)framebuffer, (uint64_t*)double_buffer + (fb_pitch * FONT_HEIGHT) / 8, (fb_size - fb_pitch * FONT_HEIGHT) / 8); 
	memcpy64((uint64_t*)double_buffer, (uint64_t*)double_buffer + (fb_pitch * FONT_HEIGHT) / 8, (fb_size - fb_pitch * FONT_HEIGHT) / 8);

	memset32((uint32_t*)framebuffer + (fb_size - fb_pitch * FONT_HEIGHT) / 4, tty->text_background, fb_pitch * FONT_HEIGHT / 4); 
	memset32((uint32_t*)double_buffer + (fb_size - fb_pitch * FONT_HEIGHT) / 4, tty->text_background, fb_pitch * FONT_HEIGHT / 4); 

	tty_draw_cursor(tty);
}

void tty_putchar(struct tty *tty, char c) {
	switch(c) {
		case '\n':
			if(tty->cursor_y == (tty->rows - 1)) {
				tty_scroll(tty);
				tty_update_cursor(tty, 0, tty->rows - 1);
			} else { 
				tty_update_cursor(tty, 0, tty->cursor_y + 1);
			}
			break;
		case '\r':
			tty_update_cursor(tty, 0, tty->cursor_y);
			break;
		case '\0':
			break;
		case '\b':
			if(tty->cursor_x || tty->cursor_y) {
				tty_clear_cursor(tty);

				if(tty->cursor_x) {
					tty->cursor_x--;
				} else {
					tty->cursor_y--;
					tty->cursor_x = tty->cols - 1;
				}
				
				tty_draw_cursor(tty);
			}
			break;
		default:
			tty_clear_cursor(tty); 

			tty_plot_char(tty, tty->cursor_x++, tty->cursor_y, tty->text_foreground, tty->text_background, c);

			if(tty->cursor_x == tty->cols) {
				tty->cursor_x = 0;
				tty->cursor_y++;
			}

			if(tty->cursor_y == tty->rows) {
				tty->cursor_y--;
				tty_scroll(tty);
			}

			tty_draw_cursor(tty);
	}
}

void fb_flush(uint32_t colour) {
	for(size_t i = 0; i < fb_height; i++) {
		for(size_t j = 0; j < fb_width; j++) {
			fb_set_pixel(j, i, colour);
		}
	}
}

void tty_init(struct stivale_struct *stivale_struct) {
	fb_pitch = stivale_struct->framebuffer_pitch;
	fb_width = stivale_struct->framebuffer_width;
	fb_height = stivale_struct->framebuffer_height;
	fb_bpp = stivale_struct->framebuffer_bpp;
	fb_size = fb_height * fb_pitch;
	framebuffer = (volatile uint32_t*)stivale_struct->framebuffer_addr;
	double_buffer = (uint32_t*)(pmm_alloc(DIV_ROUNDUP(fb_size, PAGE_SIZE), 1) + HIGH_VMA);

	current_tty = alloc(sizeof(struct tty));

	*current_tty = (struct tty) {
		.tab_size = DEFAULT_TAB_SIZE,
		.text_foreground = DEFAULT_TEXT_FG,
		.text_background = DEFAULT_TEXT_BG,
		.cursor_foreground = DEFAULT_CURSOR_FG,
		.rows = fb_height / FONT_HEIGHT,
		.cols = fb_width / FONT_WIDTH,
		.char_grid = alloc((fb_height / FONT_HEIGHT) * (fb_width / FONT_WIDTH))
	};

	fb_flush(current_tty->text_background);

	print("tty: framebuffer %x\n", (uintptr_t)framebuffer);
	print("tty: fb_height %d\n", fb_height);
	print("tty: fb_width %d\n", fb_width);
	print("tty: fb_bpp %d\n", fb_bpp);
}
