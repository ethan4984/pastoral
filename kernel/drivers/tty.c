#include <drivers/tty.h>
#include <font.h>
#include <cpu.h>
#include <mm/pmm.h>
#include <string.h>
#include <mm/slab.h>
#include <debug.h>
#include <stivale.h>

static size_t fb_pitch;
static size_t fb_width;
static size_t fb_height;
static size_t fb_bpp;
static size_t fb_size;

static volatile uint32_t *framebuffer;
static uint32_t *double_buffer;

struct tty *current_tty;

#define DEFAULT_TAB_SIZE 4
#define DEFAULT_TEXT_FG 0xffffff
#define DEFAULT_TEXT_BG 0x000000
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

void ps2_keyboard(struct registers*, void*) {
	static char keymap[] = {	'\0', '\0', '1', '2', '3',	'4', '5', '6',	'7', '8', '9', '0',
								'-', '=', '\b', '\t', 'q',	'w', 'e', 'r',	't', 'y', 'u', 'i',
								'o', 'p', '[', ']', '\0',  '\0', 'a', 's',	'd', 'f', 'g', 'h',
								'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
								'b', 'n', 'm', ',', '.',  '/', '\0', '\0', '\0', ' '
						   };

	static char cap_keymap[] = {	'\0', '\e', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
									'_', '+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
									'O', 'P', '{', '}', '\0', '\0', 'A', 'S', 'D', 'F', 'G', 'H',
									'J', 'K', 'L', ':', '\'', '~', '\0', '\\', 'Z', 'X', 'C', 'V',
									'B', 'N', 'M', '<', '>',  '?', '\0', '\0', '\0', ' '
							  };

	static bool upkey = false;

	uint8_t keycode = inb(0x60);
	char character = '\0';

	switch(keycode) {
		case 0xaa: // left shift release
			upkey = false;
			return;
		case 0x2a: // left shift press
			upkey = true;
			return;
		case 0xf: // tab
			character = '\t';
			break;
		case 0xe: // backspace
			character = '\b';
			break;
		case 0x1c: // enter
			character = '\n';
			break;
		default:
			if(keycode <= 128) {
				if(upkey) {
					character = cap_keymap[keycode];
				} else {
					character = keymap[keycode];
				}
			}
	}

	tty_putchar(current_tty, character);

	current_tty->last_char = character;
	current_tty->new_key = true;
}

ssize_t tty_read(struct asset*, void*, off_t, off_t cnt, void *buffer) {
	char *stream = buffer;

	asm volatile ("sti");
	
	while(!current_tty->new_key);

	*stream = current_tty->last_char;

	current_tty->new_key = false;
	
	return cnt;
}

ssize_t tty_write(struct asset *, void*, off_t, off_t cnt, const void *buffer) {
	const char *str = buffer;

	for(size_t i = 0; i < cnt; i++) {
		tty_putchar(current_tty, str[i]);
	}

	return cnt;
}

void tty_init() {
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
		.new_key = false,
		.last_char = '\0',
		.char_grid = alloc((fb_height / FONT_HEIGHT) * (fb_width / FONT_WIDTH))
	};

	fb_flush(current_tty->text_background);

	print("tty: framebuffer %x\n", (uintptr_t)framebuffer);
	print("tty: fb_height %d\n", fb_height);
	print("tty: fb_width %d\n", fb_width);
	print("tty: fb_bpp %d\n", fb_bpp);
}
