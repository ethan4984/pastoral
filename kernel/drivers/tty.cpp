#include <drivers/tty.hpp>
#include <mm/vmm.hpp>
#include <fs/vfs.hpp>
#include <debug.hpp>
#include <fs/dev.hpp>

namespace tty {

static size_t tty_cnt = 0;

static uint32_t ansi_colours[] = {
    0, // black
    0xff3333, // red
    0x46ff33, // green
    0xa52a2a, // brown
    0x3f33ff, // blue
    0xfc33ff, // magenta
    0x33a8ff, // cyan
    0xc1bdc2  // grey
};

screen::screen(stivale *stivale_struct) {
    framebuffer = reinterpret_cast<volatile uint32_t*>(stivale_struct->fb_addr + vmm::high_vma);

    height = stivale_struct->fb_height;
    width = stivale_struct->fb_width;
    pitch = stivale_struct->fb_pitch;
    bpp = stivale_struct->fb_bpp;
    size = height * pitch;

    double_buffer = reinterpret_cast<volatile uint32_t*>(pmm::calloc(div_roundup(size, vmm::page_size)) + vmm::high_vma);

    size_t fb_page_off = stivale_struct->fb_addr / vmm::page_size;
    for(ssize_t i = 0; i < div_roundup(size, 0x200000); i++) { // map fb and double fb as wc
        vmm::kernel_mapping->map_page_raw(fb_page_off + vmm::high_vma + i * 0x200000, fb_page_off + i * 0x200000, 0x3, 0x3 | (1 << 7) | (1 << 8), vmm::pa_wc);
        vmm::kernel_mapping->map_page_raw((size_t)double_buffer + i * 0x200000, (size_t)double_buffer - vmm::high_vma + i * 0x200000, 0x3, 0x3 | (1 << 7) | (1 << 8), vmm::pa_wc);
    }
}

inline void screen::set_pixel(ssize_t x, ssize_t y, uint32_t colour) {
    size_t index = x + pitch / (bpp / 8) * y;

    framebuffer[index] = colour;
    double_buffer[index] = colour;
}

inline uint32_t screen::get_pixel(ssize_t x, ssize_t y) {
    return double_buffer[x + pitch / (bpp / 8) * y];
}

void screen::flush(uint32_t colour) {
    for(size_t i = 0; i < height; i++) {
        for(size_t j = 0; j < width; j++) {
            set_pixel(j, i, colour);
        }
    }
}

void tty::render_char(ssize_t x, ssize_t y, uint32_t fg, uint32_t bg, char c) {
    uint16_t offset = ((uint8_t)c - 0x20) * font_height;
    for(uint8_t i = 0, i_cnt = 8; i < font_width && i_cnt > 0; i++, i_cnt--) {
        for(uint8_t j = 0; j < font_height; j++) {
            if((font[offset + j] >> i) & 1)
                sc.set_pixel(x + i_cnt, y + j, fg);
            else
                sc.set_pixel(x + i_cnt, y + j, bg);
        }
    }
}

void tty::plot_char(ssize_t x, ssize_t y, uint32_t fg, uint32_t bg, char c) {
    render_char(x * font_width, y * font_height, fg, bg, c);
    char_grid[x + y * cols] = c;
}

void tty::update_cursor(ssize_t x, ssize_t y) {
    clear_cursor();
    cursor_x = x;
    cursor_y = y;
    draw_cursor();
}

void tty::clear_cursor() {
    for(size_t i = 0; i < font_height; i++) {
        for(size_t j = 0; j < font_width; j++) {
            sc.set_pixel(j + cursor_x * font_width, i + cursor_y * font_height, text_background);
        }
    }
}

void tty::draw_cursor() {
    for(size_t i = 0; i < font_height; i++) {
        for(size_t j = 0; j < font_width; j++) {
            sc.set_pixel(j + cursor_x * font_width, i + cursor_y * font_height, cursor_foreground);
        }
    }
}

void tty::scroll() {
    clear_cursor();

    for(ssize_t i = cols; i < rows * cols; i++) {
        char_grid[i - cols] = char_grid[i];
    }

    for(ssize_t i = rows * cols - cols; i < rows * cols; i++) {
        char_grid[i] = 0;
    }

    memcpy64((uint64_t*)sc.framebuffer, (uint64_t*)sc.double_buffer + (sc.pitch * font_height) / 8, (sc.size - sc.pitch * font_height) / 8); 
    memcpy64((uint64_t*)sc.double_buffer, (uint64_t*)sc.double_buffer + (sc.pitch * font_height) / 8, (sc.size - sc.pitch * font_height) / 8);

    memset32((uint32_t*)sc.framebuffer + (sc.size - sc.pitch * font_height) / 4, text_background, sc.pitch * font_height / 4); 
    memset32((uint32_t*)sc.double_buffer + (sc.size - sc.pitch * font_height) / 4, text_background, sc.pitch * font_height / 4); 

    draw_cursor();
}

void ps2_keyboard([[maybe_unused]] regs *regs_cur, void*) {
    static char keymap[] = {    '\0', '\0', '1', '2', '3',  '4', '5', '6',  '7', '8', '9', '0',
                                '-', '=', '\b', '\t', 'q',  'w', 'e', 'r',  't', 'y', 'u', 'i',
                                'o', 'p', '[', ']', '\0',  '\0', 'a', 's',  'd', 'f', 'g', 'h',
                                'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
                                'b', 'n', 'm', ',', '.',  '/', '\0', '\0', '\0', ' '
                           };

    static char cap_keymap[] = {    '\0', '\e', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
                                    '_', '+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
                                    'O', 'P', '{', '}', '\0', '\0', 'A', 'S', 'D', 'F', 'G', 'H',
                                    'J', 'K', 'L', ':', '\'', '~', '\0', '\\', 'Z', 'X', 'C', 'V',
                                    'B', 'N', 'M', '<', '>',  '?', '\0', '\0', '\0', ' '
                              };

    static bool upkey = false;

    uint8_t keycode = inb(0x60);

    switch(keycode) {
        case 0xaa: // left shift release
            upkey = false;
            break;
        case 0x2a: // left shift press
            upkey = true;
            break;
        case 0xf: // tab
            tty_list[current_tty]->putchar('\t');
            break;
        case 0xe: // backspace
            tty_list[current_tty]->putchar('\b');
            break;
        case 0x1c: // enter
            tty_list[current_tty]->putchar('\n');
            break;
        default:
            if(keycode <= 128) {
                if(upkey) {
                    tty_list[current_tty]->putchar(cap_keymap[keycode]);
                } else {
                    tty_list[current_tty]->putchar(keymap[keycode]);
                }
            }
    }
}

bool console_code::validate(uint8_t c) {
    if(c >= '0' && c <= '9') {
        rrr = true;
        escape_grid[grid_index] *= 10;
        escape_grid[grid_index] += c - '0';
        return false;
    }

    if(rrr) {
        grid_index++;
        rrr = false;
        if(c == ';')
            return false;
    } else if(c == ';') {
        escape_grid[grid_index++] = 1;
        return false;
    }

    for(auto i = grid_index; i < max_escape_size; i++) {
        escape_grid[i] = 1;
    }

    return true; 
}

void console_code::add_character(uint8_t c) {
    if(!control_sequence) {
        if(c == '[') {
            memset8((uint8_t*)escape_grid, 0, sizeof(escape_grid));

            grid_index = 0;
            rrr = false;
            control_sequence = true;
        } else {
            parent->escape = false;
        }
        return;
    }

    if(!validate(c))
        return;

    switch(c) {
        case 'A':
            action_cuu();
            break;
        case 'B':
            action_cud();
            break;
        case 'C':
            action_cuf();
            break;
        case 'D':
            action_cub();
            break;
        case 'E':
            action_cnl();
            break;
        case 'F':
            action_cpl();
            break;
        case 'G':
            action_cha();
            break;
        case 'H':
            action_cup();
            break;
        case 'J':
            action_ed();
            break;
        case 'f':
            action_cup();
            break;
        case 'd':
            action_vpa();
            break;
        case 'r':
            action_decstbm(); 
            break;
        case 's':
            action_s();
            break;
        case 'u':
            action_u();
            break;
        case 'h':
            action_sm();
            break;
        case 'l':
            action_rm();
            break;
        case 'm':
            action_sgr();
            break;
        case '`':
            action_cha();
            break;
        case '?':
            dec_private_mode = true;
    }

    control_sequence = false;
    parent->escape = false;
}

console_code::console_code(tty *parent) : parent(parent) {
    rrr = false;
    decckm = false;
    control_sequence = false;
    dec_private_mode = false;

    memset8((uint8_t*)escape_grid, 0, sizeof(escape_grid));

    grid_index = 0;
    saved_cursor_x = 0;
    saved_cursor_y = 0;
    scrolling_region_top = 0;
    scrolling_region_bottom = 0;
}

void console_code::action_cuu() {
    if(escape_grid[0] > parent->cursor_y)
        escape_grid[0] = parent->cursor_y;

    parent->update_cursor(parent->cursor_x, parent->cursor_y + escape_grid[0]);
}

void console_code::action_cud() {
    if((parent->cursor_y + escape_grid[0]) > (parent->rows - 1))
        escape_grid[0] = (parent->rows - 1) - parent->cursor_y;

    parent->update_cursor(parent->cursor_x, parent->cursor_y + escape_grid[0]);
}

void console_code::action_cuf() {
    if((parent->cursor_x + escape_grid[0]) > (parent->cols - 1))
        escape_grid[0] = (parent->cols - 1) - parent->cursor_x;
    parent->update_cursor(parent->cursor_x + escape_grid[0], parent->cursor_y);
}

void console_code::action_cub() {
    if(escape_grid[0] > parent->cursor_x)
        escape_grid[0] = parent->cursor_x;
    parent->update_cursor(parent->cursor_x - escape_grid[0], parent->cursor_y);
}

void console_code::action_cnl() {
    if(parent->cursor_y + escape_grid[0] >= parent->rows)
        parent->update_cursor(0, parent->rows - 1);
    else
        parent->update_cursor(0, parent->cursor_y + escape_grid[0]);
}

void console_code::action_cpl() {
    if(parent->cursor_y - escape_grid[0] < 0)
        parent->update_cursor(0, 0);
    else
        parent->update_cursor(0, parent->cursor_y - escape_grid[0]);
}

void console_code::action_cha() {
    if(escape_grid[0] >= parent->cols)
        return;
    parent->clear_cursor();
    parent->cursor_x = escape_grid[0];
    parent->draw_cursor();
}

void console_code::action_ed() {
    switch(escape_grid[0]) {
        case 1: {
            parent->clear_cursor();

            for(int i = 0; i < (parent->cursor_y * parent->cols + parent->cursor_x); i++) {
                parent->plot_char(i % parent->cols, i / parent->cols, parent->text_foreground, parent->text_background, ' ');
            }

            parent->draw_cursor();

            break;
        }
        case 2:
            parent->clear();
    }
}

void console_code::action_cup() {
    escape_grid[0] -= 1;
    escape_grid[1] -= 1;

    if(escape_grid[1] >= parent->cols) {
        escape_grid[1] = parent->cols - 1;
    }

    if(escape_grid[0] >= parent->rows) {
        escape_grid[0] = parent->rows - 1;
    }

    parent->update_cursor(escape_grid[1], escape_grid[0]);
}

void console_code::action_vpa() {
    if(escape_grid[0] >= parent->rows)
        return;
    parent->clear_cursor();
    parent->cursor_y = escape_grid[0];
    parent->draw_cursor();
}

void console_code::action_decstbm() {
    scrolling_region_top = escape_grid[0];
    scrolling_region_bottom = escape_grid[1];
}

void console_code::action_s() {
    saved_cursor_x = parent->cursor_x;
    saved_cursor_y = parent->cursor_y;
}

void console_code::action_u() {
    parent->clear_cursor();
    parent->cursor_x = saved_cursor_x;
    parent->cursor_y = saved_cursor_y;
    parent->draw_cursor();
}

void console_code::action_sm() {
    if(dec_private_mode) {
        dec_private_mode = false;
        if(escape_grid[1] == 1) {
            decckm = true;
        }
    }
}

void console_code::action_rm() {
    if(dec_private_mode) {
        dec_private_mode = false;
        if(escape_grid[1] == 1) {
            decckm = false;
        }
    }
}

void console_code::action_sgr() {
    if(!grid_index) {
        parent->text_foreground = default_text_fg;
        parent->text_background = default_text_bg;
        return;
    }

    for(auto i = 0; i < grid_index; i++) {
        if(!escape_grid[i]) {
            parent->text_foreground = default_text_fg;
            parent->text_background = default_text_bg;
        } else {
            if(escape_grid[i] >= 30 && escape_grid[i] <= 37) {
                parent->text_foreground = ansi_colours[escape_grid[i] - 30];
            } else if(escape_grid[i] >= 40 && escape_grid[i] <= 47) {
                parent->text_background = ansi_colours[escape_grid[i] - 40];
            }
        }
    }
}

void tty::putchar(char c) {
    if(escape) {
        escape_sequence.add_character(c);
        return;
    }

    switch(c) {
        case '\n':
            if(cursor_y == (rows - 1)) {
                scroll();
                update_cursor(0, rows - 1);
            } else { 
                update_cursor(0, cursor_y + 1);
            }
            break;
        case '\r':
            update_cursor(0, cursor_y);
            break;
        case '\0':
            break;
        case '\b':
            if(cursor_x || cursor_y) {
                clear_cursor();

                if(cursor_x) {
                    cursor_x--;
                } else {
                    cursor_y--;
                    cursor_x = cols - 1;
                }
                
                draw_cursor();
            }
            break;
        case '\e':
            escape = true;
            break;
        default:
            clear_cursor(); 

            plot_char(cursor_x++, cursor_y, text_foreground, text_background, c);

            if(cursor_x == cols) {
                cursor_x = 0;
                cursor_y++;
            }

            if(cursor_y == rows) {
                cursor_y--;
                scroll();
            }

            draw_cursor();
    }

    last_char = c;
    new_key = true;
}

void tty::clear() {
    clear_cursor();

    for(int i = 0; i < rows * cols; i++) {
        plot_char(i % cols, i / cols, text_foreground, text_background, ' ');
    }

    cursor_x = 0;
    cursor_y = 0;

    draw_cursor();
}

int tty_ioctl::call(regs *regs_cur) {
    switch(regs_cur->rsi) {
        case tiocginsz: {
            winsize *win = reinterpret_cast<winsize*>(regs_cur->rdx);
            win->ws_row = tty_cur.rows;
            win->ws_col = tty_cur.cols;
            win->ws_xpixel = tty_cur.sc.width; 
            win->ws_ypixel = tty_cur.sc.height;
            return 0;
        }
    }

    return -1;
}

int tty::raw_read([[maybe_unused]] vfs::node *vfs_node, [[maybe_unused]] off_t off, off_t cnt, void *buf) {
    char *buffer = (char*)buf;
    
    asm ("sti");

    while(!new_key) {
        asm ("pause");
    }

    buffer[0] = last_char;

    new_key = false;

    return cnt;
}

int tty::raw_write([[maybe_unused]] vfs::node *vfs_node, [[maybe_unused]] off_t off, off_t cnt, void *buf) {
    lib::string str((char*)buf, cnt);

    for(size_t i = 0; i < str.length(); i++) {
        putchar(str[i]);
    }

    return cnt;
}

int tty::raw_open([[maybe_unused]] vfs::node *vfs_node, [[maybe_unused]] uint16_t status) {
    return 0;
}

tty::tty(screen &sc, uint8_t *font, size_t font_height, size_t font_width) : font(font), font_height(font_height), font_width(font_width), sc(sc) {
    cursor_x = 0;
    cursor_y = 0;
    tab_size = default_tab_size;
    new_key = false; 
    escape = false;
    cursor_foreground = default_cursor_fg;
    text_foreground = default_text_fg;
    text_background = default_text_bg;

    sc.flush(text_background);
    rows = sc.height / font_height;
    cols = sc.width / font_width;
    char_grid = (char*)kmm::calloc(rows * cols);
    draw_cursor();
    current_tty = tty_cnt;

    escape_sequence = console_code(this);

    ioctl_device = new tty_ioctl(*this);
    tty_list[tty_cnt] = this;

    dev::root_cluster.generate_node(lib::string("tty"), this, s_iwusr | s_irusr, ioctl_device);
}

extern "C" void syscall_syslog(regs *regs_cur) {
    print("\e[32m");

    lib::string message((char*)regs_cur->rdi);
    if(message[message.length() - 1] == '\n')
        message = lib::string((char*)regs_cur->rdi, message.length() - 1);

    print("{}\n", message);
}

}
