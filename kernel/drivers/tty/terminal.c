#include <drivers/tty/terminal.h>
#include <drivers/tty/console_ioctl.h>
#include <drivers/tty/tty.h>
#include <drivers/fbdev.h>
#include <events/queue.h>
#include <mm/pmm.h>
#include <errno.h>
#include <limine.h>

#ifndef LIMINE_TERMINAL
#include <drivers/flanterm/backends/fb.h>
#endif

struct flanterm_tty {
	struct flanterm_context *ft_ctx;

	struct waitq waitq;
	struct waitq_trigger *trigger;

	bool graphics;
	struct vt_mode vt_mode;

	struct fb_device *fb;
	struct fb_device *fb_save;
};

struct limine_tty {
	struct page_table page_table;

	struct limine_terminal *terminal;
	limine_terminal_write write;

	struct waitq waitq;
	struct waitq_trigger *trigger;

	bool graphics;
	struct vt_mode vt_mode;

	struct fb_device *fb;
	struct fb_device *fb_save;
};

static void terminal_tty_flush_output(struct tty *tty);
static int terminal_tty_ioctl(struct tty *tty, uint64_t req, void *arg);

#define TTY_MAJOR 4

static int tty_minor = 0;

static struct tty_ops terminal_ops = {
	.ioctl = terminal_tty_ioctl,
	.flush_output = terminal_tty_flush_output
};

static struct tty_driver terminal_driver = {
	.ops = &terminal_ops
};

#ifdef LIMINE_TERMINAL
static volatile struct limine_terminal_request limine_terminal_request = {
	.id = LIMINE_TERMINAL_REQUEST,
	.revision = 0
};
#endif

#ifdef LIMINE_TERMINAL
static void limine_print(struct limine_tty *ltty, char *str, size_t length) {
	asm volatile("cli");

	uint64_t cr3;
	asm volatile("mov %%cr3, %0" : "=r"(cr3));
	asm volatile("mov %0, %%cr3" :: "r"((uint64_t) ltty->page_table.pml_high - HIGH_VMA) : "memory");
	
	ltty->write(ltty->terminal, str, length);

	asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
	asm volatile("sti");
}
#endif

static void terminal_tty_flush_output(struct tty *tty) {
	spinlock_irqsave(&tty->output_lock);

	char ch;
	char buf[OUTPUT_BUFFER_SIZE];
	size_t count = 0;

	while(circular_queue_pop(&tty->output_queue, &ch)) {
		buf[count] = ch;
		count++;
	}

#ifdef LIMINE_TERMINAL
	limine_print(tty->private_data, buf, count);
#else
	struct flanterm_tty *ftty = tty->private_data;
	flanterm_write(ftty->ft_ctx, buf, count);
#endif

	spinrelease_irqsave(&tty->output_lock);
}

static int terminal_tty_ioctl(struct tty *tty, uint64_t req, void *arg) {
#ifdef LIMINE_TERMINAL
	struct limine_tty *term = tty->private_data;
#else
	struct flanterm_tty *term = tty->private_data;
#endif

	switch(req) {
		case TIOCGWINSZ:
			struct winsize *winsize = arg;

			*winsize = (struct winsize) {
#ifdef LIMINE_TERMINAL
				.ws_row = term->terminal->rows,
				.ws_col = term->terminal->columns,
#else
				.ws_row = term->ft_ctx->rows,
				.ws_col = term->ft_ctx->cols,
#endif
				.ws_xpixel = term->fb->var->xres,
				.ws_ypixel = term->fb->var->yres
			};

			break;
		case KDSETMODE:
			term->graphics = (uintptr_t)arg;

			if(term->graphics) {
				if(!term->fb_save) {
					term->fb_save = alloc(sizeof(struct fb_device));
					term->fb_save->var = alloc(sizeof(struct fb_var_screeninfo));
					term->fb_save->fix = alloc(sizeof(struct fb_fix_screeninfo));

					*term->fb_save->var = *term->fb->var;
					*term->fb_save->fix = *term->fb->fix;

					term->fb_save->fix->smem_start = (pmm_alloc(term->fb_save->fix->smem_len / PAGE_SIZE, 1)
							+ HIGH_VMA);
				}

#ifdef LIMINE_TERMINAL
				limine_print(term, "\e[?25l", 6);
#else
				flanterm_write(term->ft_ctx, "\e[?25l", 6);
#endif

				memcpy((void*)term->fb_save->fix->smem_start, (void*)term->fb->fix->smem_start,
						term->fb->fix->smem_len);
			} else {
				if(term->fb_save) {
					memcpy((void*)term->fb->fix->smem_start, (void*)term->fb_save->fix->smem_start,
						term->fb->fix->smem_len);
				}

#ifdef LIMINE_TERMINAL
				limine_print(term, "\e[?25h", 6);
#else
				flanterm_write(term->ft_ctx, "\e[?25h", 6);
#endif
			}

			break;
		case KDGETMODE: {
			int *mode = arg;
			*mode = term->graphics;
			break;
		}
		case VT_GETMODE:
			memcpy(arg, &term->vt_mode, sizeof(struct vt_mode));
			break;
		case VT_SETMODE:
			memcpy(&term->vt_mode, arg, sizeof(struct vt_mode));
			break;
		default:
			set_errno(ENOSYS);
			return -1;
	}

	return 0;
}

#ifdef LIMINE_TERMINAL
static void limine_terminals_init() {
	struct limine_terminal *limine_terminal = *limine_terminal_request.response->terminals;

	struct limine_framebuffer *framebuffer = limine_terminal->framebuffer;
	struct limine_tty *ltty = alloc(sizeof(struct limine_tty));

	vmm_default_table(&ltty->page_table);
	uint64_t phys = 0;
	for(size_t i = 0; i < 0x800; i++) {
		ltty->page_table.map_page(&ltty->page_table, phys, phys,
			VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G);
		phys += 0x200000;
	}

	uint64_t fbaddr = (uint64_t)framebuffer->address - HIGH_VMA;
	uint64_t fbsize = (framebuffer->pitch * framebuffer->height);
	for(size_t i = 0; i < DIV_ROUNDUP(fbsize, 0x200000); i++) {
		ltty->page_table.map_page(&ltty->page_table, fbaddr, fbaddr,
			VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G);
		fbaddr += 0x200000;
	}

	ltty->terminal = limine_terminal;
	ltty->write = limine_terminal_request.response->write;
	ltty->trigger = EVENT_DEFAULT_TRIGGER(&ltty->waitq);

	ltty->fb = alloc(sizeof(struct fb_device));
	ltty->fb->var = alloc(sizeof(struct fb_var_screeninfo));
	ltty->fb->fix = alloc(sizeof(struct fb_fix_screeninfo));

	ltty->fb->fix->smem_start = (uint64_t)framebuffer->address;
	ltty->fb->fix->line_length = framebuffer->pitch;
	ltty->fb->var->xres = framebuffer->width;
	ltty->fb->var->yres = framebuffer->height;

	for(size_t i = 0; i < TTY_COUNT; i++) {
		struct tty *tty = alloc(sizeof(struct tty));

		tty->driver = &terminal_driver;
		tty->private_data = ltty;
		tty_register(makedev(TTY_MAJOR, tty_minor), tty);

		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/tty%d", tty_minor);

		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);
		stat->st_rdev = makedev(TTY_MAJOR, tty_minor);
		stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

		vfs_create_node_deep(NULL, NULL, NULL, stat, device_path);
		tty_minor++;
	}
}
#endif

#ifndef LIMINE_TERMINAL
static void flanterm_terminals_init(struct limine_framebuffer *framebuffer) {
	struct flanterm_tty *ftty = alloc(sizeof(struct flanterm_tty));

	ftty->fb = alloc(sizeof(struct fb_device));
	ftty->fb->var = alloc(sizeof(struct fb_var_screeninfo));
	ftty->fb->fix = alloc(sizeof(struct fb_fix_screeninfo));

	ftty->fb->fix->smem_start = (uint64_t)framebuffer->address;
	ftty->fb->fix->line_length = framebuffer->pitch;
	ftty->fb->var->xres = framebuffer->width;
	ftty->fb->var->yres = framebuffer->height;

	ftty->ft_ctx = flanterm_fb_simple_init (
		(void*)framebuffer->address, framebuffer->width, framebuffer->height, framebuffer->pitch
	);

	for(size_t i = 0; i < TTY_COUNT; i++) {
		struct tty *tty = alloc(sizeof(struct tty));

		tty->driver = &terminal_driver;
		tty->private_data = ftty;
		tty_register(makedev(TTY_MAJOR, tty_minor), tty);

		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/tty%d", tty_minor);

		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);
		stat->st_rdev = makedev(TTY_MAJOR, tty_minor);
		stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

		vfs_create_node_deep(NULL, NULL, NULL, stat, device_path);
		tty_minor++;
	}
}
#endif

void terminals_init(struct limine_framebuffer *framebuffer) {
#ifdef LIMINE_TERMINAL
	framebuffer;
	limine_terminals_init();
#else
	flanterm_terminals_init(framebuffer);
#endif
}
