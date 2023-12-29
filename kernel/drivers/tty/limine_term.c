#include <limine.h>
#include <drivers/tty/tty.h>
#include <drivers/tty/limine_term.h>
#include <drivers/tty/console_ioctl.h>
#include <sched/queue.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <int/apic.h>
#include <int/idt.h>
#include <debug.h>
#include <errno.h>

#define LIMINE_TTY_MAJOR 4

static int limine_tty_minor;

struct limine_tty {
	struct page_table page_table;

	struct limine_terminal *terminal;
	limine_terminal_write write;

	struct waitq waitq;
	struct waitq_trigger *trigger;

	bool shift;
	bool caps;
	bool control;
	bool extended;

	bool graphics;
	struct vt_mode vt_mode;

	void *fb_addr;
	size_t fb_pitch;
	size_t fb_width;
	size_t fb_height;
	void *fb_saved;
	size_t fb_saved_len;
};

static void limine_tty_flush_output(struct tty *tty);
static int limine_tty_ioctl(struct tty *tty, uint64_t req, void *arg);

static struct tty_ops limine_terminal_ops = {
	.ioctl = limine_tty_ioctl,
	.flush_output = limine_tty_flush_output
};

static struct tty_driver limine_terminal_driver = {
	.ops = &limine_terminal_ops
};

static volatile struct limine_terminal_request limine_terminal_request = {
	.id = LIMINE_TERMINAL_REQUEST,
	.revision = 0
};

static void limine_print(struct limine_tty *ltty, char *str, size_t length) {
	asm volatile("cli");

	uint64_t cr3;
	asm volatile("mov %%cr3, %0" : "=r"(cr3));
	asm volatile("mov %0, %%cr3" :: "r"((uint64_t) ltty->page_table.pml_high - HIGH_VMA) : "memory");
	
	ltty->write(ltty->terminal, str, length);

	asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
	asm volatile("sti");
}

static void limine_tty_flush_output(struct tty *tty) {
	spinlock_irqsave(&tty->output_lock);
	char ch;
	char buf[OUTPUT_BUFFER_SIZE];
	size_t count = 0;
	while(circular_queue_pop(&tty->output_queue, &ch)) {
		buf[count] = ch;
		count++;
	}
	limine_print(tty->private_data, buf, count);
	spinrelease_irqsave(&tty->output_lock);
}

static int limine_tty_ioctl(struct tty *tty, uint64_t req, void *arg) {
	struct limine_tty *ltty = tty->private_data;

	switch(req) {
		case TIOCGWINSZ:
			struct winsize *winsize = arg;

			*winsize = (struct winsize) {
				.ws_row = ltty->terminal->rows,
				.ws_col = ltty->terminal->columns,
				.ws_xpixel = ltty->fb_width,
				.ws_ypixel = ltty->fb_height
			};

			break;

		case KDSETMODE:
			ltty->graphics = (uintptr_t)arg;
			if(ltty->graphics) {
				// Save current framebuffer and disable cursor.
				if(!ltty->fb_saved) {
					ltty->fb_saved_len = (ltty->fb_pitch * ltty->fb_height);
					ltty->fb_saved = (void *)(pmm_alloc(ltty->fb_saved_len / PAGE_SIZE, 1) + HIGH_VMA);
				}
				limine_print(ltty, "\e[?25l", 6);
				memcpy(ltty->fb_saved, ltty->fb_addr, ltty->fb_saved_len);
			} else {
				if(ltty->fb_saved) {
					memcpy(ltty->fb_addr, ltty->fb_saved, ltty->fb_saved_len);
				}
				limine_print(ltty, "\e[?25h", 6);
			}
			break;

		case KDGETMODE: {
			int *mode = arg;
			*mode = ltty->graphics;
			break;
		}

		case VT_GETMODE:
			memcpy(arg, &ltty->vt_mode, sizeof(struct vt_mode));
			break;

		case VT_SETMODE:
			memcpy(&ltty->vt_mode, arg, sizeof(struct vt_mode));
			break;

		default:
			set_errno(ENOSYS);
			return -1;
	}

	return 0;
}

void limine_terminals_init() {
	struct limine_terminal **limine_terminals = limine_terminal_request.response->terminals;
	for(size_t i = 0; i < limine_terminal_request.response->terminal_count; i++) {
		struct limine_framebuffer *framebuffer = limine_terminals[i]->framebuffer;
		struct limine_tty *ltty = alloc(sizeof(struct limine_tty));
		struct tty *tty = alloc(sizeof(struct tty));

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

		ltty->terminal = limine_terminals[i];
		ltty->write = limine_terminal_request.response->write;
		ltty->trigger = waitq_alloc(&ltty->waitq, EVENT_COMMAND);
		ltty->fb_addr = (void *) framebuffer->address;
		ltty->fb_pitch = framebuffer->pitch;
		ltty->fb_width = framebuffer->width;
		ltty->fb_height = framebuffer->height;

		tty->driver = &limine_terminal_driver;
		tty->private_data = ltty;
		tty_register(makedev(LIMINE_TTY_MAJOR, limine_tty_minor), tty);

		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/tty%d", limine_tty_minor);

		print("creating tty %s\n", device_path);

		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);
		stat->st_rdev = makedev(LIMINE_TTY_MAJOR, limine_tty_minor);
		stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

		vfs_create_node_deep(NULL, NULL, NULL, stat, device_path);
		limine_tty_minor++;

		// TODO: make current terminal switching.
		if(!active_tty)
			active_tty = tty;
	}
}
