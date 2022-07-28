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

	bool graphics;
	struct vt_mode vt_mode;
};

static struct tty *active_tty;

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
	asm volatile("cli\n");

	uint64_t cr3;
	asm volatile("mov %%cr3, %0" : "=r"(cr3));
	asm volatile("mov %0, %%cr3" :: "r"((uint64_t) ltty->page_table.pml_high - HIGH_VMA) : "memory");

	ltty->write(ltty->terminal, str, length);

	asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
	asm volatile("sti\n");
}


static char keymap_nocaps[] = {
	'\0', '\0', '1', '2', '3',	'4', '5', '6',	'7', '8', '9', '0',
	'-', '=', '\b', '\t', 'q',	'w', 'e', 'r',	't', 'y', 'u', 'i',
	'o', 'p', '[', ']', '\n',  '\0', 'a', 's',	'd', 'f', 'g', 'h',
	'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', ',', '.',  '/', '\0', '\0', 27, ' '
};

static char keymap_caps[] = {
	'\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	'-','=', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
	'O', 'P', '[', ']', '\n', '\0', 'A', 'S', 'D', 'F', 'G', 'H',
	'J', 'K', 'L', ';', '\'', '`', '\0', '\\', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', ',', '.', '/', '\0', '\0', 27, ' '
};

static char keymap_shift_nocaps[] = {
	'\0', '\0', '!', '@', '#',	'$', '%', '^',	'&', '*', '(', ')',
	'_', '+', '\b', '\t', 'Q',	'W', 'E', 'R',	'T', 'Y', 'U', 'I',
	'O', 'P', '{', '}', '\n',  '\0', 'A', 'S',	'D', 'F', 'G', 'H',
	'J', 'K', 'L', ':', '\"', '~', '\0', '|', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', '<', '>',  '?', '\0', '\0', 27, ' '
};

static char keymap_shift_caps[] = {
	'\0', '\0', '!', '@', '#',	'$', '%', '^',	'&', '*', '(', ')',
	'_', '+', '\b', '\t', 'q',	'w', 'e', 'r',	't', 'y', 'u', 'i',
	'o', 'p', '{', '}', '\n',  '\0', 'a', 's',	'd', 'f', 'g', 'h',
	'j', 'k', 'l', ':', '\"', '~', '\0', '|', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', '<', '>',  '?', '\0', '\0', 27, ' '
};

static void ps2_handler(struct registers *, void *) {
	if(!active_tty) {
		while(inb(0x64) & 1)
			inb(0x60);
		return;
	}

	struct limine_tty *ltty = active_tty->private_data;
	spinlock_irqsave(&active_tty->input_lock);
	while(inb(0x64) & 1) {
		uint8_t keycode = inb(0x60);

		switch(keycode) {
			case 0xaa:
				ltty->shift = true;
				break;
			case 0x2a:
				ltty->shift = false;
				break;
			case 0x36:
				ltty->shift = true;
				break;
			case 0xb6:
				ltty->shift = false;
				break;
			case 0x3a:
				ltty->caps = !ltty->caps;
				break;
			case 0x1d:
				ltty->control = true;
				break;
			case 0x9d:
				ltty->control = false;
				break;
			default:
				if(keycode <= 128) {
					char character;

					if(!ltty->shift && !ltty->caps) {
						character = keymap_nocaps[keycode];
					} else if(!ltty->shift && ltty->caps) {
						character = keymap_caps[keycode];
					} else if(ltty->shift && !ltty->caps) {
						character = keymap_shift_nocaps[keycode];
					} else {
						character = keymap_shift_caps[keycode];
					}

					if(ltty->control) {
						if((character >= 'A') && (character <= 'z')) {
							if(character >= 'a') {
								character = character - 'a' + 1;
							} else if(character <= '^') {
								character = character - 'A' + 1;
							}
						}
					}

					if(!circular_queue_push(&active_tty->input_queue, &character)) {
						break;
					}
				}
		}
	}

	for(size_t i = 0; i < active_tty->files.length; i++) {
		struct file_handle *handle = active_tty->files.data[i];
		waitq_wake(handle->trigger);
	}

	spinrelease_irqsave(&active_tty->input_lock);
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
				.ws_row = ltty->terminal->columns,
				.ws_col = ltty->terminal->rows,
				.ws_xpixel = ltty->terminal->framebuffer->width,
				.ws_ypixel = ltty->terminal->framebuffer->height
			};

			break;

		case KDSETMODE:
			ltty->graphics = (int) arg;
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
		uint64_t fbsize = (framebuffer->width * framebuffer->bpp * framebuffer->pitch) / 8;
		for(size_t i = 0; i < DIV_ROUNDUP(fbsize, 0x200000); i++) {
			ltty->page_table.map_page(&ltty->page_table, fbaddr, fbaddr,
				VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G);
			fbaddr += 0x200000;
		}

		ltty->terminal = limine_terminals[i];
		ltty->write = limine_terminal_request.response->write;
		ltty->trigger = waitq_alloc(&ltty->waitq, EVENT_COMMAND);

		tty->driver = &limine_terminal_driver;
		tty->private_data = ltty;
		tty_register(makedev(LIMINE_TTY_MAJOR, limine_tty_minor), tty);

		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/tty%d", limine_tty_minor);

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

	// TODO: make a PS/2 driver and remove this outta here.
	int ps2_vector = idt_alloc_vector(ps2_handler, NULL);
	ioapic_set_irq_redirection(xapic_read(XAPIC_ID_REG_OFF), ps2_vector, 1, false);
}
