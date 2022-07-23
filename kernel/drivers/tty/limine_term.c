#include <limine.h>
#include <drivers/tty/tty.h>
#include <drivers/tty/limine_term.h>
#include <mm/vmm.h>

#define LIMINE_TTY_MAJOR 4
static int limine_tty_minor;

struct limine_tty {
	struct page_table page_table;

	struct limine_terminal *terminal;
	limine_terminal_write write;
};


static ssize_t limine_tty_read(struct tty *tty, void *buf, size_t count);
static ssize_t limine_tty_write(struct tty *tty, const void *buf, size_t count);
static int limine_tty_ioctl(struct tty *tty, uint64_t req, void *arg);

static struct tty_ops limine_terminal_ops = {
	.read = limine_tty_read,
	.write = limine_tty_write,
	.ioctl = limine_tty_ioctl
};

static struct tty_driver limine_terminal_driver = {
	.ops = &limine_terminal_ops
};

static volatile struct limine_terminal_request limine_terminal_request = {
	.id = LIMINE_TERMINAL_REQUEST,
	.revision = 0
};


static void limine_print(struct limine_tty *ltty, const char *str, size_t length) {
	asm volatile("cli\n");
	char *s = alloc(length);
	memcpy(s, str, length);

	uint64_t cr3;
	asm volatile("mov %%cr3, %0" : "=r"(cr3));
	asm volatile("mov %0, %%cr3" :: "r"((uint64_t) ltty->page_table.pml_high - HIGH_VMA) : "memory");

	ltty->write(ltty->terminal, s, length);

	asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
	asm volatile("sti\n");
}


static ssize_t limine_tty_read(struct tty *tty, void *buf, size_t count) {
	return -1;
}

static ssize_t limine_tty_write(struct tty *tty, const void *buf, size_t count) {
	limine_print(tty->private_data, buf, count);
	return count;
}

static int limine_tty_ioctl(struct tty *tty, uint64_t req, void *arg) {
	return -1;
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
	}
}
