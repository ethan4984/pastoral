#include <limine.h>
#include <cpu.h>
#include <debug.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <mm/mmap.h>
#include <mm/slab.h>
#include <int/apic.h>
#include <int/gdt.h>
#include <int/idt.h>
#include <sched/smp.h>
#include <sched/ehfi.h>
#include <acpi/rsdp.h>
#include <drivers/hpet.h>
#include <drivers/pci.h>
#include <drivers/pit.h>
#include <drivers/iommu/intel/vtd.h>
#include <drivers/tty/limine_term.h>
#include <drivers/fbdev.h>
#include <fs/vfs.h>
#include <fs/initramfs.h>
#include <sched/sched.h>
#include <time.h>
#include <hash.h>
#include <drivers/tty/self_tty.h>

static volatile struct limine_stack_size_request limine_stack_size_request = {
	.id = LIMINE_STACK_SIZE_REQUEST,
	.revision = 0,
	.stack_size = 0x8000
};

static volatile struct limine_hhdm_request limine_hhdm_request = {
	.id = LIMINE_HHDM_REQUEST,
	.revision = 0
};

static volatile struct limine_rsdp_request limine_rsdp_request = {
	.id = LIMINE_RSDP_REQUEST,
	.revision = 0
};

static volatile struct limine_framebuffer_request limine_framebuffer_request = {
	.id = LIMINE_FRAMEBUFFER_REQUEST,
	.revision = 0
};

void init_process() {
	char *argv[] = { "/init", NULL };
	char *envp[] = {
        "HOME=/",
        "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "TERM=linux",
		"FBDEV=/dev/fb0",
		NULL
	};

	struct sched_arguments *arguments = alloc(sizeof(struct sched_arguments));

	*arguments = (struct sched_arguments) {
		.argv = argv,
		.envp = envp,
		.envp_cnt = 3,
		.argv_cnt = 1
	};

	struct sched_task *task = sched_task_exec("/usr/sbin/init", 0x43, arguments, TASK_YIELD);
	if(task == NULL) {
		panic("unable to start init process");
	}

/*
	struct fd_handle *stdin_fd_handle = alloc(sizeof(struct fd_handle)),
		*stdout_fd_handle = alloc(sizeof(struct fd_handle)),
		*stderr_fd_handle = alloc(sizeof(struct fd_handle));

	struct file_handle *stdin_file_handle = alloc(sizeof(struct file_handle)),
		*stdout_file_handle = alloc(sizeof(struct file_handle)),
		*stderr_file_handle = alloc(sizeof(struct file_handle));

	struct file_ops *stdin_fops = alloc(sizeof(struct file_ops)),
		*stdout_fops = alloc(sizeof(struct file_ops)),
		*stderr_fops = alloc(sizeof(struct file_ops));

	struct stat *stdin_stat = alloc(sizeof(struct stat)),
		*stdout_stat = alloc(sizeof(struct stat)),
		*stderr_stat = alloc(sizeof(struct stat));

	fd_init(stdin_fd_handle);
	fd_init(stdout_fd_handle);
	fd_init(stderr_fd_handle);

	file_init(stdin_file_handle);
	file_init(stdout_file_handle);
	file_init(stderr_file_handle);

	stat_init(stdin_stat);
	stat_init(stdout_stat);
	stat_init(stderr_stat);

	stdin_fd_handle->fd_number = bitmap_alloc(&task->fd_bitmap);
	stdin_fd_handle->file_handle = stdin_file_handle;
	stdout_fd_handle->fd_number = bitmap_alloc(&task->fd_bitmap);
	stdout_fd_handle->file_handle = stdout_file_handle;
	stderr_fd_handle->fd_number = bitmap_alloc(&task->fd_bitmap);
	stderr_fd_handle->file_handle = stderr_file_handle;

	stdin_file_handle->flags = O_RDONLY;
	stdin_file_handle->ops = stdin_fops;
	stdin_file_handle->stat = stdin_stat;
	stdin_stat->st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stdin_fops->read = terminal_read;
	stdin_fops->ioctl = terminal_ioctl;

	stdout_file_handle->flags = O_WRONLY;
	stdout_file_handle->ops = stdout_fops;
	stdout_file_handle->stat = stdout_stat;
	stdout_stat->st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stdout_fops->write = terminal_write;
	stdout_fops->ioctl = terminal_ioctl;

	stderr_file_handle->flags = O_WRONLY;
	stderr_file_handle->ops = stderr_fops;
	stderr_file_handle->stat = stderr_stat;
	stderr_stat->st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stderr_fops->write = terminal_write;
	stderr_fops->ioctl = terminal_ioctl;

	hash_table_push(&task->fd_list, &stdin_fd_handle->fd_number, stdin_fd_handle, sizeof(stdin_fd_handle->fd_number));
	hash_table_push(&task->fd_list, &stdout_fd_handle->fd_number, stdout_fd_handle, sizeof(stdout_fd_handle->fd_number));
	hash_table_push(&task->fd_list, &stderr_fd_handle->fd_number, stderr_fd_handle, sizeof(stderr_fd_handle->fd_number));
*/
	struct sched_task *parent = sched_translate_pid(task->ppid);
	if(parent == NULL) {
		panic("");
	}

	task->session = parent->session;
	task->group = parent->group;

	VECTOR_PUSH(task->group->process_list, task);

	task->sched_status = TASK_WAITING;
}

void pastoral_thread() {
	print("Greetings from pastorals kernel thread\n");

	if(initramfs() == -1) {
		panic("initramfs: unable to initialise");
	}

	limine_terminals_init();
	self_tty_init();

	struct limine_framebuffer **framebuffers = limine_framebuffer_request.response->framebuffers;
	uint64_t framebuffer_count = limine_framebuffer_request.response->framebuffer_count;

	for(uint64_t i = 0; i < framebuffer_count; i++) {
		fbdev_init_device(framebuffers[i]);
		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/fb%d", i);

		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);
		stat->st_mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) | S_IFCHR;
		stat->st_rdev = makedev(FBDEV_MAJOR, (i));

		vfs_create_node_deep(NULL, NULL, NULL, stat, device_path);
	}

	init_process();

	sched_dequeue(CURRENT_TASK, CURRENT_THREAD);

	for(;;)
		asm ("hlt");
}

void pastoral_entry(void) {
	HIGH_VMA = limine_hhdm_request.response->offset;

	print("Pastoral unleashes the real power of the cpu\n");

	init_cpu_features();

	pmm_init();
	vmm_init();

	slab_cache_create(NULL, 32);
	slab_cache_create(NULL, 64);
	slab_cache_create(NULL, 128);
	slab_cache_create(NULL, 256);
	slab_cache_create(NULL, 512);
	slab_cache_create(NULL, 1024);
	slab_cache_create(NULL, 2048);
	slab_cache_create(NULL, 4096);
	slab_cache_create(NULL, 8192);
	slab_cache_create(NULL, 16384);

	gdt_init();
	idt_init();

	rsdp = limine_rsdp_request.response->address;

	if(rsdp->xsdt_addr) {
		xsdt = (struct xsdt*)(rsdp->xsdt_addr + HIGH_VMA);
		print("acpi: xsdt found at %x\n", (uintptr_t)xsdt);
	} else {
		rsdt = (struct rsdt*)(rsdp->rsdt_addr + HIGH_VMA);
		print("acpi: rsdt found at %x\n", (uintptr_t)rsdt);
	}

	vfs_init();

	hpet_init();
	apic_init();
	boot_aps();
	pci_init();
	pit_init();

	apic_timer_init(20);

	struct sched_task *kernel_task = sched_default_task();
	struct sched_thread *kernel_thread = sched_default_thread(kernel_task);

	kernel_thread->regs.cs = 0x28;
	kernel_thread->regs.ss = 0x30;
	kernel_thread->regs.rip = (uintptr_t)pastoral_thread;
	kernel_thread->regs.rflags = 0x202;
	kernel_thread->regs.rsp = kernel_thread->kernel_stack;
	kernel_task->cwd = NULL;

	kernel_task->page_table = alloc(sizeof(struct page_table));
	vmm_default_table(kernel_task->page_table);

	task_create_session(kernel_task, true);

	kernel_task->sched_status = TASK_WAITING;
	kernel_thread->sched_status = TASK_WAITING;

	asm ("sti");

	for(;;)
		asm ("hlt");
}
