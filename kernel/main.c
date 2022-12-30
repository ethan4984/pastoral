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
#include <drivers/tty/pty.h>
#include <drivers/keyboard.h>

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

static volatile struct limine_kernel_file_request limine_kernel_file_request = {
	.id = LIMINE_KERNEL_FILE_REQUEST,
	.revision = 0
};

static ssize_t kernel_file_read(struct elf_file*, void *buffer, off_t offset, size_t cnt) {
	struct limine_file *file = limine_kernel_file_request.response->kernel_file;

	memcpy8(buffer, file->address + offset, cnt);

	return cnt;
}

void init_process() {
	char *argv[] = { "/usr/sbin/init", NULL };
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

	struct task *task = alloc(sizeof(struct task));
	sched_default_task(task, CURRENT_TASK->namespace, 1);

	int ret = sched_load_program(task, argv[0]);
	if(ret == -1) panic("unable to start init process");

	ret = sched_task_init(task, envp, argv);
	if(ret == -1) panic("unable to start init process");

	waitq_trigger_calibrate(task->status_trigger, task, EVENT_PROCESS_STATUS);
	waitq_add(CURRENT_TASK->waitq, task->status_trigger);

	struct task *parent = task->parent;
	if(parent == NULL) panic("unable to start init process");

	task->session = parent->session;
	task->group = parent->group;

	VECTOR_PUSH(task->group->process_list, task);

	task->sched_status = TASK_WAITING;
	task->signal_queue.active = true;

	sched_dequeue(CURRENT_TASK);

	for(;;)
		asm ("hlt");
}

void pastoral_thread() {
	print("Greetings from pastorals kernel thread\n");

	if(initramfs() == -1) {
		panic("initramfs: unable to initialise");
	}

	limine_terminals_init();
	self_tty_init();
	pty_init();

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

	ps2_init();

	init_process();

	sched_dequeue(CURRENT_TASK);

	for(;;)
		asm ("hlt");
}

void pastoral_entry(void) {
	HIGH_VMA = limine_hhdm_request.response->offset;

	print("Pastoral unleashes the real power of the cpu\n");

	init_cpu_features();

	pmm_init();

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

	vmm_init();

	gdt_init();
	idt_init();

	kernel_file.read = kernel_file_read;
	if(elf64_file_init(&kernel_file) == -1) {
		panic("could not parse kernel file");
	}

	rsdp = limine_rsdp_request.response->address;

	if(rsdp->xsdt_addr) {
		xsdt = (struct xsdt*)(rsdp->xsdt_addr + HIGH_VMA);
		print("acpi: xsdt found at %x\n", (uintptr_t)xsdt);
	} else {
		rsdt = (struct rsdt*)(rsdp->rsdt_addr + HIGH_VMA);
		print("acpi: rsdt found at %x\n", (uintptr_t)rsdt);
	}

	fadt = acpi_find_sdt("FACP");

	vfs_init();

	hpet_init();
	apic_init();
	boot_aps();
	pci_init();
	pit_init();

	apic_timer_init(20);

	struct pid_namespace *namespace = sched_default_namespace();
	struct task *kernel_task = alloc(sizeof(struct task));
	sched_default_task(kernel_task, namespace, 1);

	kernel_task->regs.cs = 0x28;
	kernel_task->regs.ss = 0x30;
	kernel_task->regs.rip = (uintptr_t)pastoral_thread;
	kernel_task->regs.rflags = 0x202;
	kernel_task->regs.rsp = kernel_task->kernel_stack.sp;
	kernel_task->cwd = NULL;

	kernel_task->page_table = alloc(sizeof(struct page_table));
	vmm_default_table(kernel_task->page_table);

	task_create_session(kernel_task, true);

	kernel_task->sched_status = TASK_WAITING;

	asm ("sti");

	for(;;)
		asm ("hlt");
}
