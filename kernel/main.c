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
#include <drivers/terminal.h>
#include <drivers/fbdev.h>
#include <fs/vfs.h>
#include <fs/initramfs.h>
#include <sched/sched.h>
#include <hash.h>

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

void pastoral_thread() {
	print("Greetings from pastorals kernel thread\n");

	if(initramfs() == -1) {
		panic("initramfs: unable to initialise");
	}

	struct limine_framebuffer **framebuffers = limine_framebuffer_request.response->framebuffers;
	uint64_t framebuffer_count = limine_framebuffer_request.response->framebuffer_count;

	for(uint64_t i = 0; i < framebuffer_count; i++) {
		fbdev_init_device(framebuffers[i]);
	}

	limine_terminal_init();

	char *argv[] = { "/usr/bin/bash", NULL };
	char *envp[] = {
        "HOME=/",
        "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "TERM=linux",
		NULL
	};

	struct sched_arguments *arguments = alloc(sizeof(struct sched_arguments));

	*arguments = (struct sched_arguments) {
		.argv = argv,
		.envp = envp,
		.envp_cnt = 3,
		.argv_cnt = 1 
	};

	sched_task_exec("/usr/bin/bash", 0x43, arguments, TASK_WAITING);

	/*char *argv[] = { "/init", "big butt hoes", NULL };
	char *envp[] = {
        "HOME=/",
        "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "TERM=linux",
		NULL
	};

	struct sched_arguments *arguments = alloc(sizeof(struct sched_arguments));

	*arguments = (struct sched_arguments) {
		.argv = argv,
		.envp = envp,
		.envp_cnt = 3,
		.argv_cnt = 2 
	};

	sched_task_exec("/init", 0x43, arguments, TASK_WAITING);*/

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

	apic_timer_init(100);

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

	kernel_task->status = TASK_WAITING;
	kernel_thread->status = TASK_WAITING;

	asm ("sti");

	for(;;)
		asm ("hlt");
}
