#include <stivale.h>
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
#include <drivers/tty.h>
#include <drivers/hpet.h>
#include <drivers/pci.h>
#include <drivers/pit.h>
#include <drivers/iommu/intel/vtd.h>
#include <fs/vfs.h>
#include <fs/initramfs.h>
#include <sched/sched.h>
#include <hash.h>

static uint8_t stack[8192];

__attribute__((section(".stivalehdr"), used))
static struct stivale_header stivale_hdr = {
	.stack = (uintptr_t)stack + sizeof(stack),
	.flags = (1 << 0) | (1 << 1) | (1 << 3),
	.framebuffer_width	= 1024,
	.framebuffer_height = 768,
	.framebuffer_bpp = 32,
	.entry_point = 0
};

struct stivale_struct *stivale_struct;

void pastoral_thread() {
	print("Greetings from pastorals kernel thread %b\n", (1 << 7));

	if(initramfs() == -1) {
		panic("initramfs: unable to initialise");
	}

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

	struct vfs_node *vfs_node = vfs_root; 
	print("bruh %x\n", vfs_node);
	for(size_t i= 0; i < vfs_node->children.length; i++) {
		struct vfs_node *node = vfs_node->children.data[i];
		print("%s %x\n", node->name, node->parent);
	}

	sched_task_exec("/usr/bin/bash", 0x23, arguments, TASK_WAITING);

	/*char *argv[] = { "/init", NULL };
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

	sched_task_exec("/init", 0x23, arguments, TASK_WAITING);*/

	for(;;)
		asm ("hlt");
}

void pastoral_entry(uintptr_t stivale_addr) {
	print("Pastoral unleashes the real power of the cpu\n");

	stivale_struct = (struct stivale_struct*)stivale_addr;

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

	tty_init();

	gdt_init();
	idt_init();

	rsdp = (struct rsdp*)stivale_struct->rsdp;	

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

	kernel_thread->regs.cs = 0x8;
	kernel_thread->regs.ss = 0x10;
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
