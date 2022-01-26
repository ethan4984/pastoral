#include <stivale.h>
#include <cpu.h>
#include <debug.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
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

void pastoral_entry(struct stivale_struct *stivale_struct) {
	print("Pastoral unleashes the real power of the cpu\n");

	init_cpu_features();

	pmm_init(stivale_struct);
	vmm_init(stivale_struct);

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

	tty_init(stivale_struct);

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

	struct vfs_node *node0 = vfs_create_node(NULL, vfs_default_asset(S_IFDIR), NULL, "lol");
	struct vfs_node *node1 = vfs_create_node(NULL, vfs_default_asset(S_IFDIR), NULL, "bruh");
	struct vfs_node *node2 = vfs_create_node(NULL, vfs_default_asset(S_IFDIR), NULL, "what");
	struct vfs_node *node3 = vfs_create_node(node2, vfs_default_asset(S_IFREG), NULL, "file");
	struct vfs_node *node4 = vfs_create_node(node2, vfs_default_asset(S_IFREG), NULL, "file1");
	struct vfs_node *node5 = vfs_create_node_deep(NULL, vfs_default_asset(S_IFREG), NULL, "/what/lol/ok/kill");

	const char *node0_path = vfs_absolute_path(node0);
	const char *node1_path = vfs_absolute_path(node1);
	const char *node2_path = vfs_absolute_path(node2);
	const char *node3_path = vfs_absolute_path(node3);
	const char *node4_path = vfs_absolute_path(node4);
	const char *node5_path = vfs_absolute_path(node5);

	print("%x: %s\n", (uintptr_t)node0, node0_path); 
	print("%x: %s\n", (uintptr_t)node1, node1_path); 
	print("%x: %s\n", (uintptr_t)node2, node2_path); 
	print("%x: %s\n", (uintptr_t)node3, node3_path); 
	print("%x: %s\n", (uintptr_t)node4, node4_path); 
	print("%x: %s\n", (uintptr_t)node5, node5_path); 

	struct vfs_node *node6 = vfs_search_absolute(NULL, "/what/lol/ok/kill");

	print("found this %x\n", (uintptr_t)node6);

	for(;;);

	hpet_init();
	apic_init();
	boot_aps();
	pci_init();
	ehfi_init();
	vtd_init();
	pit_init(stivale_struct);

	apic_timer_init(100);

	asm ("sti");

	for(;;)
		asm ("hlt");
}
