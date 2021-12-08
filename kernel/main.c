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

	hpet_init();

	apic_init();
	boot_aps();

	ehfi_init();
	
	apic_timer_init(100);

	asm ("sti");

	for(;;)
		asm ("hlt");
}
