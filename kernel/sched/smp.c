#include <sched/smp.h>
#include <int/apic.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <acpi/madt.h>
#include <int/idt.h>
#include <int/gdt.h>
#include <string.h>
#include <cpu.h>
#include <debug.h>

static char core_init_lock;

static void core_bootstrap(struct cpu_local *cpu_local) {
	print("initalising core: apic_id %x\n", xapic_read(XAPIC_ID_REG_OFF) >> 24);

	spinrelease(&core_init_lock);

	init_cpu_features();
	gdt_init();

	wrmsr(MSR_GS_BASE, (uintptr_t)cpu_local);

	xapic_write(XAPIC_TPR_OFF, 0);
	xapic_write(XAPIC_SINT_OFF, xapic_read(XAPIC_SINT_OFF) | 0x1ff);

	asm volatile ("mov %0, %%cr8\nsti" :: "r"(0ull));

	for(;;) {
		asm ("hlt");
	}
};

asm (
	".global smp_init_begin\n\t"
	"smp_init_begin: .incbin \"sched/smp.bin\"\n\t"
	".global smp_init_end\n\t"
	"smp_init_end:\n\t"
);

extern uint64_t smp_init_begin[];
extern uint64_t smp_init_end[];

void boot_aps() {
	struct idtr idtr;
	asm ("sidtq %0" :: "m"(idtr));

	kernel_mappings.map_page(&kernel_mappings, 0, 0, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS);
	memcpy8((void*)0x80000, (void*)(uintptr_t)smp_init_begin, (uintptr_t)smp_init_end - (uintptr_t)smp_init_begin);

	for(size_t i = 0; i < madt_ent0_list.element_cnt; i++) {
		struct madt_ent0 *madt0 = &madt_ent0_list.elements[i];

		if(madt0->flags != 1) { // unusable
			continue;
		}

		struct cpu_local *cpu_local = alloc(sizeof(struct cpu_local));

		*cpu_local = (struct cpu_local) {
			.kernel_stack = pmm_alloc(2, 1) + HIGH_VMA,
			.apic_id = madt0->apic_id,
			.pid = -1,
			.tid = -1,
			.page_table = &kernel_mappings
		};

		if(cpu_local->apic_id == (xapic_read(XAPIC_ID_REG_OFF) >> 24)) {
			wrmsr(MSR_GS_BASE, (uintptr_t)cpu_local);
			continue;
		}

		spinlock(&core_init_lock);

		uint64_t *parameters = (uint64_t*)0x81000;

		parameters[0] = cpu_local->kernel_stack;
		parameters[1] = (uintptr_t)(kernel_mappings.pml_high - HIGH_VMA);
		parameters[2] = (uintptr_t)core_bootstrap;
		parameters[3] = (uintptr_t)cpu_local;
		parameters[4] = (uintptr_t)&idtr;
		parameters[5] = 0; // la57

		uint8_t apic_id = madt0->apic_id;

		xapic_write(XAPIC_ICR_OFF + 0x10, (apic_id << 24));
		xapic_write(XAPIC_ICR_OFF, 0x500); // MT = 0b101 init ipi

		xapic_write(XAPIC_ICR_OFF + 0x10, (apic_id << 24));
		xapic_write(XAPIC_ICR_OFF, 0x600 | 0x80); // MT = 0b11 V=0x80 for 0x80000
	}

	while((volatile char)core_init_lock);

	kernel_mappings.unmap_page(&kernel_mappings, 0);
}
