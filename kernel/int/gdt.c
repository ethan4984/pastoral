#include <int/gdt.h>
#include <mm/slab.h>

struct segment_descriptor {
	uint16_t limit;
	uint16_t base_low;
	uint8_t base_mid;
	uint8_t access;
	uint8_t granularity;
	uint8_t base_high;
} __attribute__((packed));

struct tss_descriptor {
	uint16_t length;
	uint16_t base_low;
	uint8_t base_mid;
	uint16_t flags;
	uint8_t base_high;
	uint32_t base_high32;
	uint32_t reserved;
} __attribute__((packed));

struct tss {
	uint32_t reserved;
	uint64_t rsp0;
	uint64_t rsp1;
	uint64_t rsp2;
	uint32_t reserved1;
	uint32_t reserved2;
	uint64_t ist1;
	uint64_t ist2; 
	uint64_t ist3;
	uint64_t ist4;
	uint64_t ist5;
	uint64_t ist6;
	uint64_t ist7;
	uint64_t reserved3;
	uint16_t reserved4;
	uint16_t iopb; 
} __attribute__((packed));

struct gdtr {
	uint16_t limit;
	uint64_t offset;
} __attribute__((packed));

struct gdt {
	struct segment_descriptor null;
	struct segment_descriptor kernel_code64;
	struct segment_descriptor kernel_data64;
	struct segment_descriptor user_code64;
	struct segment_descriptor user_data64;
	struct tss_descriptor tss_descriptor;
} __attribute__((packed));

void gdt_init() {
	struct gdt *gdt = alloc(sizeof(struct gdt));

	gdt->kernel_code64.access = 0b10011000;
	gdt->kernel_code64.granularity = 0b00100000;
	gdt->kernel_data64.access = 0b10010110;
	gdt->user_data64.access = 0b11110010;
	gdt->user_code64.access = 0b11111010;
	gdt->user_code64.granularity = 0b00100000;

	struct tss *tss = alloc(sizeof(struct tss));

	gdt->tss_descriptor.length = 104;
	gdt->tss_descriptor.base_low = (uintptr_t)tss & 0xffff;
	gdt->tss_descriptor.base_mid = (uintptr_t)tss >> 16 & 0xffff;
	gdt->tss_descriptor.flags = 0b10001001;
	gdt->tss_descriptor.base_high = (uintptr_t)tss >> 24 & 0xff;
	gdt->tss_descriptor.base_high32 = (uintptr_t)tss >> 32 & 0xffffffff;

	struct gdtr gdtr = {
		.limit = sizeof(struct gdt) - 1,
		.offset = (uintptr_t)gdt
	};
							
	asm volatile (	
		"lgdtq %0\n\t"
		"lea 1f(%%rip), %%rax\n\t"
		"push $0x8\n\t"
		"push %%rax\n\t"
		"lretq\n\t"
		"1:\n\t"
		"mov $0x10, %%ax\n\t"
		"mov %%ax, %%ds\n\t"
		"mov %%ax, %%ss\n\t"
		"mov %%ax, %%es\n\t"
		"mov %%ax, %%gs\n\t"
		"mov %%ax, %%fs\n\t"
		"mov $0x28, %%ax\n\t"
		"ltr %%ax\n\t"
		:: "m"(gdtr) : "rax", "memory"
	);
}
