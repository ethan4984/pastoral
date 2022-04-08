#pragma once

#include <cpu.h>

struct idtr {
	uint16_t limit;
	uint64_t offset;
} __attribute__((packed));

int idt_alloc_vector(void (*handler)(struct registers*, void*), void *ptr);
void idt_init();
