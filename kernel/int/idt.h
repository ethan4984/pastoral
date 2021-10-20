#pragma once

#include <stdint.h>

struct idtr {
	uint16_t limit;
	uint64_t offset;
} __attribute__((packed));

void idt_init();
