#pragma once

#include <mm/vmm.h>
#include <types.h>

struct cpu_local {
	uintptr_t kernel_stack;
	uintptr_t user_stack;
	uint64_t errno;
	pid_t pid;
	tid_t tid;
	int apic_id;
	struct page_table *page_table;
} __attribute__((packed));

extern size_t logical_processor_cnt;

void boot_aps();
