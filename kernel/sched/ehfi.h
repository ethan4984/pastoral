#pragma once

#include <stdint.h>
#include <stddef.h>

struct ehfi_hdr {
	uint64_t timestamp;
	uint8_t perf_change;
	uint8_t energy_change;
	uint8_t reserved[6];
} __attribute__((packed));

struct ehfi_entry {
	uint8_t perf_capability;
	uint8_t energy_capability;
	uint8_t reserved[6];
} __attribute__((packed));

struct ehfi_structure {
	struct ehfi_hdr hdr;
	struct ehfi_entry entries[];
};

int ehfi_init();
