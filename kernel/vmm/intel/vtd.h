#pragma once

#include <acpi/rsdp.h>

#define DMAR_UNIT_TYPE 0
#define DMAR_RMRR_TYPE 1
#define DMAR_ATSR_TYPE 2
#define DMAR_RHSA_TYPE 3
#define DMAR_ANDD_TYPE 4

struct device_scope {
	uint8_t type;
	uint8_t length;
	uint16_t reserved;
	uint8_t id;
	uint8_t bus_number;
	uint16_t path[];
} __attribute__((packed));

struct dmar_unit {
	uint16_t type;
	uint16_t length;
	uint8_t flags;
	uint8_t reserved;
	uint16_t segment_number;
	uint64_t register_base;
	struct device_scope scope[];
} __attribute__((packed));

struct dmar {
	struct acpi_hdr acpi_hdr;
	uint8_t host_address_width;
	uint8_t flags;
	uint8_t reserved[10];
	struct dmar_unit units[];
} __attribute__((packed));

int vtd_init();
