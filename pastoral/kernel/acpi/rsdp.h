#pragma once

#include <stdint.h>
#include <stddef.h>

struct acpi_hdr {
	char signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	char OEMID[6];
	char OEM_table_id[8];
	uint32_t OEM_revision;
	uint32_t creator_ID;
	uint32_t creator_revision;
} __attribute__((packed));

struct rsdp {
	char signature[8];
	uint8_t checksum;
	char OEMID[6];
	uint8_t revision; 
	uint32_t rsdt_addr;
	uint32_t length;
	uint64_t xsdt_addr;
	uint8_t ext_checksum;
	uint8_t reserved[3];
} __attribute__((packed));

struct rsdt {
	struct acpi_hdr acpi_hdr;
	uint32_t acpi_ptr[];
} __attribute__((packed));

struct xsdt {
	struct acpi_hdr acpi_hdr;
	uint64_t acpi_ptr[];
} __attribute__((packed));

extern struct rsdp *rsdp;
extern struct rsdt *rsdt;
extern struct xsdt *xsdt;

void *acpi_find_sdt(const char *signature);
