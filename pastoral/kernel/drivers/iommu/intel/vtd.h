#pragma once

#include <drivers/pci.h>
#include <acpi/rsdp.h>
#include <bitmap.h>
#include <vector.h>

#define DMAR_DRHD_TYPE 0
#define DMAR_RMRR_TYPE 1
#define DMAR_ATSR_TYPE 2
#define DMAR_RHSA_TYPE 3
#define DMAR_ANDD_TYPE 4

#define DMAR_SCOPE_PCI_ENDPOINT 0x1
#define DMAR_SCOPE_PCI_SUB_HIERARCHY 0x2
#define DMAR_SCOPE_IOAPIC 0x3
#define DMAR_MSI_CAPABLE_HPET 0x4
#define DMAR_ACPI_NAMESPACE_DEVICE 0x5

struct dmar_scope {
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
	struct dmar_scope scopes[];
} __attribute__((packed));

struct dmar {
	struct acpi_hdr acpi_hdr;
	uint8_t host_address_width;
	uint8_t flags;
	uint8_t reserved[10];
	struct dmar_unit units[];
} __attribute__((packed));

struct rtt {
	uint64_t present : 1;
	uint64_t reserved0 : 10;
	uint64_t ctp : 52;
	uint64_t reserved1 : 64;
} __attribute__((packed));

struct context_entry {
	uint64_t present : 1;
	uint64_t fpd : 1;
	uint64_t translation_type : 2;
	uint64_t reserved0 : 8;
	uint64_t second_level_page_translation_ptr : 52;
	uint64_t address_width : 3;
	uint64_t ign : 4;
	uint64_t reserved1 : 1;
	uint64_t domain_id : 16;
	uint64_t reserved2 : 40;
} __attribute__((packed));

struct device_scope {
	struct pci_device *device;
	struct dmar_scope *scope;
};

struct remapping_module {
	struct dmar_unit *unit;
	VECTOR(struct device_scope*) devices;

	int domain_cnt;
	int address_width;

	struct bitmap domain_bitmap;
};

int vtd_init();
