#pragma once

#include <vector.h>
#include <bitmap.h>
#include <stdint.h>
#include <stddef.h>
#include <cpu.h>

#define GET_CLASS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_read(BUS, DEVICE, FUNC, 0x8) >> 24)

#define GET_SUB_CLASS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_read(BUS, DEVICE, FUNC, 0x8) >> 16)

#define GET_PROG_IF(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_read(BUS, DEVICE, FUNC, 0x8) >> 8)

#define GET_DEVICE_ID(BUS, DEVICE, FUNC) \
	(uint16_t)(pci_read(BUS, DEVICE, FUNC, 0) >> 16)

#define GET_VENDOR_ID(BUS, DEVICE, FUNC) \
	(uint16_t)(pci_read(BUS, DEVICE, FUNC, 0))

#define GET_HEADER_TYPE(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_read(BUS, DEVICE, FUNC, 0xc) >> 16)

#define GET_SECONDARY_BUS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_read(BUS, DEVICE, FUNC, 0x18) >> 8)

struct pci_bar {
	size_t base;
	size_t size;
};

struct pci_device {
	uint8_t bus;
	uint8_t dev;
	uint8_t func;
	uint8_t class_code;
	uint8_t sub_class;
	uint8_t prog_if;
	uint16_t device_id;
	uint16_t vendor_id;

	int msi_offset;
	int msix_offset;
	int msix_table_size;

	struct bitmap msix_table_bitmap;
};


static inline uint32_t pci_read(uint8_t bus, uint8_t device_code, uint8_t func, uint8_t off) {
	outd(0xcf8, (1 << 31) | // enable
				((uint32_t)bus << 16) | // bus number
				(((uint32_t)device_code & 31) << 11) | // device number
				(((uint32_t)func & 7) << 8) | // function number
				((uint32_t)off & ~(3)));
	return ind(0xcfc);
}

static inline void pci_write(uint32_t data, uint8_t bus, uint8_t device_code, uint8_t func, uint8_t off) {
	outd(0xcf8, (1 << 31) | // enable
				((uint32_t)bus << 16) | // bus number
				(((uint32_t)device_code & 31) << 11) | // device number
				(((uint32_t)func & 7) << 8) | // function number
				((uint32_t)off & ~(3)));
	outd(0xcfc, data);
};

extern VECTOR(struct pci_device*) pci_device_list;

void pci_init();
struct pci_device *pci_search_device(uint8_t bus, uint8_t dev, uint8_t func);
