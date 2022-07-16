#pragma once

#include <vector.h>
#include <bitmap.h>
#include <stdint.h>
#include <stddef.h>
#include <cpu.h>

#define GET_CLASS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0x8) >> 24)

#define GET_SUB_CLASS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0x8) >> 16)

#define GET_PROG_IF(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0x8) >> 8)

#define GET_DEVICE_ID(BUS, DEVICE, FUNC) \
	(uint16_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0) >> 16)

#define GET_VENDOR_ID(BUS, DEVICE, FUNC) \
	(uint16_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0))

#define GET_HEADER_TYPE(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0xc) >> 16)

#define GET_SECONDARY_BUS(BUS, DEVICE, FUNC) \
	(uint8_t)(pci_raw_read(4, BUS, DEVICE, FUNC, 0x18) >> 8)

#define PCI_BECOME_MASTER(DEVICE) \
	pci_device_write(DEVICE, 2, 4, pci_device_read(DEVICE, 2, 4) | (1 << 2));

#define PCI_ENABLE_MMIO(DEVICE) \
	pci_device_write(DEVICE, 2, 4, pci_device_read(DEVICE, 2, 4) | (1 << 1));

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

	bool msi_capable;
	bool msix_capable; 

	struct bitmap msix_table_bitmap;
};

extern VECTOR(struct pci_device*) pci_device_list;

void pci_init();
void pci_device_write(struct pci_device *device, int size, uint8_t off, uint32_t data);
void pci_raw_write(int size, uint32_t data, uint8_t bus, uint8_t device_code, uint8_t func, uint8_t off);

uint32_t pci_device_read(struct pci_device *device, int size, uint8_t off);
uint32_t pci_raw_read(int size, uint8_t bus, uint8_t device_code, uint8_t func, uint8_t off);

struct pci_device *pci_search_device(uint8_t bus, uint8_t dev, uint8_t func);

int pci_device_get_bar(struct pci_device *device, struct pci_bar *ret, int num);
int pci_device_set_msix(struct pci_device *device, uint8_t vec);
int pci_device_set_msi(struct pci_device *device, uint8_t vec);
