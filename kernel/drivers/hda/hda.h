#pragma once

#include <fs/vfs.h>
#include <drivers/pci.h>
#include <types.h>

struct hda_registers { 
	uint16_t gcap;
	uint8_t vmin;
	uint8_t vmaj;
	uint16_t outpay;
	uint16_t inpay;
	uint32_t gctl;
	uint16_t wakeen;
	uint16_t wakests;
	uint16_t gsts;
	uint8_t reserved0[6];
	uint16_t outstrmpay;
	uint16_t instrmpay;
	uint8_t reserved1[4];
	uint32_t intctl;
	uint32_t insts;
	uint8_t reserved2[8];
	uint32_t walclk;
	uint32_t old_ssync;
	uint32_t ssync;
	uint8_t reserved3[4];
	uint32_t corblbase;
	uint32_t corbhbase;
	uint16_t corbwp;
	uint16_t corbrp;
	uint8_t corbctl;
	uint8_t corbsts;
	uint8_t corbsize;
	uint8_t reserved4;
	uint32_t rirblbase;
	uint32_t rirbhbase;
	uint16_t rirbwp;
	uint16_t rirbcnt;
	uint8_t rirbctl;
	uint8_t rirbsts;
	uint8_t rirbsize;
	uint8_t reserved5;
	uint32_t icoi;
	uint32_t icii;
	uint16_t icis;
	uint8_t reserved6[6];
	uint32_t dpiblbase;
	uint32_t bpibubase;
	uint8_t reserved7[8]; 
};

struct hda_device {
	struct pci_device *pci_device;
	struct pci_bar bar;

	struct vfs_node *vfs_node;

	int oss_cap;
	int iss_cap;
	int bss_cap;
	int nsdo_cap;
	int addr64cap;
	int corbsize;
	int rirbsize;

	volatile struct hda_registers *regs;
};

void hda_device_init(struct pci_device *pci_device);
