#pragma once

#include <drivers/pci.h>
#include <types.h>

#define HDA_MAJOR 30
#define HDA_PARTITION_MAJOR 31

#define SATA_ATA 0x101
#define SATA_ATAPI 0xeb140101
#define SATA_SEMB 0xc33C0101
#define SATA_PM 0x96690101

#define FIS_H2D 0x27
#define FIS_D2H 0x34

#define PORT_CMD_ST (1 << 0)
#define PORT_CMD_FRE (1 << 4)
#define PORT_CMD_FR (1 << 14)
#define PORT_CMD_CR (1 << 15)

#define PORT_TFD_ERR (1 << 0)
#define PORT_TFD_BSY (1 << 7)

#define AHCI_MAX_CMD 32
#define AHCI_SECTOR_SIZE 0x200

struct ahci_port {
	uint32_t clb;
	uint32_t clbu;
	uint32_t fb;
	uint32_t fbu;
	uint32_t is;
	uint32_t ie;
	uint32_t cmd;
	uint32_t reserved0;
	uint32_t tfd;
	uint32_t sig;
	uint32_t ssts;
	uint32_t sstl;
	uint32_t serr;
	uint32_t sact;
	uint32_t ci;
	uint32_t sntf;
	uint32_t fbs;
	uint32_t devslp;
	uint32_t reserved1[11];
	uint32_t vs[10];
};

struct ahci_registers {
	uint32_t cap;
	uint32_t ghc;
	uint32_t is; 
	uint32_t pi;
	uint32_t vs;
	uint32_t ccc_ctl;
	uint32_t ccc_ports;
	uint32_t em_lock;
	uint32_t em_ctl;
	uint32_t cap2;
	uint32_t bohc;
	uint32_t reserved[29];
	uint32_t vendor[24];
	volatile struct ahci_port ports[];
};

struct ahci_fis_d2h {
	uint8_t fis_type;
	uint8_t flags;
	uint8_t status;
	uint8_t error;
	uint8_t lba0;
	uint8_t lba1;
	uint8_t lba2;
	uint8_t device;
	uint8_t lba3;
	uint8_t lba4;
	uint8_t lba5;
	uint8_t reserved2;
	uint8_t countl;
	uint8_t counth;
	uint8_t reserved3;
	uint8_t reserved4;
};

struct ahci_fis_h2d {
	uint8_t fis_type;
	uint8_t flags;
	uint8_t command;
	uint8_t featurel;
	uint8_t lba0;
	uint8_t lba1;
	uint8_t lba2;
	uint8_t device;
	uint8_t lba3;
	uint8_t lba4;
	uint8_t lba5;
	uint8_t featureh;
	uint8_t countl;
	uint8_t counth;
	uint8_t icc;
	uint8_t control;
	uint32_t reserved;
};

struct ahci_hda_prdt {
	uint32_t dba;
	uint32_t dbau;
	uint32_t reserved;
	uint32_t dbc;
};

struct ahci_cmdtable {
	uint8_t cfis[64];
	uint8_t acmd[16];
	uint8_t reserved[48];
	struct ahci_hda_prdt prdt[];
};

struct ahci_cmdhdr {
	uint16_t flags;
	uint16_t prdtl;
	uint32_t prdbc;
	uint32_t ctba;
	uint32_t ctbau;
	uint32_t reserved[4];
};

struct ahci_cmd {
	volatile struct ahci_cmdhdr *cmdhdr;
	volatile struct ahci_cmdtable *cmdtable;
	struct ahci_device *device;

	uintptr_t data_base;
	size_t data_length;
	bool interrupt;

	int slot;
};

struct ahci_controller {
	struct pci_device *pci_device;
	struct pci_bar bar;

	const char *generation;

	int version_maj;
	int version_min;
	int port_cnt;
	int slot_cnt;

	struct ahci_registers *regs;

	VECTOR(struct ahci_device*) device_list; 
};

struct ahci_device {
	struct ahci_controller *controller;

	volatile struct ahci_port *port;

	char serial_number[21];
	char firmware_revision[9];
	char model_number[41];

	struct ahci_cmd command_list[AHCI_MAX_CMD];
};

int ahci_controller_initialise(struct pci_device *pci_device);
