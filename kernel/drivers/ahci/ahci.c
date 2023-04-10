#include <drivers/ahci/ahci.h>
#include <drivers/hpet.h>
#include <drivers/block.h>
#include <mm/pmm.h>
#include <fs/fd.h>
#include <fs/cdev.h>
#include <string.h>
#include <debug.h>

static int hda_minor = 0;

static ssize_t ahci_device_read(struct cdev *, void *, size_t, off_t);
static ssize_t ahci_device_write(struct cdev *, const void *, size_t, off_t);

static struct block_ops ahci_device_ops = {
	.read = ahci_device_read,
	.write = ahci_device_write,
	.ioctl = NULL
};

static const char *ahci_interface_speed(int iss) {
	switch(iss) {
		case 0b01:
			return "Gen 1 (1.5 Gbps)";	
		case 0b10: 
			return "Gen 2 (3 Gbps)";
		case 0b11:
			return "Gen 3 (6 Gbps)";
		default:
			return "Unkown Generation";
	}
}

static int ahci_declare_ownership(struct ahci_controller *controller) {
	if((controller->regs->cap2 & (1 << 0)) == 0) {
		print("ahci: bios/os handoff not supported\n");
		return -1;
	}

	controller->regs->bohc |= (1 << 1);

	while((controller->regs->bohc & (1 << 0)) == 0) asm volatile ("pause");

	msleep(25);

	if(controller->regs->bohc & (1 << 4)) {
		msleep(2 * 1000);
	}

	uint32_t bohc = controller->regs->bohc;
	if(bohc & (1 << 4) || bohc & (1 << 0) || (bohc & (1 << 1)) == 0) {
		print("ahci: bios handoff failed\n");
		return -1;
	}

	print("ahci: bios handoff successful\n");

	return 0;
}

static struct ahci_cmd *ahci_allocate_slot(struct ahci_device *device) {
	int slot_cnt = device->controller->slot_cnt;

	for(size_t i = 0; i < slot_cnt; i++) {
		if((device->port->sact & (1 << i)) == 0 && ((device->port->ci & (1 << i)) == 0)) {
			volatile struct ahci_cmdhdr *cmdhdr = (void*)((device->port->clb | ((uintptr_t)device->port->clbu
							<< 32)) + HIGH_VMA + i * sizeof(struct ahci_cmdhdr));
			volatile struct ahci_cmdtable *cmdtable = (void*)((cmdhdr->ctba | ((uintptr_t)cmdhdr->ctbau << 32))
					+ HIGH_VMA);

			device->command_list[i].device = device;
			device->command_list[i].cmdhdr = cmdhdr; 
			device->command_list[i].cmdtable = cmdtable; 
			device->command_list[i].slot = i;
		
			return &device->command_list[i];
		}
	}

	return NULL;
}

static int ahci_initialise_clb(struct ahci_device *device) {
	uintptr_t cmd_base = pmm_alloc(1, 1);

	device->port->clb = (uint32_t)cmd_base;
	device->port->clbu = (uint32_t)(cmd_base >> 32);

	for(int i = 0; i < AHCI_MAX_CMD; i++) {
		volatile struct ahci_cmdhdr *cmdhdr = (void*)(cmd_base + HIGH_VMA + i * sizeof(struct ahci_cmdhdr));

		uintptr_t data_base = pmm_alloc(1, 1);

		cmdhdr->ctba = (uint32_t)data_base;
		cmdhdr->ctbau = (uint32_t)(data_base >> 32);
	}

	return 0;
}

static int ahci_issue_cmd(struct ahci_cmd *cmd) {
	struct ahci_device *device = cmd->device;

	while((device->port->tfd & PORT_TFD_BSY) || (device->port->tfd & PORT_TFD_DRQ)) asm ("pause");

	device->port->cmd &= ~PORT_CMD_ST;
	while(device->port->cmd & PORT_CMD_CR) asm ("pause"); // good

	device->port->cmd |= PORT_CMD_FRE;
	while(!(device->port->cmd & PORT_CMD_FR)) asm ("pause");
	device->port->cmd |= PORT_CMD_ST;

	device->port->ci = 1 << cmd->slot;

	while(device->port->ci & (1 << cmd->slot)) asm ("pause");

	if(device->port->tfd & PORT_TFD_ERR) {
		print("ahci: command: an error has occured during transfer\n");
	}

	device->port->cmd &= ~PORT_CMD_ST;
	while(device->port->cmd & PORT_CMD_ST) asm ("pause");
	device->port->cmd &= ~PORT_CMD_FRE;

	return 0;
}

static int ahci_initialise_prdt(struct ahci_cmd *cmd, int index) {
	cmd->cmdtable->prdt[index].dba = (uint32_t)cmd->data_base;
	cmd->cmdtable->prdt[index].dbau = (uint32_t)(cmd->data_base >> 32);
	cmd->cmdtable->prdt[index].dbc = cmd->data_length | (cmd->interrupt << 31);

	return 0;
}

static int ahci_issue_identity(struct ahci_device *device, uintptr_t identity) {
	struct ahci_cmd *ahci_cmd = ahci_allocate_slot(device);
	if(ahci_cmd == NULL) {
		print("ahci: unable to allocate command slot\n");
		return -1;
	}

	ahci_cmd->data_base = identity;
	ahci_cmd->data_length = 511;
	ahci_cmd->interrupt = false;

	ahci_cmd->cmdhdr->flags |= sizeof(struct ahci_fis_h2d) / 4;
	ahci_cmd->cmdhdr->prdtl = 1;

	if(ahci_initialise_prdt(ahci_cmd, 0) == -1) {
		return -1;
	}

	struct ahci_fis_h2d *cmdptr = (void*)(&ahci_cmd->cmdtable->cfis);
	memset(cmdptr, 0, sizeof(struct ahci_fis_h2d));

	cmdptr->fis_type = FIS_H2D;
	cmdptr->command = 0xec;
	cmdptr->flags = (1 << 7);

	return ahci_issue_cmd(ahci_cmd);
}

static int ahci_issue_read(struct ahci_device *device, uint64_t block, uint64_t cnt, void *buffer) {
	struct ahci_cmd *ahci_cmd = ahci_allocate_slot(device);
	if(ahci_cmd == NULL) {
		print("ahci: unable to allocate command slot\n");
		return -1;
	}

	ahci_cmd->cmdhdr->flags &= ~(0b11111 | (1 << 6));
	ahci_cmd->cmdhdr->flags |= sizeof(struct ahci_fis_h2d) / 4;
	ahci_cmd->cmdhdr->prdtl = 1;

	ahci_cmd->data_base = (uintptr_t)buffer - HIGH_VMA;
	ahci_cmd->data_length = cnt * AHCI_SECTOR_SIZE - 1;
	ahci_cmd->interrupt = false;

	ahci_initialise_prdt(ahci_cmd, 0);

	struct ahci_fis_h2d *cmdptr = (void*)(&ahci_cmd->cmdtable->cfis);
	memset(cmdptr, 0, sizeof(struct ahci_fis_h2d));

	cmdptr->command = 0x25;

	cmdptr->fis_type = FIS_H2D;
	cmdptr->flags = (1 << 7);
	cmdptr->device = (1 << 6);

	cmdptr->lba0 = (uint8_t)(block >> 0);
	cmdptr->lba1 = (uint8_t)(block >> 8);
	cmdptr->lba2 = (uint8_t)(block >> 16);
	cmdptr->lba3 = (uint8_t)(block >> 24);
	cmdptr->lba4 = (uint8_t)(block >> 32);
	cmdptr->lba5 = (uint8_t)(block >> 40);

	cmdptr->countl = (uint8_t)(cnt >> 0);
	cmdptr->counth = (uint8_t)(cnt >> 8);

	if(ahci_issue_cmd(ahci_cmd) == -1) {
		return -1;
	}

	uint32_t bytes_read = ahci_cmd->cmdhdr->prdbc;

	return DIV_ROUNDUP(bytes_read, AHCI_SECTOR_SIZE);
}

static int ahci_issue_write(struct ahci_device *device, uint64_t block, uint64_t cnt, void *buffer) {
	struct ahci_cmd *ahci_cmd = ahci_allocate_slot(device);
	if(ahci_cmd == NULL) {
		print("ahci: unable to allocate command slot\n");
		return -1;
	}

	ahci_cmd->cmdhdr->flags &= ~(0b11111 | (1 << 6));
	ahci_cmd->cmdhdr->flags |= sizeof(struct ahci_fis_h2d) / 4;
	ahci_cmd->cmdhdr->prdtl = 1;

	ahci_cmd->data_base = (uintptr_t)buffer - HIGH_VMA;
	ahci_cmd->data_length = cnt * AHCI_SECTOR_SIZE - 1;
	ahci_cmd->interrupt = false;

	ahci_initialise_prdt(ahci_cmd, 0);

	struct ahci_fis_h2d *cmdptr = (void*)(&ahci_cmd->cmdtable->cfis);
	memset(cmdptr, 0, sizeof(struct ahci_fis_h2d));

	cmdptr->command = 0x35;

	cmdptr->fis_type = FIS_H2D;
	cmdptr->flags = (1 << 7);
	cmdptr->device = (1 << 6);

	cmdptr->lba0 = (uint8_t)(block >> 0);
	cmdptr->lba1 = (uint8_t)(block >> 8);
	cmdptr->lba2 = (uint8_t)(block >> 16);
	cmdptr->lba3 = (uint8_t)(block >> 24);
	cmdptr->lba4 = (uint8_t)(block >> 32);
	cmdptr->lba5 = (uint8_t)(block >> 40);

	cmdptr->countl = (uint8_t)(cnt >> 0);
	cmdptr->counth = (uint8_t)(cnt >> 8);

	if(ahci_issue_cmd(ahci_cmd) == -1) {
		return -1;
	}

	uint32_t bytes_wrote = ahci_cmd->cmdhdr->prdbc;

	return DIV_ROUNDUP(bytes_wrote, AHCI_SECTOR_SIZE);
}

static ssize_t ahci_device_read(struct cdev *cdev, void *buffer, size_t cnt, off_t offset) {
	struct ahci_device *device = cdev->private_data; 

	size_t lba_start = offset / AHCI_SECTOR_SIZE;
	size_t lba_cnt = DIV_ROUNDUP(cnt, AHCI_SECTOR_SIZE);

	if((cnt % AHCI_SECTOR_SIZE == 0) && (offset % AHCI_SECTOR_SIZE != 0)) {
		lba_cnt++;
	}

	if(((offset % (AHCI_SECTOR_SIZE)) + cnt) > AHCI_SECTOR_SIZE) {
		lba_cnt++;
	}

	if(lba_cnt == 0) {
		return 0;
	}

	void *lba_buffer = (void*)(pmm_alloc(DIV_ROUNDUP(lba_cnt * AHCI_SECTOR_SIZE, PAGE_SIZE), 1) + HIGH_VMA);

	int bytes_read = ahci_issue_read(device, lba_start, lba_cnt, lba_buffer);
	if(bytes_read == -1) {
		return -1;
	}

	pmm_free((uintptr_t)lba_buffer - HIGH_VMA, DIV_ROUNDUP(lba_cnt * AHCI_SECTOR_SIZE, PAGE_SIZE));

	memcpy(buffer, (char*)lba_buffer + (offset % AHCI_SECTOR_SIZE), cnt);

	return bytes_read - ABS(bytes_read, cnt);
}

static ssize_t ahci_device_write(struct cdev *cdev, const void *buffer, size_t cnt, off_t offset) {
	struct ahci_device *device = cdev->private_data; 

	size_t lba_start = offset / AHCI_SECTOR_SIZE;
	size_t lba_cnt = DIV_ROUNDUP(cnt, AHCI_SECTOR_SIZE);

	void *lba_buffer = (void*)(pmm_alloc(DIV_ROUNDUP(lba_cnt * AHCI_SECTOR_SIZE, PAGE_SIZE), 1) + HIGH_VMA);

	if(offset % AHCI_SECTOR_SIZE != 0) ahci_device_read(cdev, lba_buffer, AHCI_SECTOR_SIZE, offset);
	if(cnt % AHCI_SECTOR_SIZE != 0) ahci_device_read(cdev, lba_buffer, AHCI_SECTOR_SIZE, offset + lba_cnt - 1);

	memcpy(lba_buffer + (offset % AHCI_SECTOR_SIZE), buffer, cnt);

	int bytes_read = ahci_issue_write(device, lba_start, lba_cnt, lba_buffer);
	if(bytes_read == -1) {
		return -1;
	}

	pmm_free((uintptr_t)lba_buffer - HIGH_VMA, DIV_ROUNDUP(lba_cnt * AHCI_SECTOR_SIZE, PAGE_SIZE));

	return bytes_read - ABS(bytes_read, cnt);
}

static int ahci_extract_serial(struct ahci_device *device, void *identity) {
	memcpy(device->serial_number, identity + 20, 20);
	swap_endianess(device->serial_number, 20);
	return 0;
}

static int ahci_extract_firmware(struct ahci_device *device, void *identity) {
	memcpy(device->firmware_revision, identity + 46, 8);
	swap_endianess(device->firmware_revision, 8);
	return 0;
}

static int ahci_extract_model(struct ahci_device *device, void *identity) {
	memcpy(device->model_number, identity + 54, 40);
	swap_endianess(device->model_number, 40);
	return 0;
}

static int ahci_port_initialise(struct ahci_controller *controller, int index) {
	volatile struct ahci_port *port = (void*)(&controller->regs->ports[index]);

	switch(port->sig) {
		case SATA_ATA:
			print("ahci: sata drive found on port %d\n", index);
			break;
		case SATA_ATAPI:
			print("ahci: enclosure mangement bridge found on port %d\n", index);
			return -1;
		case SATA_PM:
			print("port multipler found on port %d\n", index);
			return -1;
		default:
			return -1;
	}

	struct ahci_device *device = alloc(sizeof(struct ahci_device));

	device->controller = controller; 
	device->port = port;

	if(ahci_initialise_clb(device) == -1) {
		print("ahci: error initailising device ports command list\n");
		return -1;
	}

	uintptr_t fis_base = pmm_alloc(1, 1);

	port->fb = (uint32_t)fis_base;
	port->fbu = (uint32_t)(fis_base >> 32);

	port->cmd |= (1 << 0) | (1 << 4);

	uint16_t *identity = (void*)(pmm_alloc(1, 1) + HIGH_VMA);

	if(ahci_issue_identity(device, (uintptr_t)identity - HIGH_VMA) == -1) { 
		print("ahci: unable to issue identity command\n");
		return -1;
	}

	if(ahci_extract_serial(device, identity) == -1) return -1;
	if(ahci_extract_firmware(device, identity) == -1) return -1;
	if(ahci_extract_model(device, identity) == -1) return -1;

	print("ahci: device: serial number: %s\n", device->serial_number);
	print("ahci: device: firmware revision: %s\n", device->firmware_revision);
	print("ahci: device: model number: %s\n", device->model_number);

	struct cdev *hda_cdev = alloc(sizeof(struct cdev));

	hda_cdev->bops = &ahci_device_ops;
	hda_cdev->private_data = device;
	hda_cdev->rdev = makedev(HDA_MAJOR, hda_minor);

	cdev_register(hda_cdev);

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);

	stat->st_blksize = AHCI_SECTOR_SIZE;
	stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stat->st_rdev = makedev(HDA_MAJOR, hda_minor);

	char *device_path = alloc(MAX_PATH_LENGTH);
	sprint(device_path, "/dev/hd%c", 'a' + hda_minor);

	vfs_create_node_deep(NULL, NULL, NULL, stat, device_path);

	struct blkdev *blkdev = alloc(sizeof(struct blkdev));

	blkdev->disk = hda_cdev;
	blkdev->sector_size = AHCI_SECTOR_SIZE;
	blkdev->sector_cnt = *(uint64_t*)(identity + 200);
	blkdev->device_name = "ahci";
	blkdev->device_prefix = device_path;
	blkdev->serial_number = device->serial_number;
	blkdev->firmware_revision = device->firmware_revision;
	blkdev->model_number = device->model_number;
	blkdev->partition_major = HDA_PARTITION_MAJOR;
	blkdev->partition_minor = 0;

	register_blkdev(blkdev);

	print("ahci: registered device %x:%x at %s\n", HDA_MAJOR, hda_minor++, device_path);

	return 0;
}

int	ahci_controller_initialise(struct pci_device *pci_device) {
	switch(pci_device->prog_if) {
		case 0:
			print("ahci: vendor specific interface\n");
			return -1;
		case 1: 
			print("ahci: ahci 1.0 compatiable device\n");
			break;
		case 2: 
			print("ahci: Pdetceted a serial storage bus\n");
			return -1;
		default:
			print("ahci: detected an unknwon device type\n");
			return -1;
	}

	PCI_BECOME_MASTER(pci_device);
	PCI_ENABLE_MMIO(pci_device);

	struct pci_bar pci_bar;

	int ret = pci_device_get_bar(pci_device, &pci_bar, 5);
	if(ret == -1) {
		print("ahci: unable to get bar5\n");
		return -1;
	}

	struct ahci_controller *controller = alloc(sizeof(struct ahci_controller));

	controller->regs = (void*)(pci_bar.base + HIGH_VMA);
	controller->version_maj = (controller->regs->vs >> 16) & 0xffff;
	controller->version_min = controller->regs->vs & 0xffff;
	controller->generation = ahci_interface_speed((controller->regs->cap >> 20) & 0b1111);

	print("ahci: controller version %x:%x [%s]\n", controller->version_maj, controller->version_min, controller->generation);

	if((controller->regs->cap & (1ull << 31)) == 0) {
		print("ahci: controller not capable of 64 bit addressing\n");
		return -1;
	}

	ahci_declare_ownership(controller);

	controller->port_cnt = controller->regs->cap & 0b11111;
	controller->slot_cnt = (controller->regs->cap >> 8) & 0b11111;

	for(int i = 0; i < controller->port_cnt; i++) {
		if(controller->regs->pi & (1 << i)) {
			ahci_port_initialise(controller, i);
		}
	}

	return 0;
}
