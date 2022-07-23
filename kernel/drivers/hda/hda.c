#include <drivers/hda/hda.h>
#include <drivers/hpet.h>
#include <mm/pmm.h>
#include <int/idt.h>
#include <debug.h>
#include <string.h>

static VECTOR(struct hda_device*) hda_device_list;

#define HDA_REG_WRITEH(DEVICE, REG, VALUE) \
	if(VALUE) { \
		return -1; \
	} \
	if(DEVICE->addr64cap) { \
		REG = VALUE; \
	}

int initialise_corb(struct hda_device *device) {
	uint64_t corb_base = pmm_alloc(DIV_ROUNDUP(device->corbsize, PAGE_SIZE), 1);

	device->corbbase = (void*)(corb_base + HIGH_VMA);

	// dma must be disabled to avoid transfer corruption
	if(device->regs->corbctl & (1 << 1)) {
		device->regs->corbctl &= ~(1 << 1);
	}

	device->regs->corblbase = corb_base & 0xffffffff;	
	HDA_REG_WRITEH(device, device->regs->corbhbase, (corb_base >> 32) & 0xffffffff);

	print("hda: corb: initialised with %d entries\n", device->corbsize);

	// reset corb read pointer
	device->regs->corbrp |= (1 << 15);
	while((device->regs->corbrp & (1 << 15)) == 0) asm ("pause");

	device->regs->corbrp &= ~(1 << 15);
	while(device->regs->corbrp & (1 << 15)) asm ("pause");

	// initialise write potiner and start the dma engine
	device->regs->corbwp &= ~(0xff);
	device->regs->corbctl |= (1 << 1);

	print("hda: corb: started\n");

	return 0;
}

int initialise_rirb(struct hda_device *device) {
	uint64_t rirb_base = pmm_alloc(DIV_ROUNDUP(device->rirbsize, PAGE_SIZE), 1);

	device->rirbbase = (void*)(rirb_base + HIGH_VMA);

	// dma must be disabled to avoid transfer corruption
	if(device->regs->rirbctl & (1 << 1)) {
		device->regs->rirbctl &= ~(1 << 1);
	}

	device->regs->rirblbase = rirb_base & 0xffffffff;
	HDA_REG_WRITEH(device, device->regs->rirbhbase, (rirb_base >> 32) & 0xffffffff);

	print("hda: rirb: initialised with %d entries\n", device->rirbsize);

	// write pointer reset
	device->regs->rirbwp |= (1 << 15);
	
	// generate an irq after one rirb response
	device->regs->rirbcnt = 1;

	// enable interrupts and dma
	device->regs->rirbctl |= (1 << 0) | (1 << 1);

	print("hda: rirb: started\n");

	return 0;
}

int get_codec_ctrl_buffer_size(size_t szcap, int *size, int *id) {
	if(szcap & (1 << 2)) {
		*size = 256; *id = 0b00; 
		return 0;	
	} else if(szcap & (1 << 1)) {
		*size = 16; *id = 0b01;
		return 0;
	} else if(szcap & (1 << 0)) {
		*size = 2; *id = 0b10;
		return 0;
	}

	return -1;
}

int send_command(struct hda_device *device, int codec, int nid, int cmd) {
	uint32_t verb = ((codec & 0xf) << 28) | ((nid & 0xff) << 20) | (cmd & 0xfffff);

	int index = (device->regs->corbwp + 1) % device->corbsize;
	if(index == device->regs->corbrp || device->regs->corbctl & (1 << 1)) {
		return -1;
	}

	device->corbbase[index] = verb;
	device->regs->corbwp = index;

	/*int ret = event_wait(&device->command_event, EVENT_HDA_CMD);
	if(ret == -1) {
		return -1;
	}*/

	return device->codec[codec].codec_response;
}

static int parse_codec(struct hda_device*, int) {
	return 0;
}

static void enumerate_codec(struct hda_device *device) {
	for(size_t i = 0; i < 15; i++) {
		if(device->regs->statests & (1 << i)) {
			int ret = parse_codec(device, i);
			if(ret == -1) { 
				print("hda: codec: error parsing codec: index %d\n", i);
			}

			// acknowledge status change by clearing its bit (clearing is done by setting)
			device->regs->statests |= (1 << i);
		}
	}
}

static void hda_irq_handler(struct registers*, void *_device) {
	struct hda_device *device = _device;

	if(device->regs->rirbsts & (1 << 2)) {

	}

/*	if(device->regs->rirbsts & (1 << 0)) {
		event_fire(&device->command_event_trigger);	
	}*/
}

void hda_device_init(struct pci_device *pci_device) {
	PCI_BECOME_MASTER(pci_device);
	PCI_ENABLE_MMIO(pci_device);

	struct pci_bar pci_bar;

	int ret = pci_device_get_bar(pci_device, &pci_bar, 0);
	if(ret == -1) {
		print("hda: unable to get bar0\n");
		return;
	}

	struct hda_registers *regs = (void*)(pci_bar.base + HIGH_VMA);

	// reset controller	
	regs->gctl = regs->gctl & ~(1 << 0);
	while((regs->gctl & (1 << 0)) != 0);

	// enable controller
	regs->gctl = regs->gctl | 1; 
	while((regs->gctl & (1 << 0)) == 0) asm ("pause");

	// wait 521 us (25 frames) to ensure all codecs made successful status change requests	
	usleep(521);

	print("hda: version %d:%d\n", regs->vmaj, regs->vmin);

	int oss_cap = (regs->gcap >> 12) & 0b1111;
	int iss_cap = (regs->gcap >> 8) & 0b1111;
	int bss_cap = (regs->gcap >> 3) & 0b11111;
	int nsdo_cap = (regs->gcap >> 1) & 0b11;
	int addr64cap = regs->gcap & 0b1;

	int corbszcap = regs->corbsize >> 4 & 0b1111;
	int corbsize;
	int corbsizeid;

	ret = get_codec_ctrl_buffer_size(corbszcap, &corbsize, &corbsizeid);
	if(ret == -1) {
		print("hda: invalid corbsizecap\n");
		return;
	}

	int rirbszcap = regs->corbsize >> 4 & 0b1111;
	int rirbsize;
	int rirbsizeid;

	ret = get_codec_ctrl_buffer_size(rirbszcap, &rirbsize, &rirbsizeid);
	if(ret == -1) {
		print("hda: invalid corbsizecap\n");
		return;
	}

	struct hda_device *device = alloc(sizeof(struct hda_device));

	*device = (struct hda_device) {
		.pci_device = pci_device,
		.bar = pci_bar,
		.oss_cap = oss_cap,
		.iss_cap = iss_cap,
		.bss_cap = bss_cap,
		.nsdo_cap = nsdo_cap,
		.addr64cap = addr64cap,
		.corbsize = corbsize,
		.rirbsize = rirbsize,
		.regs = regs
	};

	VECTOR_PUSH(hda_device_list, device);

	int irq = idt_alloc_vector(hda_irq_handler, device);

	if(pci_device->msix_capable) {
		print("hda: msix: initialised vector %d\n", irq);
		pci_device_set_msix(pci_device, irq);
	} else if(pci_device->msi_capable) {
		print("hda: msi: initialised vector %d\n", irq);
		pci_device_set_msi(pci_device, irq);
	} else {
		print("hda: device is neither capable of msi or msix\n");
		return;
	}

	ret = initialise_corb(device);
	if(ret == -1) {
		print("hda: corb initialisation error\n");
		return;
	}

	ret = initialise_rirb(device);
	if(ret == -1) {
		print("hda: rirb initialisation error\n");
		return;
	}

	// enable global device and controller interrupts
	regs->intctl |= (1 << 30) | (1 << 31);

	enumerate_codec(device);
}
