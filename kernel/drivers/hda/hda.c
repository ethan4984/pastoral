#include <drivers/hda/hda.h>
#include <drivers/hpet.h>
#include <int/idt.h>
#include <debug.h>

static VECTOR(struct hda_device*) hda_device_list;

static int initialise_corb(struct hda_device *device) {

}

static int initialise_rirb(struct hda_device *device) {

}

static int get_codec_ctrl_buffer_size(size_t szcap, int *size, int *id) {
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

static void hda_irq_handler(struct registers*, void*) { 

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
	while((regs->gctl & (1 << 0)) == 0);

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
}
