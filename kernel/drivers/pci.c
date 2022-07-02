#include <drivers/pci.h>
#include <int/apic.h>
#include <debug.h>
#include <cpu.h>

typeof(pci_device_list) pci_device_list;

union msi_address {
	struct {
		uint32_t reserved0 : 2;
		uint32_t destination_mode : 1;
		uint32_t redirection_hint : 1;
		uint32_t reserved_0 : 8;
		uint32_t destination_id : 8;
		uint32_t base_address : 12;
	};
	uint32_t raw;
} __attribute__((packed));

union msi_data {
	struct {
		uint32_t vector : 8;
		uint32_t delivery_mode : 3;
		uint32_t reserved : 3;
		uint32_t level : 1;
		uint32_t trigger_mode : 1;
		uint32_t reserved0 : 16;
	};
	uint32_t raw;
} __attribute__((packed));

union msi_message_control {
	struct {
		uint32_t enable : 1;
		uint32_t mmc : 3;
		uint32_t mme : 3;
		uint32_t c64 : 1;
		uint32_t pvm : 1;
		uint32_t reserved1 : 7;
	};
	uint32_t raw;
} __attribute__((packed));

union msix_address {
	struct {
		uint32_t bir : 3;
		uint32_t offset : 29;
	};
	uint32_t raw;
} __attribute__((packed));

union msix_vector_control {
	struct {
		uint32_t mask : 1; 
		uint32_t reserved : 31;
	};
	uint32_t raw;
} __attribute__((packed));

union msix_message_control {
	struct {
		uint16_t table : 11;
		uint16_t reserved : 3;
		uint16_t mask : 1;
		uint16_t enable : 1;
	};
	uint16_t raw;
} __attribute__((packed));

struct msix_entry {
	uint32_t addr_low; 
	uint32_t addr_high;
	uint32_t data;
	uint32_t control;
} __attribute__((packed));

static inline void pci_device_write(struct pci_device *device, int size, uint8_t off, uint32_t data) {
	outd(0xcf8, (1 << 31) |
				((uint32_t)device->bus << 16) |
				(((uint32_t)device->dev & 31) << 11) |
				(((uint32_t)device->func & 7) << 8) |
				((uint32_t)off & ~(3)));
	
	switch(size) {
		case 4:
			outd(0xcfc + (off & 3), data);
			break;
		case 2:
			outw(0xcfc + (off & 3), (uint16_t)data);
			break;
		case 1:
			outb(0xcfc + (off & 3), (uint8_t)data);
	}
}

static inline uint32_t pci_device_read(struct pci_device *device, int size, uint8_t off) {
	outd(0xcf8, (1 << 31) |
				((uint32_t)device->bus << 16) |
				(((uint32_t)device->dev & 31) << 11) |
				(((uint32_t)device->func & 7) << 8) |
				((uint32_t)off & ~(3)));
	
	switch(size) {
		case 4:
			return ind(0xcfc + (off & 3));
		case 2:
			return inw(0xcfc + (off & 3));
		case 1:
			return inb(0xcfc + (off & 3));
		default:
			return -1;
	}
}

static void pci_new_device(uint8_t, uint8_t, uint8_t);
static void pci_scan_bus(uint8_t);

static void pci_new_device(uint8_t bus, uint8_t dev, uint8_t func) {
	struct pci_device *device = alloc(sizeof(struct pci_device));

	*device = (struct pci_device) {
		.bus = bus,
		.dev = dev,
		.func = func,
		.class_code = GET_CLASS(bus, dev, func),
		.sub_class = GET_SUB_CLASS(bus, dev, func),
		.prog_if = GET_PROG_IF(bus, dev, func),
		.device_id = GET_DEVICE_ID(bus, dev, func),
		.vendor_id = GET_VENDOR_ID(bus, dev, func),
		.msi_offset = -1,
		.msix_offset = -1
	};

	if((GET_HEADER_TYPE(bus, dev, func) & ~(1 << 7))) { // pci to pci bridge
		pci_scan_bus(GET_SECONDARY_BUS(bus, dev, func));
	}

	VECTOR_PUSH(pci_device_list, device);
}

static void pci_scan_bus(uint8_t bus) {
	for(uint8_t dev = 0; dev < 32; dev++) { 
		if(GET_VENDOR_ID(bus, dev, 0) == 0xffff)
			continue;
	
		pci_new_device(bus, dev, 0);

		if(GET_HEADER_TYPE(bus, dev, 0) & (1 << 7)) {
			for(uint8_t func = 1; func < 8; func++) {
				if(GET_VENDOR_ID(bus, dev, func) != 0xffff) {
					pci_new_device(bus, dev, func);
				}
			}
		}
	}
}

int pci_device_get_bar(struct pci_device *device, struct pci_bar *ret, int num) {
	if(GET_HEADER_TYPE(device->bus, device->dev, device->func) != 0) {
		return -1;
	}

	if(num > 5) {
		return -1;
	}

	size_t bar_off = 0x10 + num * 4;
	size_t bar_low = pci_device_read(device, 4, bar_off);
	size_t is_mmio = !(bar_low & 1);

	pci_device_write(device, 4, bar_off, ~0);
	size_t bar_size_low = pci_device_read(device, 4, bar_off);
	pci_device_write(device, 4, bar_off, bar_low);

	if(((bar_low >> 1) & 0b11) == 0b10) { // is 64 bit
		size_t bar_high = pci_device_read(device, 4, bar_off + 4);

		pci_device_write(device, 4, bar_off + 4, ~0);
		size_t bar_size_high = pci_device_read(device, 4, bar_off + 4);
		pci_device_write(device, 4, bar_off + 4, bar_high); 

		size_t size = ((bar_size_high << 32) | bar_size_low) & ~(is_mmio ? 0b1111 : 0b11);
		size = ~size + 1;

		size_t base = ((bar_high << 32) | bar_low) & ~(is_mmio ? 0b1111 : 0b11);

		*ret = (struct pci_bar) {
			.base = base,
			.size = size
		};

		return 0;
	}

	size_t size = bar_size_low & is_mmio ? 0b1111 : 0b11;
	size = ~size + 1; 

	*ret = (struct pci_bar) {
		.base = bar_low,
		.size = size
	};

	return 0;
}

int pci_device_set_msix(struct pci_device *device, uint8_t vec) {
	union msix_address table_ptr;
	table_ptr.raw = pci_device_read(device, 4, device->msix_offset + 4);
	pci_device_read(device, 4, device->msix_offset + 8);

	size_t bar_index = table_ptr.bir;
	size_t bar_offset = table_ptr.offset << 3;

	struct pci_bar table_bar;
	pci_device_get_bar(device, &table_bar, bar_index);

	size_t bar_base = table_bar.base + bar_offset;

	volatile struct msix_entry *table = (volatile struct msix_entry*)(bar_base + HIGH_VMA);

	union msi_data data = { 0 };
	union msi_address address = { 0 };

	data.delivery_mode = 0;
	data.vector = vec;

	address.base_address = 0xfee;
	address.destination_id = xapic_read(XAPIC_ID_REG_OFF);

	ssize_t table_index = bitmap_alloc(&device->msix_table_bitmap);
	if(table_index == -1) {
		return -1;
	}

	union msix_vector_control vec_cntl = { 0 };
	vec_cntl.mask = 0;

	table[table_index].addr_low = address.raw;
	table[table_index].addr_high = 0;
	table[table_index].data = data.raw;
	table[table_index].control = vec_cntl.raw;

	union msix_message_control message_control;

	message_control.raw = pci_device_read(device, 2, device->msix_offset + 2);
	message_control.enable = 1;
	message_control.mask = 0;
	pci_device_write(device, 2, device->msix_offset + 2, message_control.raw);

	return 0;
}

int pci_device_set_msi(struct pci_device *device, uint8_t vec) {
	if(device->msi_offset == -1) {
		return -1;
	}

	union msi_message_control message_control;

	message_control.raw = pci_device_read(device, 2, device->msi_offset + 2);

	uint32_t reg0 = 0x4;
	uint32_t reg1 = 0x8;

	if(message_control.c64) { // 64 bit support
		reg1 = 0xc;
	} 

	union msi_data data;
	union msi_address address;

	address.raw = pci_device_read(device, 4, device->msi_offset + reg1);
	data.raw = pci_device_read(device, 4, device->msi_offset + reg0);

	data.delivery_mode = 0;
	data.vector = vec;

	address.base_address = 0xfee;
	address.destination_id = xapic_read(XAPIC_ID_REG_OFF);

	pci_device_write(device, device->msi_offset + reg0, 4, address.raw);
	pci_device_write(device, device->msi_offset + reg1, 4, data.raw);

	message_control.enable = 1;
	message_control.mme = 0;

	pci_device_write(device, 2, device->msi_offset + 2, message_control.raw);

	return 0;	
}

void pci_init() {
	for(size_t i = 0; i < 256; i++) {
		pci_scan_bus(i);
	}

	for(size_t i = 0; i < pci_device_list.length; i++) {
		struct pci_device *device = pci_device_list.data[i];

		print("pci: %x:%x:%x: class %x: subclass %x: progif: %x: vendor_id: %x: device_id: %x\n",
				device->bus,
				device->dev,
				device->func, 
				device->class_code, 
				device->sub_class, 
				device->prog_if,
				device->vendor_id,
				device->device_id);

		int off = pci_device_read(device, 2, 0x6) & (1 << 4) ? pci_device_read(device, 1, 0x34) : -1;

		if(off != -1) {
			while(off) {
				uint8_t id = pci_device_read(device, 1, off);

				switch(id) {
					case 0x5:
						device->msi_offset = off;
						break;
					case 0x11:
						device->msix_offset = off;
						device->msix_table_size = pci_device_read(device, 2, off + 2) & 0x7ff;
						bitmap_init(&device->msix_table_bitmap, false, device->msix_table_size);
				}

				off = pci_device_read(device, 1, off + 1);
			}
		}
	}
}

struct pci_device *pci_search_device(uint8_t bus, uint8_t dev, uint8_t func) {
	for(size_t i = 0; i < pci_device_list.length; i++) {
		struct pci_device *device = pci_device_list.data[i];

		if(device->bus == bus && device->dev == dev && device->func == func) {
			return device;
		}
	}

	return NULL;
}
