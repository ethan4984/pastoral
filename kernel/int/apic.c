#include <int/apic.h>
#include <debug.h>
#include <mm/vmm.h>
#include <cpu.h>

typeof(madt_ent0_list) madt_ent0_list;
typeof(madt_ent1_list) madt_ent1_list;
typeof(madt_ent2_list) madt_ent2_list;
typeof(madt_ent4_list) madt_ent4_list;
typeof(madt_ent5_list) madt_ent5_list;
typeof(ioapic_list) ioapic_list;

struct madt_hdr *madt_hdr;

uint32_t ioapic_read(struct ioapic *ioapic, uint8_t reg) {
	*ioapic->ioapic_base = reg;
	return *(ioapic->ioapic_base + 4);
}

void ioapic_write(struct ioapic *ioapic, uint32_t reg, uint32_t data) {
	*ioapic->ioapic_base = reg;
	*(ioapic->ioapic_base + 4) = data;
}

void xapic_write(uint32_t reg, uint32_t data) {
	*(volatile uint32_t*)((rdmsr(MSR_LAPIC_BASE) & 0xfffff000) + HIGH_VMA + reg) = data;
}

uint32_t xapic_read(uint32_t reg) {
	return *(volatile uint32_t*)((rdmsr(MSR_LAPIC_BASE) & 0xfffff000) + HIGH_VMA + reg);
}

void ioapic_write_redirection_table(struct ioapic *ioapic, uint32_t redirection_entry, uint64_t data) {
	ioapic_write(ioapic, redirection_entry + 0x10, data & 0xffffffff);
	ioapic_write(ioapic, redirection_entry + 0x10 + 1, data >> 32 & 0xffffffff);
}

uint64_t ioapic_read_redirection_table(struct ioapic *ioapic, uint8_t redirection_entry) {
	uint64_t data = ioapic_read(ioapic, redirection_entry + 0x10) | ((uint64_t)ioapic_read(ioapic, redirection_entry + 0x10 + 1) << 32);
	return data;
}

void apic_init() {
	madt_hdr = acpi_find_sdt("APIC");

	if(madt_hdr == NULL) {
		print("apic: unable to locate APIC SDT\n");
		return;
	}

	for(size_t i = 0; i < madt_hdr->acpi_hdr.length - sizeof(struct madt_hdr); i++) {
		uint8_t entry_type = madt_hdr->entries[i++];
		uint8_t entry_size = madt_hdr->entries[i++];

		switch(entry_type) {
			case 0:
				VECTOR_PUSH(madt_ent0_list, *(struct madt_ent0*)(&madt_hdr->entries[i]));
				break;
			case 1:
				VECTOR_PUSH(madt_ent1_list, *(struct madt_ent1*)(&madt_hdr->entries[i]));
				break;
			case 2:
				VECTOR_PUSH(madt_ent2_list, *(struct madt_ent2*)(&madt_hdr->entries[i]));
				break;
			case 4:
				VECTOR_PUSH(madt_ent4_list, *(struct madt_ent4*)(&madt_hdr->entries[i]));
				break;
			case 5:
				VECTOR_PUSH(madt_ent5_list, *(struct madt_ent5*)(&madt_hdr->entries[i]));
		}
		i += entry_size - 3;
	}

	print("apic: core count %d\n", madt_ent0_list.element_cnt);

	for(size_t i = 0; i < madt_ent1_list.element_cnt; i++) {
		struct madt_ent1 *madt1  = &madt_ent1_list.elements[i];

		struct ioapic ioapic = {
			.ioapic_base = (volatile uint32_t*)((uintptr_t)madt1->ioapic_addr + HIGH_VMA),
			.madt1 = madt1
		};

		kernel_mappings.map_page(&kernel_mappings, (uintptr_t)ioapic.ioapic_base, ((uintptr_t)ioapic.ioapic_base - HIGH_VMA), VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_G | VMM_FLAGS_PS);

		ioapic.ioapic_id = ioapic_read(&ioapic, 0);
		ioapic.ioapic_version = ioapic_read(&ioapic, 1) & 0xff;
		ioapic.maximum_redirection_entry = ioapic_read(&ioapic, 1) >> 16 & 0xff;
		ioapic.ioapic_arbitration_id = ioapic_read(&ioapic, 2) >> 23 & 0xf;

		print("ioapic: id %x\n", ioapic.ioapic_id);
		print("ioapic: version %x\n", ioapic.ioapic_version);
		print("ioapic: maximum redirection entry %x\n", ioapic.maximum_redirection_entry);
		print("ioapic: arbitration id %x\n", ioapic.ioapic_arbitration_id);
		print("ioapic: base %x\n", (uintptr_t)ioapic.ioapic_base);

		VECTOR_PUSH(ioapic_list, ioapic);
	}

	outb(0x20, 0x11);
	outb(0xa0, 0x11);
	outb(0x21, 0x20);
	outb(0xa1, 0x28);
	outb(0x21, 0x4);
	outb(0xa1, 0x2);
	outb(0x21, 0x1);
	outb(0xa1, 0x1);
	outb(0x21, 0x0);
	outb(0xa1, 0x0);

	outb(0xa1, 0xff);
	outb(0x21, 0xff);

	for(size_t i = 0; i < madt_ent2_list.element_cnt; i++) {
		struct madt_ent2 *madt2 = &madt_ent2_list.elements[i];

		uint64_t entry = (madt2->irq_src + 32) | (1 << 16);

		if(madt2->flags & (1 << 1)) { // egde triggered
			entry |= IOAPIC_INTPOL;
		} else if(madt2->flags & (1 << 3)) { // level triggered
			entry |= IOAPIC_TRIGGER_MODE;
		}

		print("ioapic: mapping gsi %x to legacy irq %x\n", madt2->gsi, madt2->irq_src);

		for(size_t i = 0; i < ioapic_list.element_cnt; i++) {
			struct ioapic *ioapic = &ioapic_list.elements[i];
			if(madt2->gsi <= ioapic->maximum_redirection_entry && madt2->gsi >= ioapic->madt1->gsi_base) {
				ioapic_write_redirection_table(ioapic, (madt2->gsi - ioapic->madt1->gsi_base) * 2, entry);
			}
		}
	}

	kernel_mappings.map_page(&kernel_mappings, (rdmsr(MSR_LAPIC_BASE) & 0xfffff000) + HIGH_VMA, (rdmsr(MSR_LAPIC_BASE) & 0xfffff000), VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_G | VMM_FLAGS_PS);

	xapic_write(XAPIC_TPR_OFF, 0);
	xapic_write(XAPIC_SINT_OFF, xapic_read(XAPIC_SINT_OFF) | 0x1ff);

	asm volatile ("mov %0, %%cr8" :: "r"(0ull));
}
