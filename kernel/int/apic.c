#include <int/apic.h>
#include <debug.h>
#include <mm/vmm.h>
#include <drivers/hpet.h>
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

void apic_timer_init(uint32_t ms) {
	xapic_write(XAPIC_TIMER_DIVIDE_CONF_OFF, 0x3); // divide by 16
	xapic_write(XAPIC_TIMER_INITAL_COUNT_OFF, ~0);

	msleep(ms);

	uint32_t ticks = ~0 - xapic_read(XAPIC_TIMER_CURRENT_COUNT_OFF);

	xapic_write(XAPIC_TIMER_LVT_OFF, 0x20 | (1 << 17));
	xapic_write(XAPIC_TIMER_DIVIDE_CONF_OFF, 0x3); // divide by 16
	xapic_write(XAPIC_TIMER_INITAL_COUNT_OFF, ticks);
}

int ioapic_set_irq_redirection(uint32_t lapic_id, uint8_t vector, uint8_t irq, bool mask) {
	uint64_t flags = 0;

	for(size_t i = 0; i < madt_ent2_list.length; i++) {
		struct madt_ent2 *madt2 = &madt_ent2_list.data[i];

		if(madt2->irq_src != irq) {
			continue;
		}

		if(madt2->flags & (1 << 1)) { // edge triggered
			flags |= IOAPIC_INTPOL;
		} else if(madt2->flags & (1 << 3)) { // level triggered
			flags |= IOAPIC_TRIGGER_MODE;
		}

		irq = madt2->gsi;
		
		break;
	}

	if(mask) {
		flags |= IOAPIC_INT_MASK;
	}

	uint64_t entry = vector | flags | ((uint64_t)lapic_id << 56);

	for(size_t i = 0; i < ioapic_list.length; i++) { 
		struct ioapic *ioapic = &ioapic_list.data[i]; 

		if(irq <= ioapic->maximum_redirection_entry && irq >= ioapic->madt1->gsi_base) {
			ioapic_write_redirection_table(ioapic, (irq - ioapic->madt1->gsi_base) * 2, entry);
			return 0;
		}
	}

	return -1;
}

// redirect if necessary and mask all ISA IRQ's
void ioapic_redirect_all_isa_irqs(void)
{
	/*
	Algorithm taken from apoptOS:
		https://github.com/Tix3Dev/apoptOS/blob/ca04813f3f1d8fb8f1c4292dd95409a86165b80e/src/kernel/hardware/apic/apic.c#L251-L286
	Under following license:
		This file is part of a modern x86_64 UNIX-like microkernel-based
		operating system which is called apoptOS
		Everything is openly developed on GitHub: https://github.com/Tix3Dev/apoptOS
		Copyright (C) 2022  Yves Vollmeier <https://github.com/Tix3Dev>
		This program is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.
		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU General Public License for more details.
		You should have received a copy of the GNU General Public License
		along with this program.  If not, see <https://www.gnu.org/licenses/>.

	// first redirect all ISO's
	for (size_t isos_i = 0; isos_i < madt_isos_i; isos_i++)
	{
	    ioapic_set_gsi_redirect(lapic_get_id(), madt_isos[isos_i]->irq_source + 32,
		    madt_isos[isos_i]->gsi, madt_isos[isos_i]->flags, true);
	}

	// and then redirect the rest of ISA IRQ's, skipping the already set ISO's
	uint8_t vector = 0;
	for (uint8_t gsi = 0; gsi < 16; gsi++, vector++)
	{
	    // check if current GSI is already set, if yes decrease vector
	    // so next iteration it's still the same
	    if (ioapic_get_vector_from_gsi(gsi) >= 32)
	    {
		vector--;
		continue;
	    }

    retry:
	    // check if current vector is from a ISO, if yes retry
	    for (size_t isos_i = 0; isos_i < madt_isos_i; isos_i++)
	    {
		if (madt_isos[isos_i]->irq_source == vector)
		{
		    vector++;
		    goto retry;
		}
	    }

	    ioapic_set_gsi_redirect(lapic_get_id(), vector + 32, gsi, 0, true);
	}	

	*/

	print("apic: fix me - ISA IRQ redirection!\n");
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

	print("apic: core count %d\n", madt_ent0_list.length);

	for(size_t i = 0; i < madt_ent1_list.length; i++) {
		struct madt_ent1 *madt1  = &madt_ent1_list.data[i];

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

	// shouldn't be used anymore - undefined behavior might result
	// for(size_t i = 0; i < 16; i++) {
	// 	ioapic_set_irq_redirection(xapic_read(XAPIC_ID_REG_OFF), i + 32, i, true);
	// }
	
	ioapic_redirect_all_isa_irqs();

	kernel_mappings.map_page(&kernel_mappings, (rdmsr(MSR_LAPIC_BASE) & 0xfffff000) + HIGH_VMA, (rdmsr(MSR_LAPIC_BASE) & 0xfffff000), VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_G | VMM_FLAGS_PS);

	xapic_write(XAPIC_TPR_OFF, 0);
	xapic_write(XAPIC_SINT_OFF, xapic_read(XAPIC_SINT_OFF) | 0x1ff);

	asm volatile ("mov %0, %%cr8" :: "r"(0ull));
}
