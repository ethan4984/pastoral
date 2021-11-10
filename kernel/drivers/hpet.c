#include <drivers/hpet.h>
#include <debug.h>
#include <cpu.h>

static volatile struct hpet_table *hpet_table;
static volatile struct hpet_regs *hpet_regs;

void sleep(size_t ms) {
	size_t ticks = (hpet_regs->counter_value + (ms * 1000000000000)) / ((hpet_regs->capabilities >> 32) & 0xffffffff);
	for(;hpet_regs->counter_value < ticks;); 
}

void hpet_init() {
	hpet_table = acpi_find_sdt("HPET");
	hpet_regs = (struct hpet_regs*)(hpet_table->address + HIGH_VMA);
	hpet_regs->general_config = 1; 
} 
