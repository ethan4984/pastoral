#include <sched/ehfi.h>
#include <sched/smp.h>
#include <int/apic.h>
#include <int/idt.h>
#include <mm/slab.h>
#include <mm/pmm.h>
#include <debug.h>
#include <string.h>
#include <cpu.h>

static struct ehfi_structure *ehfi_structure;

static void ehfi_notification(struct registers*, void*) {
	uint64_t therm_status_package = rdmsr(MSR_PACKAGE_THERM_STATUS);

	if(therm_status_package & (1 << 26)) {
		print("EHFI structure has been updated\n");
		for(size_t i = 0; i < logical_processor_cnt; i++) {
			print("proc %d: performance capability %d energy efficency capability %d\n",
			ehfi_structure->entries[i].perf_capability,
			ehfi_structure->entries[i].energy_capability);
		}
	}

	therm_status_package &= ~(1 << 26);
	wrmsr(MSR_PACKAGE_THERM_STATUS, therm_status_package);
}

static int thermal_lvt_init() {
	int vec = idt_alloc_vector(ehfi_notification, NULL);
	if(vec == -1) {
		return -1;
	}

	uint32_t thermal_sensor_interrupt = xapic_read(XAPIC_THERMAL_LVT_OFF);
	thermal_sensor_interrupt |= vec;
	thermal_sensor_interrupt &= ~(1 << 16);
	xapic_write(XAPIC_THERMAL_LVT_OFF, thermal_sensor_interrupt);

	return 0;
}

int ehfi_init() {
	struct cpuid_state cpuid_state = cpuid(6, 0);
	if(!(cpuid_state.rax & (1 << 19))) {
		print("ehfi: not supported\n");
		return -1;
	}

	size_t page_cnt = DIV_ROUNDUP(sizeof(struct ehfi_hdr) + sizeof(struct ehfi_entry) * logical_processor_cnt, PAGE_SIZE);
	ehfi_structure = (struct ehfi_structure*)(pmm_alloc(page_cnt, 1) + HIGH_VMA);

	uint64_t feedback_ptr = rdmsr(MSR_HW_FEEDBACK_PTR);
	feedback_ptr |= (1 << 0) | (((uintptr_t)ehfi_structure - HIGH_VMA) << 11);
	wrmsr(MSR_HW_FEEDBACK_PTR, feedback_ptr);

	uint64_t feedback_config = rdmsr(MSR_HW_FEEDBACK_CONFIG);
	feedback_config |= (1 << 0);
	wrmsr(MSR_HW_FEEDBACK_CONFIG, feedback_config);

	print("ehfi: hfi enabled\n");
	
	if(thermal_lvt_init() == -1) {
		return -1;	
	}

	uint64_t therm_interrupt_package = rdmsr(MSR_PACKAGE_THERM_INTERRUPT);
	therm_interrupt_package |= (1 << 25);
	wrmsr(MSR_PACKAGE_THERM_INTERRUPT, therm_interrupt_package);

	print("ehfi: hardware feedback notifications enabled\n");

	return 0;
}
