#include <drivers/iommu/intel/vtd.h>
#include <string.h>
#include <mm/pmm.h>
#include <cpu.h>
#include <debug.h>

static struct dmar *dmar;
static VECTOR(struct remapping_module*) remapping_modules;

#define UNIT_READ32(MOD, OFF) ({ \
	*(volatile uint32_t*)((MOD)->unit->register_base + HIGH_VMA + OFF); \
})

#define UNIT_READ64(MOD, OFF) ({ \
	*(volatile uint64_t*)((MOD)->unit->register_base + HIGH_VMA + OFF); \
})

#define UNIT_WRITE32(MOD, OFF, DATA) ({ \
	*(volatile uint32_t*)((MOD)->unit->register_base + HIGH_VMA + OFF) = DATA; \
})

#define UNIT_WRITE64(MOD, OFF, DATA) ({ \
	*(volatile uint64_t*)((MOD)->unit->register_base + HIGH_VMA + OFF) = DATA; \
})

static void drhd_scope_parse(struct remapping_module *module, struct dmar_scope *scope) {
	if(scope->type == DMAR_SCOPE_PCI_ENDPOINT) {
		size_t n = (scope->length - sizeof(struct dmar_scope)) / 2;

		size_t bus = scope->bus_number;
		size_t dev = scope->path[0] & 0xff;
		size_t func = scope->path[0] >> 8 & 0xff;

		for(size_t i = 1; i < n; i++) {
			bus = GET_SECONDARY_BUS(bus, dev, func);
			dev = scope->path[i] & 0xff;
			func = scope->path[i] >> 8 & 0xff;
		}

		print("dmar: scope: device %x:%x:%x\n", bus, dev, func);

		struct pci_device *pci_device = pci_search_device(bus, dev, func);
		if(!pci_device) {
			return;
		}
		
		struct device_scope *device_scope = alloc(sizeof(struct device_scope));
		*device_scope = (struct device_scope) {
			.device = pci_device,
			.scope = scope
		};

		VECTOR_PUSH(module->devices, device_scope);
	}
}

static void drhd_parse(struct remapping_module *module) {
	size_t scope_cnt = (module->unit->length - sizeof(struct dmar_unit)) / sizeof(struct dmar_scope);

	for(size_t i = 0; i < scope_cnt; i++) {
		drhd_scope_parse(module, &module->unit->scopes[i]);
	}
}

static void drhd_set_global_config(struct remapping_module *module, size_t bit, bool value) {
	uint32_t gsts = UNIT_READ32(module, 0x1c);

	if((gsts & (1 << bit)) != value) {
		gsts ^= 1 << bit;
		UNIT_WRITE32(module, 0x18, gsts);
		while(UNIT_READ32(module, 0x1c) & (1 << 31));
	}
}

int vtd_init() {
	dmar = acpi_find_sdt("DMAR");
	if(dmar == NULL) {
		return -1;	
	}

	size_t unit_cnt = (dmar->acpi_hdr.length - sizeof(struct dmar)) / sizeof(struct dmar_unit);

	for(size_t i = 0; i < unit_cnt; i++) {
		struct dmar_unit *unit = &dmar->units[i];

		if(unit->type == DMAR_DRHD_TYPE) {
			struct remapping_module *module = alloc(sizeof(struct remapping_module));
			*module = (struct remapping_module) {
				.unit = unit
			};

			VECTOR_PUSH(remapping_modules, module);

			drhd_parse(module);
		}
	}

	for(size_t i = 0; i < remapping_modules.element_cnt; i++) {
		struct remapping_module *module = remapping_modules.elements[i];

		drhd_set_global_config(module, 31, false); // ensure remapping is disabled

		struct rtt *root_table = (struct rtt*)(pmm_alloc(DIV_ROUNDUP(sizeof(struct rtt) * 256, PAGE_SIZE), 1) + HIGH_VMA);

		uint64_t rtaddr = UNIT_READ64(module, 0x20);
		rtaddr &= ~(1 << 11); // root table
		rtaddr &= ~((~0xfffull) << 12);
		rtaddr |= (uintptr_t)root_table - HIGH_VMA;
		UNIT_WRITE64(module, 0x20, rtaddr);

		drhd_set_global_config(module, 30, true); // set root table pointer

		print("drhd: root table enabled\n");
	}

	return 0;
}
