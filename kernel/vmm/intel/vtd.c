#include <vmm/intel/vtd.h>
#include <cpu.h>
#include <debug.h>

static struct dmar *dmar;

static inline void dmar_unit_write32(struct dmar_unit *unit, size_t off, uint32_t data) {
	*(volatile uint32_t*)(unit->register_base + HIGH_VMA + off) = data;
}

static inline void dmar_unit_write64(struct dmar_unit *unit, size_t off, uint32_t data) {
	*(volatile uint64_t*)(unit->register_base + HIGH_VMA + off) = data;
}

static inline uint32_t dmar_unit_read32(struct dmar_unit *unit, size_t off) {
	return *(volatile uint32_t*)(unit->register_base + HIGH_VMA + off);
}

static inline uint64_t dmar_unit_read64(struct dmar_unit *unit, size_t off) {
	return *(volatile uint64_t*)(unit->register_base + HIGH_VMA + off);
}

static void drhd_scope_parse(struct dmar_scope *scope) {
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
	}
}

static void drhd_parse(struct dmar_unit *unit) {
	uint32_t vs = dmar_unit_read32(unit, 0);

	int major_version = vs >> 4 & 0xf;
	int minor_version = vs & 0xf;

	print("drhd: version: %d:%d\n", major_version, minor_version);

	size_t scope_cnt = (unit->length - sizeof(struct dmar_unit)) / sizeof(struct dmar_scope);

	for(size_t i = 0; i < scope_cnt; i++) {
		drhd_scope_parse(&unit->scopes[i]);
	}
}

int vtd_init() {
	dmar = acpi_find_sdt("DMAR");
	if(dmar == NULL) {
		return -1;	
	}

	size_t unit_cnt = (dmar->acpi_hdr.length - sizeof(struct dmar)) / sizeof(struct dmar_unit);

	print("dmar: host address width %d\n", dmar->host_address_width);

	if(dmar->flags & (1 << 0)) {
		print("dmar: interrupt remapping supported\n");
		if(dmar->flags & (1 << 1)) {
			print("dmar: x2apic opt out\n");
		}
	} else {
		print("dmar: interrupt remapping not supported\n");
	}

	for(size_t i = 0; i < unit_cnt; i++) {
		struct dmar_unit *unit = &dmar->units[i];

		if(unit->type == DMAR_DRHD_TYPE) {
			drhd_parse(&dmar->units[i]);
		}
	}

	return 0;
}
