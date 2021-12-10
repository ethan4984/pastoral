#include <vmm/intel/vtd.h>

static struct dmar *dmar;

int vtd_init() {
	dmar = acpi_find_sdt("DMAR");
	if(dmar == NULL) {
		return -1;	
	}

	return 0;
}
