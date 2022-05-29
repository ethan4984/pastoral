#include <mm/vmm.h>
#include <mm/pmm.h>
#include <cpu.h>
#include <string.h>
#include <stivale.h>
#include <sched/sched.h>
#include <mm/mmap.h>
#include <debug.h>

#define PML5_FLAGS_MASK ~(VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_NX)
#define PML4_FLAGS_MASK ~(VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_NX)
#define PML3_FLAGS_MASK ~(VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_NX)
#define PML2_FLAGS_MASK ~(VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_NX)

struct pml_indices {
	uint16_t pml5_index;
	uint16_t pml4_index;
	uint16_t pml3_index;
	uint16_t pml2_index;
	uint16_t pml1_index;
};

struct vmm_cow_page {
	VECTOR(struct sched_task*) task_list;
};

static struct pml_indices compute_table_indices(uintptr_t vaddr) {
	struct pml_indices ret;

	ret.pml5_index = (vaddr >> 48) & 0x1ff;
	ret.pml4_index = (vaddr >> 39) & 0x1ff;
	ret.pml3_index = (vaddr >> 30) & 0x1ff;
	ret.pml2_index = (vaddr >> 21) & 0x1ff;
	ret.pml1_index = (vaddr >> 12) & 0x1ff;

	return ret;
}

struct page_table kernel_mappings;

static void pml4_map_page(struct page_table *page_table, uintptr_t vaddr, uint64_t paddr, uint64_t flags) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		page_table->pml_high[pml_indices.pml4_index] = pmm_alloc(1, 1) | (flags & PML4_FLAGS_MASK);
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		pml3[pml_indices.pml3_index] = pmm_alloc(1, 1) | (flags & PML3_FLAGS_MASK);
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(flags & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] = paddr | flags;
		return;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		pml2[pml_indices.pml2_index] = pmm_alloc(1, 1) | (flags & PML2_FLAGS_MASK);
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] = paddr | flags;
}

static size_t pml4_unmap_page(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if((pml2[pml_indices.pml2_index] & 0xfff) & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] &= ~(VMM_FLAGS_P);
		invlpg(vaddr);
		return 0x200000;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] &= ~(VMM_FLAGS_P);
	invlpg(vaddr);

	return 0x1000;
}

static uint64_t *pml4_lowest_level(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(pml2[pml_indices.pml2_index] & VMM_FLAGS_PS) {
		return &pml2[pml_indices.pml2_index];
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	} 

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	return &pml1[pml_indices.pml1_index];
}

static uint64_t *pml5_lowest_level(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml5_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml4 = (uint64_t*)((page_table->pml_high[pml_indices.pml5_index] & ~(0xfff)) + HIGH_VMA);

	if((pml4[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml3 = (uint64_t*)((pml4[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(pml2[pml_indices.pml2_index] & VMM_FLAGS_PS) {
		return &pml2[pml_indices.pml2_index];
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		return NULL;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	return &pml1[pml_indices.pml1_index];
}

static void pml5_map_page(struct page_table *page_table, uintptr_t vaddr, uint64_t paddr, uint64_t flags) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml5_index] & VMM_FLAGS_P) == 0) {
		page_table->pml_high[pml_indices.pml5_index] = pmm_alloc(1, 1) | (flags & PML5_FLAGS_MASK);
	}

	uint64_t *pml4 = (uint64_t*)((page_table->pml_high[pml_indices.pml5_index] & ~(0xfff)) + HIGH_VMA);

	if((pml4[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		pml4[pml_indices.pml4_index] = pmm_alloc(1, 1) | (flags & PML4_FLAGS_MASK);	
	}

	uint64_t *pml3 = (uint64_t*)((pml4[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		pml3[pml_indices.pml3_index] = pmm_alloc(1, 1) | (flags & PML3_FLAGS_MASK);
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(flags & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] = paddr | flags;
		return;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		pml2[pml_indices.pml2_index] = pmm_alloc(1, 1) | (flags & PML2_FLAGS_MASK);
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] = paddr | flags;
}

static size_t pml5_unmap_page(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml4 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml4[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml3 = (uint64_t*)((pml4[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if((pml2[pml_indices.pml2_index] & 0xfff) & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] &= ~(VMM_FLAGS_P);
		invlpg(vaddr);
		return 0x200000;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		return 0;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] &= ~(VMM_FLAGS_P);
	invlpg(vaddr);

	return 0x1000;
}

void vmm_map_range(struct page_table *page_table, uintptr_t vaddr, uint64_t cnt, uint64_t flags) {
	if(flags & VMM_FLAGS_PS) {
		for(size_t i = 0; i < cnt; i++) {
			page_table->map_page(page_table, vaddr, pmm_alloc(1, 0x200), flags);
			vaddr += 0x200000;
		}
	} else {
		for(size_t i = 0; i < cnt; i++) {
			page_table->map_page(page_table, vaddr, pmm_alloc(1, 1), flags);
			vaddr += 0x1000;
		}
	}
}

void vmm_unmap_range(struct page_table *page_table, uintptr_t vaddr, uint64_t cnt) {
	for(size_t i = 0; i < cnt; i++) {
		size_t page_size = page_table->unmap_page(page_table, vaddr);
		if(page_size == 0) {
			return;
		}
		vaddr += page_size;
	}
}

void vmm_init_page_table(struct page_table *page_table) {
	asm volatile ("mov %0, %%cr3" :: "r"((uint64_t)page_table->pml_high - HIGH_VMA) : "memory");
}

void vmm_init() {
	vmm_default_table(&kernel_mappings);
	vmm_init_page_table(&kernel_mappings);
}

void vmm_default_table(struct page_table *page_table) {
	struct cpuid_state cpuid_state = cpuid(7, 0);

	if(cpuid_state.rcx & (1 << 16)) {
		page_table->map_page = pml5_map_page;
		page_table->unmap_page = pml5_unmap_page;
		page_table->lowest_level = pml5_lowest_level;
	} else {
		page_table->map_page = pml4_map_page;
		page_table->unmap_page = pml4_unmap_page;
		page_table->lowest_level = pml4_lowest_level;
	}

	page_table->pml_high = (uint64_t*)(pmm_alloc(1, 1) + HIGH_VMA);

	size_t phys = 0;
	for(size_t i = 0; i < 0x400; i++) {
		page_table->map_page(page_table, phys + KERNEL_HIGH_VMA, phys, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_US);
		phys += 0x200000;
	}

	phys = 0;
	for(size_t i = 0; i < 0x800; i++) {
		page_table->map_page(page_table, phys + HIGH_VMA, phys, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_US);
		phys += 0x200000;
	}

	struct stivale_mmap_entry *mmap = (struct stivale_mmap_entry*)stivale_struct->memory_map_addr;

	for(size_t i = 0; i < stivale_struct->memory_map_entries; i++) {
		phys = (mmap[i].base / 0x200000) * 0x200000;
		for(size_t j = 0; j < DIV_ROUNDUP(mmap[i].length, 0x200000); j++) {
			page_table->map_page(page_table, phys + HIGH_VMA, phys, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_US);
			phys += 0x200000;
		}
	}

	page_table->mmap_bump_base = MMAP_MAP_MIN_ADDR;
}

void vmm_pf_handler(struct registers *regs, void *status) {
	if(regs->cs & 0x3) {
		swapgs();
	}

	struct sched_task *task = CURRENT_TASK;
	if(task == NULL) {
		if(regs->cs & 0x3) {
			swapgs();
		}
		return;
	}

	uint64_t faulting_address;
	asm volatile ("mov %%cr2, %0" : "=a"(faulting_address));

	struct mmap_region *root = task->page_table->mmap_region_root;

	if(root == NULL) {
		if(regs->cs & 0x3) {
			swapgs();
		}
		return;
	}

	while(root) {
		if(root->base <= faulting_address && (root->base + root->limit) >= faulting_address) {
			uint64_t flags = VMM_FLAGS_P | VMM_FLAGS_NX;

			if(root->prot & MMAP_PROT_WRITE) flags |= VMM_FLAGS_RW;
			if(root->prot & MMAP_PROT_USER) flags |= VMM_FLAGS_US;
			if(root->prot & MMAP_PROT_EXEC) flags &= ~(VMM_FLAGS_NX);
			if(root->prot & MMAP_PROT_NONE) flags &= ~(VMM_FLAGS_P);

			size_t misalignment = faulting_address & (PAGE_SIZE - 1);

			vmm_map_range(task->page_table, faulting_address - misalignment, 1, flags);

			*(int*)status = 1;

			if(regs->cs & 0x3) {
				swapgs();
			}

			return;
		}

		if(root->base > faulting_address) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	panic("page fault: unable to map address %x\n", faulting_address);

	if(regs->cs & 0x3) {
		swapgs();
	}
}
