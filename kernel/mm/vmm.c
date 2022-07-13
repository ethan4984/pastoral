#include <mm/vmm.h>
#include <mm/pmm.h>
#include <cpu.h>
#include <string.h>
#include <sched/sched.h>
#include <mm/mmap.h>
#include <debug.h>
#include <limine.h>

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

static uint64_t *pml4_map_page(struct page_table *page_table, uintptr_t vaddr, uint64_t paddr, uint64_t flags) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		page_table->pml_high[pml_indices.pml4_index] = pmm_alloc(1, 1) | (flags & PML4_FLAGS_MASK) | VMM_FLAGS_RW;
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		pml3[pml_indices.pml3_index] = pmm_alloc(1, 1) | (flags & PML3_FLAGS_MASK) | VMM_FLAGS_RW;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(flags & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] = paddr | flags;
		spinrelease(&page_table->lock);
		return NULL;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		pml2[pml_indices.pml2_index] = pmm_alloc(1, 1) | (flags & PML2_FLAGS_MASK) | VMM_FLAGS_RW;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] = paddr | flags;

	spinrelease(&page_table->lock);

	return &pml1[pml_indices.pml1_index];
}

static size_t pml4_unmap_page(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if((pml2[pml_indices.pml2_index] & 0xfff) & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] &= ~(VMM_FLAGS_P);
		invlpg(vaddr);
		spinrelease(&page_table->lock);
		return 0x200000;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] &= ~(VMM_FLAGS_P);
	invlpg(vaddr);

	spinrelease(&page_table->lock);

	return 0x1000;
}

static uint64_t *pml4_lowest_level(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml3 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(pml2[pml_indices.pml2_index] & VMM_FLAGS_PS) {
		spinrelease(&page_table->lock);
		return &pml2[pml_indices.pml2_index];
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	} 

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	spinrelease(&page_table->lock);

	return pml1 + pml_indices.pml1_index;
}

static uint64_t *pml5_lowest_level(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

	if((page_table->pml_high[pml_indices.pml5_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml4 = (uint64_t*)((page_table->pml_high[pml_indices.pml5_index] & ~(0xfff)) + HIGH_VMA);

	if((pml4[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml3 = (uint64_t*)((pml4[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if(pml2[pml_indices.pml2_index] & VMM_FLAGS_PS) {
		spinrelease(&page_table->lock);
		return &pml2[pml_indices.pml2_index];
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return NULL;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	spinrelease(&page_table->lock);

	return pml1 + pml_indices.pml1_index;
}

static uint64_t *pml5_map_page(struct page_table *page_table, uintptr_t vaddr, uint64_t paddr, uint64_t flags) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

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
		spinrelease(&page_table->lock);
		return NULL;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		pml2[pml_indices.pml2_index] = pmm_alloc(1, 1) | (flags & PML2_FLAGS_MASK);
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] = paddr | flags;

	spinrelease(&page_table->lock);

	return &pml1[pml_indices.pml1_index];
}

static size_t pml5_unmap_page(struct page_table *page_table, uintptr_t vaddr) {
	struct pml_indices pml_indices = compute_table_indices(vaddr);

	spinlock(&page_table->lock);

	if((page_table->pml_high[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml4 = (uint64_t*)((page_table->pml_high[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml4[pml_indices.pml4_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml3 = (uint64_t*)((pml4[pml_indices.pml4_index] & ~(0xfff)) + HIGH_VMA);

	if((pml3[pml_indices.pml3_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml2 = (uint64_t*)((pml3[pml_indices.pml3_index] & ~(0xfff)) + HIGH_VMA);

	if((pml2[pml_indices.pml2_index] & 0xfff) & VMM_FLAGS_PS) {
		pml2[pml_indices.pml2_index] &= ~(VMM_FLAGS_P);
		invlpg(vaddr);
		spinrelease(&page_table->lock);
		return 0x200000;
	}

	if((pml2[pml_indices.pml2_index] & VMM_FLAGS_P) == 0) {
		spinrelease(&page_table->lock);
		return 0;
	}

	uint64_t *pml1 = (uint64_t*)((pml2[pml_indices.pml2_index] & ~(0xfff)) + HIGH_VMA);

	pml1[pml_indices.pml1_index] &= ~(VMM_FLAGS_P);
	invlpg(vaddr);

	spinrelease(&page_table->lock);

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

static volatile struct limine_kernel_address_request limine_kernel_address_request = {
	.id = LIMINE_KERNEL_ADDRESS_REQUEST,
	.revision = 0
};

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
	page_table->pages = alloc(sizeof(struct hash_table));

	uintptr_t kernel_vaddr = limine_kernel_address_request.response->virtual_base;
	uintptr_t kernel_paddr = limine_kernel_address_request.response->physical_base;

	for(size_t i = 0; i < 0x400; i++) {
		page_table->map_page(page_table, kernel_vaddr, kernel_paddr, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_G | VMM_FLAGS_US);
		kernel_vaddr += 0x1000;
		kernel_paddr += 0x1000;
	}

	uint64_t phys = 0;
	for(size_t i = 0; i < 0x800; i++) {
		page_table->map_page(page_table, phys + HIGH_VMA, phys, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_US);
		phys += 0x200000;
	}

	struct limine_memmap_entry **mmap = limine_memmap_request.response->entries;
	uint64_t entry_count = limine_memmap_request.response->entry_count;

	for(uint64_t i = 0; i < entry_count; i++) {
		phys = (mmap[i]->base / 0x200000) * 0x200000;
		for(size_t j = 0; j < DIV_ROUNDUP(mmap[i]->length, 0x200000); j++) {
			page_table->map_page(page_table, phys + HIGH_VMA, phys, VMM_FLAGS_P | VMM_FLAGS_RW | VMM_FLAGS_PS | VMM_FLAGS_G | VMM_FLAGS_US);
			phys += 0x200000;
		}
	}

	page_table->mmap_bump_base = MMAP_MAP_MIN_ADDR;
}

struct mmap_region *vmm_copy_region_tree(struct mmap_region *root) {
	if(root == NULL) {
		return NULL;
	}

	struct mmap_region *region = alloc(sizeof(struct mmap_region));
	*region = *root;

	region->left = vmm_copy_region_tree(root->left);
	region->right = vmm_copy_region_tree(root->right);

	return region;
}

struct page_table *vmm_fork_page_table(struct page_table *page_table) {
	struct page_table *new_table = alloc(sizeof(struct page_table));

	vmm_default_table(new_table);

	for(size_t i = 0; i < page_table->pages->capacity; i++) {
		struct page *page = page_table->pages->data[i];

		if(page) {
			*page->pml_entry &= ~(VMM_FLAGS_RW);
			*page->pml_entry |= VMM_COW_FLAG;

			(*page->reference)++;

			page->flags = (page->flags & ~(VMM_FLAGS_RW)) | VMM_COW_FLAG;

			invlpg(page->vaddr);

			struct page *new_page = alloc(sizeof(struct page));
			*new_page = *page;

			new_page->pml_entry = new_table->map_page(new_table, page->vaddr, page->paddr, page->flags);

			hash_table_push(new_table->pages, &new_page->vaddr, new_page, sizeof(new_page->vaddr));
		}
	}

	uint64_t cr3;
	asm volatile ("mov %%cr3, %0" : "=a"(cr3));
	asm volatile ("mov %0, %%cr3" :: "r"(cr3) : "memory");

	new_table->mmap_region_root = vmm_copy_region_tree(page_table->mmap_region_root);

	return new_table;
}

int vmm_share_map(struct page_table *page_table, uintptr_t address) {
	
}

int vmm_private_map(struct page_table *page_table, uintptr_t address) {
	struct mmap_region *root = page_table->mmap_region_root;
	if(root == NULL) {
		return 0;
	}

	uint64_t faulting_page = address & ~(0xfff);
	uint64_t *lowest_level = page_table->lowest_level(page_table, faulting_page);

	while(root) {
		if(root->base <= address && (root->base + root->limit) >= address) {
			struct page *page = hash_table_search(page_table->pages, &faulting_page, sizeof(faulting_page));
			if(page == NULL) {
				return 0;
			}

			struct vfs_node *node = page->node;
			if(node == NULL) {
				return 0;
			}

			invlpg(address);

			int ret = node->asset->read(node->asset, NULL, page->offset, PAGE_SIZE, (void*)(page->paddr + HIGH_VMA)) == -1 ? 0 : 1;
			if(ret) {
				*lowest_level = *lowest_level | VMM_FLAGS_P;
			}

			return ret;
		}

		if(root->base > address) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	return 0;
}

int vmm_anon_map(struct page_table *page_table, uintptr_t address) {
	struct mmap_region *root = page_table->mmap_region_root;
	if(root == NULL) {
		return 0;
	}

	while(root) {
		if(root->base <= address && (root->base + root->limit) >= address) {
			uint64_t flags = VMM_FLAGS_P | VMM_FLAGS_NX;

			if(root->prot & MMAP_PROT_WRITE) flags |= VMM_FLAGS_RW;
			if(root->prot & MMAP_PROT_USER) flags |= VMM_FLAGS_US;
			if(root->prot & MMAP_PROT_EXEC) flags &= ~(VMM_FLAGS_NX);
			if(root->prot & MMAP_PROT_NONE) flags &= ~(VMM_FLAGS_P);

			size_t misalignment = address & (PAGE_SIZE - 1);

			uint64_t paddr = pmm_alloc(1, 1);
			uint64_t vaddr = address - misalignment;

			invlpg(address);

			struct page *new_page = alloc(sizeof(struct page));
			*new_page = (struct page) {
				.vaddr = vaddr,
				.paddr = paddr,
				.size = PAGE_SIZE,
				.flags = flags,
				.pml_entry = page_table->map_page(page_table, vaddr, paddr, flags),
				.reference = alloc(sizeof(int))
			};

			(*new_page->reference) = 1;

			hash_table_push(page_table->pages, &new_page->vaddr, new_page, sizeof(new_page->vaddr));

			return 1;
		}

		if(root->base > address) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	return 0;
}

#define EXIT_PF(STATUS) ({ \
	*(int*)status = STATUS; \
	return; \
})

void vmm_pf_handler(struct registers *regs, void *status) {
	struct sched_task *task = CURRENT_TASK;
	if(task == NULL) {
		EXIT_PF(0);
	}

	uint64_t faulting_address;
	asm volatile ("mov %%cr2, %0" : "=a"(faulting_address));

	uint64_t faulting_page = faulting_address & ~(0xfff);
	uint64_t *lowest_level = task->page_table->lowest_level(task->page_table, faulting_page);
	uint64_t pmll_entry = lowest_level == NULL ? 0 : *lowest_level;

	if((regs->error_code & VMM_FLAGS_P) == 0) {
		if(pmll_entry & VMM_PRIVATE_FLAG) {
			EXIT_PF(vmm_private_map(task->page_table, faulting_address));
		}
		EXIT_PF(vmm_anon_map(task->page_table, faulting_address));
	}

	if(pmll_entry & VMM_COW_FLAG) {
		struct page *page = hash_table_search(task->page_table->pages, &faulting_page, sizeof(faulting_page));
		if(page == NULL) {
			EXIT_PF(0);
		}

		uint64_t original_frame = pmll_entry & ~(0xfff) & 0xffffffffff;
		uint64_t new_frame;

		if((*page->reference) <= 1) {
			new_frame = original_frame;
		} else {
			new_frame = pmm_alloc(1, 1);
			memcpy64((uint64_t*)(new_frame + HIGH_VMA), (uint64_t*)(original_frame + HIGH_VMA), PAGE_SIZE / 8);
		}

		(*page->reference)--;

		uint64_t entry = new_frame | ((pmll_entry & 0x1ff) | (VMM_FLAGS_RW));
		*lowest_level = entry;

		invlpg(faulting_address);

		page->paddr = new_frame;
		page->reference = alloc(sizeof(int));
		(*page->reference) = 1;

		EXIT_PF(1);
	}

	if(pmll_entry & VMM_SHARE_FLAG) {
		EXIT_PF(vmm_share_map(task->page_table, faulting_address));
	}

	EXIT_PF(0);
}
