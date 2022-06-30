#pragma once

#include <types.h>
#include <vector.h>

#define VMM_FLAGS_P (1 << 0)
#define VMM_FLAGS_RW (1 << 1)
#define VMM_FLAGS_US (1 << 2)
#define VMM_FLAGS_PWT (1 << 3) 
#define VMM_FLAGS_PCD (1 << 4)
#define VMM_FLAGS_A (1 << 5)
#define VMM_FLAGS_D (1 << 6)
#define VMM_FLAGS_PS (1 << 7)
#define VMM_FLAGS_G (1 << 8)
#define VMM_FLAGS_NX (1ull << 63)

#define VMM_PAT_UC 0
#define VMM_PAT_WC 1
#define VMM_PAT_WT 4
#define VMM_PAT_WP 5
#define VMM_PAT_WB 6
#define VMM_PAT_UCM 7

#define VMM_COW_FLAG (1 << 9)

struct page {
	uint64_t paddr;
	uint64_t vaddr;
	uint64_t size;
	uint64_t flags;

	uint64_t *pml_entry;

	int *reference;
};

struct mmap_region {
	uintptr_t base;
	size_t limit;
	int flags;
	int prot;
	int fd;
	off_t offset;

	struct mmap_region *left;
	struct mmap_region *right;
	struct mmap_region *parent;
};

struct page_table {
	uint64_t *(*map_page)(struct page_table *page_table, uintptr_t vaddr, uint64_t paddr, uint64_t flags);
	size_t (*unmap_page)(struct page_table *page_table, uintptr_t vaddr);
	uint64_t *(*lowest_level)(struct page_table *page_table, uintptr_t vaddr);

	struct mmap_region *mmap_region_root;
	uint64_t mmap_bump_base;

	struct hash_table *pages;

	uint64_t *pml_high;

	char lock;
};

extern struct page_table kernel_mappings;

void vmm_init();
void vmm_init_page_table(struct page_table *page_table);
void vmm_map_range(struct page_table *page_table, uintptr_t vaddr, uint64_t cnt, uint64_t flags);
void vmm_unmap_range(struct page_table *page_table, uintptr_t vaddr, uint64_t cnt);
void vmm_default_table(struct page_table *page_table);

struct page_table *vmm_fork_page_table(struct page_table *page_table);
