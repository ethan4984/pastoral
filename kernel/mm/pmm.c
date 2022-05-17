#include <mm/pmm.h>
#include <debug.h>
#include <stddef.h>
#include <cpu.h>
#include <string.h>
#include <stivale.h>

struct pmm_module {
	struct stivale_mmap_entry *mmap_entry;

	size_t bitmap_size;
	size_t bitmap_entry_cnt;
	size_t last_free;
	uint8_t *bitmap;

	struct pmm_module *next;

	char lock;
};

static struct pmm_module *root_module;
static void *meta_buffer;

static void pmm_init_module(struct pmm_module *module, struct stivale_mmap_entry *mmap_entry) {
	size_t page_cnt = DIV_ROUNDUP(mmap_entry->length, PAGE_SIZE);

	module->mmap_entry = mmap_entry;
	module->bitmap_size = DIV_ROUNDUP(page_cnt, 8);
	module->bitmap_entry_cnt = page_cnt;
	module->bitmap = meta_buffer;

	memset8(module->bitmap, 0, module->bitmap_size);

	meta_buffer += module->bitmap_size;
}

static uint64_t pmm_module_alloc(struct pmm_module *module, uint64_t cnt, uint64_t align) {
	spinlock(&module->lock);

	size_t alloc_base = ALIGN_UP(module->mmap_entry->base + (module->last_free * PAGE_SIZE), align * PAGE_SIZE); // calcuate base address for the allocation
	size_t bit_base = (alloc_base - module->mmap_entry->base) / PAGE_SIZE;

	for(size_t i = bit_base; i < module->bitmap_entry_cnt; i += align) {
		if(module->bitmap_entry_cnt < (i + cnt)) {
			spinrelease(&module->lock);
			return -1;
		}

		for(size_t j = i, count = 0; j < (i + cnt); j++) {
			if(BIT_TEST(module->bitmap, j)) {
				alloc_base += align * PAGE_SIZE;
				break;
			}

			if(++count == cnt) {
				for(size_t z = 0; z < count; z++) {
					BIT_SET(module->bitmap, i + z);
				}

				module->last_free = 0;

				for(size_t z = j; z < module->bitmap_entry_cnt; z++) {
					if(!BIT_TEST(module->bitmap, z)) {
						module->last_free = z;
						break;
					}
				}

				spinrelease(&module->lock);

				return alloc_base;
			}
		}
	}

	spinrelease(&module->lock);

	return -1;
}

static void pmm_module_free(struct pmm_module *module, uint64_t base, uint64_t cnt) {
	spinlock(&module->lock);

	for(size_t i = DIV_ROUNDUP(base, PAGE_SIZE); i < (DIV_ROUNDUP(base, PAGE_SIZE) + cnt); i++) {
		BIT_CLEAR(module->bitmap, i);
	}

	spinrelease(&module->lock);
}

void pmm_init() {
	struct stivale_mmap_entry *mmap = (struct stivale_mmap_entry*)stivale_struct->memory_map_addr;

	size_t buffer_size = 0;

	for(size_t i = 0; i < stivale_struct->memory_map_entries; i++) { // calcuate the size the metabuffer needs to be
		if(mmap[i].type == STIVALE_MMAP_USABLE) {
			size_t entry_cnt = DIV_ROUNDUP(mmap[i].length, PAGE_SIZE);
			buffer_size += sizeof(struct pmm_module) * 2 + DIV_ROUNDUP(entry_cnt, 8);
		}

		if(mmap[i].base < 0x100000) {
			if(0x100000 - mmap[i].base > mmap[i].length) {
				mmap[i].length = 0;
				continue;
			}

			mmap[i].base += 0x100000 - mmap[i].base;
			mmap[i].length -= 0x100000 - mmap[i].base;
		}
	}

	for(size_t i = 0; i < stivale_struct->memory_map_entries; i++) { // find a memory range that the buffer can fit inside and allocate it
		if(mmap[i].type == STIVALE_MMAP_USABLE && mmap[i].length >= buffer_size) {
			meta_buffer = (void*)(mmap[i].base + HIGH_VMA);
			mmap[i].base += buffer_size;
			mmap[i].length -= buffer_size;

			mmap[i].base = ALIGN_UP(mmap[i].base, PAGE_SIZE); // align up a page
			mmap[i].length = mmap[i].length / PAGE_SIZE * PAGE_SIZE; // align down a page

			break;
		}
	}

	for(size_t i = 0; i < stivale_struct->memory_map_entries; i++) { // create bitmap modules for all usable regions
		if(mmap[i].type == STIVALE_MMAP_USABLE && mmap[i].length) {
			print("pmm: [%x -> %x] length %x type %x\n", mmap[i].base, mmap[i].base + mmap[i].length, mmap[i].length, mmap[i].type);

			if(root_module == NULL) {
				meta_buffer = (void*)(ALIGN_UP((uintptr_t)meta_buffer - HIGH_VMA, sizeof(struct pmm_module)) + HIGH_VMA);
				root_module = (struct pmm_module*)meta_buffer;
				memset8((void*)root_module, 0, sizeof(struct pmm_module));
				meta_buffer += sizeof(struct pmm_module) * 2;
				pmm_init_module(root_module, &mmap[i]);
				continue; 
			}

			struct pmm_module *node = root_module;
			while(node->next) {
				node = node->next;
			}

			meta_buffer = (void*)(ALIGN_UP((uintptr_t)meta_buffer - HIGH_VMA, sizeof(struct pmm_module)) + HIGH_VMA);
			node->next = (struct pmm_module*)meta_buffer;
			memset8((void*)node->next, 0, sizeof(struct pmm_module));
			meta_buffer += sizeof(struct pmm_module) * 2;

			pmm_init_module(node->next, &mmap[i]);
		}
	}

	print("pmm: initialised\n");
}


uint64_t pmm_alloc(uint64_t cnt, uint64_t align) {
	struct pmm_module *module = root_module;

	do {
		uint64_t alloc = pmm_module_alloc(module, cnt, align);

		if(alloc == -1) {
			module = module->next;
			continue;
		}

		memset64((void*)(alloc + HIGH_VMA), 0, (cnt * PAGE_SIZE) / 8);

		return alloc;
	} while(module);

	return -1;
}

void pmm_free(uint64_t base, uint64_t cnt) {
	struct pmm_module *module = root_module;

	do {
		struct stivale_mmap_entry *mmap = module->mmap_entry;
		if(base >= mmap->base && (mmap->base + cnt * PAGE_SIZE) <= (mmap->base + module->bitmap_entry_cnt * PAGE_SIZE)) {
			return pmm_module_free(module, base - mmap->base, cnt);
		}
		module = module->next;
	} while(module);
}
