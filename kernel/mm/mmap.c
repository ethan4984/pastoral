#include <mm/mmap.h>
#include <mm/vmm.h>
#include <vector.h>

static ssize_t validate_region(struct page_table *page_table, uint64_t base, uint64_t length) {
    struct mmap_region *root = page_table->mmap_region_root;
    struct mmap_region *parent = NULL;

    if(root == NULL) {
        return -1;
    }

    while(root) {
        parent = root;

        if(root->base > base) {
            root = root->left;
        } else {
            root = root->right;
        }
    }

    struct mmap_region *region = parent->parent;

    if(region->base <= base && (region->base + region->limit) >= base) {
        return -1;
    }

    return region->base + region->limit - base + length;
}

void *mmap(struct page_table *page_table, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    uint64_t base = MMAP_MAP_MIN_ADDR;

    if(flags & MMAP_MAP_FIXED) {
        base = (uintptr_t)addr;
    } else {
        base = page_table->mmap_bump_base;

        for(;;) {
            ssize_t conflict_offset = validate_region(page_table, base, length);

            if(conflict_offset == -1) {
                break;
            }

            base += conflict_offset;
        }

        page_table->mmap_bump_base += length;
    }

    struct mmap_region *region = alloc(sizeof(struct mmap_region));

    *region = (struct mmap_region) {
        .base = base,
        .limit = length,
        .prot = prot,
        .flags = flags,
        .fd = fd,
        .offset = offset
    };

    struct mmap_region *root = page_table->mmap_region_root;
    struct mmap_region *parent = NULL;

    while(root) {
        parent = root;

        if(root->base > region->base) {
            root = root->left;
        } else {
            root = root->right;
        }
    }

    region->parent = parent;

    if(parent == NULL) {
        page_table->mmap_region_root = region;
    } else if(parent->base > region->base) {
        parent->left = region;
    } else {
        parent->right = region;
    }

    return (void*)base;
}

/*int munmap(struct page_table *page_table, void *addr, size_t length) {

}*/
