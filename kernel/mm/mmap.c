#include <mm/mmap.h>
#include <mm/vmm.h>
#include <vector.h>
#include <sched/sched.h>
#include <debug.h>

static ssize_t validate_region(struct page_table *page_table, uint64_t base, uint64_t length) {
	struct mmap_region *root = page_table->mmap_region_root;

	if(root == NULL) {
		return -1;
	}

	while(root) {
		if(root->base <= base && (root->base + root->limit) > base) {
			return root->base + root->limit - base + length;
		}

		if(root->base > base) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	return -1;
}

void *mmap(struct page_table *page_table, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	uint64_t base = 0;

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

		page_table->mmap_bump_base = base;
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

extern void syscall_mmap(struct registers *regs) {
	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("cant find current task");
	}
	
	struct page_table *page_table = current_task->page_table;
	void *addr = (void*)regs->rdi;
	size_t length = regs->rsi;
	int prot = regs->rdx;
	int flags = regs->r10;
	int fd = regs->r8;
	off_t offset = regs->r9;

#ifndef SYSCALL_DEBUG
	print("syscall: mmap: addr {%x}, length {%x}, prot {%x}, flags {%x}, fd {%x}, offset {%x}\n", (uintptr_t)addr, length, prot, flags, fd, offset);
#endif

	regs->rax = (uint64_t)mmap(page_table, addr, length, prot | MMAP_PROT_USER, flags, fd, offset);
}
