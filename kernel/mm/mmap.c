#include <mm/mmap.h>
#include <mm/vmm.h>
#include <vector.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>
#include <bst.h>
#include <string.h>

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

static struct mmap_region *mmap_search_region(struct page_table *page_table, uint64_t base) {
	struct mmap_region *root = page_table->mmap_region_root;

	while(root) {
		if(root->base <= base && (root->base + root->limit) >= base) {
			break;
		}

		if(root->base > base) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	return root;
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

	if(length == 0 || base == 0) {
		set_errno(EINVAL);
		return (void*)-1;
	}

	if((base % PAGE_SIZE != 0) || (length % PAGE_SIZE != 0)) {
		set_errno(EINVAL);
		return (void*)-1;
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

	BST_GENERIC_INSERT(page_table->mmap_region_root, base, region);

	return (void*)base;
}

int munmap(struct page_table *page_table, void *addr, size_t length) {
	uint64_t base = (uint64_t)addr;

	if(length == 0 || base == 0) {
		set_errno(EINVAL);
		return -1;
	}

	if((base % PAGE_SIZE != 0) || (length % PAGE_SIZE != 0)) {
		set_errno(EINVAL);
		return -1;
	}

	struct mmap_region *region = mmap_search_region(page_table, base);

	if(region == NULL) {
		return 0;
	}

	if(length > region->limit) {
		munmap(page_table, (void*)(base + region->limit), length - region->limit);
		length = region->limit;
	}

	struct mmap_region *lower_split = NULL;
	struct mmap_region *upper_split = NULL;

	if(region->base > base) {
		lower_split = alloc(sizeof(struct mmap_region));

		*lower_split = (struct mmap_region) {
			.base = region->base,
			.limit = region->base - base,
			.prot = region->prot,
			.flags = region->flags,
			.fd = region->fd,
			.offset = region->offset
		};
	}

	if(region->limit > length) {
		upper_split = alloc(sizeof(struct mmap_region));

		*upper_split = (struct mmap_region) {
			.base = region->base + length,
			.limit = length - region->limit,
			.prot = region->prot,
			.flags = region->flags,
			.fd = region->fd,
			.offset = region->offset
		};
	}

	BST_GENERIC_DELETE(page_table->mmap_region_root, base, region);
	BST_GENERIC_INSERT(page_table->mmap_region_root, base, lower_split);
	BST_GENERIC_INSERT(page_table->mmap_region_root, base, upper_split);

	for(size_t i = 0; i < region->limit / PAGE_SIZE; i++) {
		page_table->unmap_page(page_table, base);
		base += PAGE_SIZE;
	}

	return 0;
}

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

extern void syscall_munmap(struct registers *regs) {
	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("cant find current task");
	}

	struct page_table *page_table = current_task->page_table;
	void *addr = (void*)regs->rdi;
	size_t length = regs->rsi;

#ifndef SYSCALL_DBEUG
	print("syscall: munmap: addr {%x}, length {%x}\n", (uintptr_t)addr, length);
#endif

	regs->rax = munmap(page_table, addr, length);
}
