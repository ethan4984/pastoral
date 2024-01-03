#include <mm/mmap.h>
#include <mm/vmm.h>
#include <vector.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>
#include <bst.h>
#include <string.h>
#include <fs/vfs.h>
#include <mm/pmm.h>

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

static int mmap_shared_pages(struct page_table *page_table, uintptr_t vaddr, int fd, off_t offset, int length, int prot) {
	print("SHARED PAGES!!!!\n");
	struct fd_handle *handle = fd_translate(fd);
	if(handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	file_get(handle->file_handle);
	offset = offset & ~(0xfff);

	uint64_t flags = VMM_FILE_FLAG | VMM_SHARE_FLAG | VMM_FLAGS_NX;

	if(prot & MMAP_PROT_WRITE) flags |= VMM_FLAGS_RW;
	if(prot & MMAP_PROT_USER) flags |= VMM_FLAGS_US;
	if(prot & MMAP_PROT_EXEC) flags &= ~(VMM_FLAGS_NX);

	for(size_t i = 0; i < DIV_ROUNDUP(length, PAGE_SIZE); i++) {
		struct page *page = hash_table_search(&handle->file_handle->vfs_node->shared_pages, &offset, sizeof(offset));
		struct page *new_page = alloc(sizeof(struct page));

		if(page) {
			flags |= VMM_FLAGS_P;

			*new_page = (struct page) {
				.vaddr = vaddr,
				.frame = page->frame,
				.size = PAGE_SIZE,
				.flags = flags,
				.offset = offset,
				.pml_entry = page_table->map_page(page_table, vaddr, page->frame->addr, flags),
				.reference = page->reference
			};

			(*new_page->reference)++;
		} else {
			struct frame *frame = alloc(sizeof(struct frame));
			uint64_t extra_flags = 0;

			if(handle->file_handle->ops->shared == NULL) {
				frame->addr = pmm_alloc(1, 1);
			} else {
				frame->addr = (uint64_t)handle->file_handle->ops->shared(handle->file_handle, NULL, offset);
				extra_flags |= VMM_FLAGS_P;
			}

			*new_page = (struct page) {
				.vaddr = vaddr,
				.frame = frame,
				.size = PAGE_SIZE,
				.flags = flags | extra_flags,
				.file = handle->file_handle,
				.offset = offset,
				.pml_entry = page_table->map_page(page_table, vaddr, frame->addr, flags | extra_flags),
				.reference = alloc(sizeof(int))
			};

			(*new_page->reference) = 1;
		}

		hash_table_push(page_table->pages, &new_page->vaddr, new_page, sizeof(new_page->vaddr));
		hash_table_push(&handle->file_handle->vfs_node->shared_pages, &new_page->offset, new_page, sizeof(new_page->vaddr));

		offset += PAGE_SIZE;
		vaddr += PAGE_SIZE;
	}

	return 0;
}

static int mmap_private_pages(struct page_table *page_table, uintptr_t vaddr, int fd, off_t offset, int length, int prot) {
	struct fd_handle *handle = fd_translate(fd);
	if(handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	file_get(handle->file_handle);
	offset = offset & ~(0xfff);

	uint64_t flags = VMM_FILE_FLAG | VMM_FLAGS_NX;

	if(prot & MMAP_PROT_WRITE) flags |= VMM_FLAGS_RW;
	if(prot & MMAP_PROT_USER) flags |= VMM_FLAGS_US;
	if(prot & MMAP_PROT_EXEC) flags &= ~(VMM_FLAGS_NX);

	for(size_t i = 0; i < DIV_ROUNDUP(length, PAGE_SIZE); i++) {
		struct page *page = alloc(sizeof(struct page));

		struct frame *frame = alloc(sizeof(struct frame));
		frame->addr = pmm_alloc(1, 1);

		*page = (struct page) {
			.vaddr = vaddr,
			.frame = frame,
			.size = PAGE_SIZE,
			.flags = flags,
			.file = handle->file_handle,
			.offset = offset,
			.pml_entry = page_table->map_page(page_table, vaddr, frame->addr, flags),
			.reference = alloc(sizeof(int))
		};

		(*page->reference) = 1;

		hash_table_push(page_table->pages, &page->vaddr, page, sizeof(page->vaddr));

		offset += PAGE_SIZE;
		vaddr += PAGE_SIZE;
	}

	return 0;
}

void *mmap(struct page_table *page_table, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	uint64_t base = 0;

	length = ALIGN_UP(length, PAGE_SIZE);

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

	if(!(flags & MMAP_MAP_ANONYMOUS)) {
		if(flags & MMAP_MAP_SHARED) {
			if(mmap_shared_pages(page_table, base, fd, offset, length, prot) == -1) {
				return (void*)-1;
			}
		} else if(flags & MMAP_MAP_PRIVATE) {
			if(mmap_private_pages(page_table, base, fd, offset, length, prot) == -1) {
				return (void*)-1;
			}
		} else {
			set_errno(EINVAL);
			return (void*)-1;
		}
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

/*	uint64_t _flags = VMM_FLAGS_P | VMM_FLAGS_NX;

	if(prot & MMAP_PROT_WRITE) _flags |= VMM_FLAGS_RW;
	if(prot & MMAP_PROT_USER) _flags |= VMM_FLAGS_US;
	if(prot & MMAP_PROT_EXEC) _flags &= ~(VMM_FLAGS_NX);
	if(prot & MMAP_PROT_NONE) _flags &= ~(VMM_FLAGS_P);

	for(size_t i = 0; i < DIV_ROUNDUP(length, PAGE_SIZE); i++) {
		uint64_t paddr = pmm_alloc(1, 1);
		uint64_t vaddr = base;

		struct page *new_page = alloc(sizeof(struct page));
		*new_page = (struct page) {
			.vaddr = vaddr,
			.paddr = paddr,
			.size = PAGE_SIZE,
			.flags = _flags,
			.pml_entry = page_table->map_page(page_table, vaddr, paddr, _flags),
			.reference = alloc(sizeof(int))
		};

		(*new_page->reference) = 1;

		hash_table_push(page_table->pages, &new_page->vaddr, new_page, sizeof(new_page->vaddr));
	}*/

	return (void*)base;
}


// TODO: decrease reference count on the mmaped file
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
		struct page *page = hash_table_search(CURRENT_TASK->page_table->pages, &base, sizeof(base));

		if(page) {
			if(page->flags & VMM_SHARE_FLAG) {
				(*page->reference)--;

				if(*page->reference == 0 && page->file) {
					if(page->file->ops->shared == NULL) {
						page->file->ops->write(page->file, (void*)(page->frame->addr + HIGH_VMA), PAGE_SIZE, page->offset);
					}

					hash_table_delete(&page->file->vfs_node->shared_pages, &page->vaddr, sizeof(page->vaddr));
				}
			}

			hash_table_delete(CURRENT_TASK->page_table->pages, &base, sizeof(base));
		}

		page_table->unmap_page(page_table, base);
		base += PAGE_SIZE;
	}

	return 0;
}

extern void syscall_mmap(struct registers *regs) {
	struct task *current_task = CURRENT_TASK;
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

#if defined(SYSCALL_DEBUG_MEM) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] mmap: addr {%x}, length {%x}, prot {%x}, flags {%x}, fd {%x}, offset {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, (uintptr_t)addr, length, prot, flags, fd, offset);
#endif

	regs->rax = (uint64_t)mmap(page_table, addr, length, prot | MMAP_PROT_USER, flags, fd, offset);
}

extern void syscall_munmap(struct registers *regs) {
	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("cant find current task");
	}

	struct page_table *page_table = current_task->page_table;
	void *addr = (void*)regs->rdi;
	size_t length = regs->rsi;

#if defined(SYSCALL_DEBUG_MEM) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] munmap: addr {%x}, length {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, (uintptr_t)addr, length);
#endif

	regs->rax = munmap(page_table, addr, length);
}
