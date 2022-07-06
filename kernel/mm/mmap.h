#pragma once

#include <mm/vmm.h>

#define MMAP_MAP_FAILED (void*)-1
#define MMAP_MAP_PRIVATE 0x1
#define MMAP_MAP_SHARED 0x2
#define MMAP_MAP_FIXED 0x4
#define MMAP_MAP_ANONYMOUS 0x8
#define MMAP_MAP_MIN_ADDR 0x100000000000

#define MMAP_PROT_NONE 0x0
#define MMAP_PROT_READ 0x1
#define MMAP_PROT_WRITE 0x2
#define MMAP_PROT_EXEC 0x4
#define MMAP_PROT_USER 0x8

void *mmap(struct page_table *page_table, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(struct page_table *page_table, void *addr, size_t length);
