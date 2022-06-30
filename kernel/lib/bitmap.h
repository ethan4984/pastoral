#pragma once 

#include <types.h>

#define BITMAP_RESIZEABLE 0
#define BITMAP_NON_RERESIZEABLE 1

struct bitmap {
	uint8_t *data;
	size_t size;
	bool resizable;
};

ssize_t bitmap_alloc(struct bitmap *bitmap);
void bitmap_free(struct bitmap *bitmap, size_t index);
void bitmap_init(struct bitmap *bitmap, bool resizable, size_t size);
void bitmap_dup(struct bitmap *bitmap, struct bitmap *dest);
