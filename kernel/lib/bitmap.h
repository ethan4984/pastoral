#pragma once 

#include <types.h>

struct bitmap {
	uint8_t *data;
	size_t size;
};

ssize_t bitmap_alloc(struct bitmap *bitmap);
void bitmap_free(struct bitmap *bitmap, size_t index);
