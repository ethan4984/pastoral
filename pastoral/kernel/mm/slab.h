#pragma once

#include <stdint.h>
#include <stddef.h>

void slab_cache_create(const char *name, size_t object_size);
void *alloc(size_t cnt);
void *realloc(void *obj, size_t size);
void free(void *obj);
