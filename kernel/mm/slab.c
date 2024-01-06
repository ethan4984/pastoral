#include <mm/pmm.h>
#include <mm/slab.h>
#include <cpu.h>
#include <string.h>
#include <debug.h>
#include <lock.h>

#define OBJECTS_PER_SLAB 512

struct slab;

struct cache {
	size_t object_size;
	size_t active_slabs;
	size_t pages_per_slab;

	const char *name;

	struct slab *slab_empty;
	struct slab *slab_partial;
	struct slab *slab_full;

	struct spinlock lock;

	struct cache *next;
};

struct slab {
	size_t available_objects;
	size_t total_objects;
	
	uint8_t *bitmap;
	void *buffer;

	struct cache *cache;
	struct slab *next;
	struct slab *last;
};

static struct cache *root_cache;

static struct slab *cache_alloc_slab(struct cache *cache) {
	struct slab *new_slab = (struct slab*)(pmm_alloc(cache->pages_per_slab, 1) + HIGH_VMA);

	new_slab->bitmap = (uint8_t*)((uintptr_t)new_slab + sizeof(struct slab));
	new_slab->buffer = (void*)(ALIGN_UP((uintptr_t)new_slab->bitmap + OBJECTS_PER_SLAB - HIGH_VMA, 16) + HIGH_VMA);
	new_slab->available_objects = OBJECTS_PER_SLAB;
	new_slab->total_objects = OBJECTS_PER_SLAB;
	new_slab->cache = cache;

	if(cache->slab_empty)
		cache->slab_empty->last = new_slab;

	new_slab->next = cache->slab_empty;
	cache->slab_empty = new_slab;

	return new_slab;
}

static int cache_move_slab(struct slab **dest_head, struct slab **src_head, struct slab *src) {
	if(!src || !*src_head)
		return -1; 

	if(src->next != NULL)
		src->next->last = src->last;
	if(src->last != NULL)
		src->last->next = src->next;
	if(*src_head == src)
		*src_head = src->next;

	if(!*dest_head) {
		src->last = NULL;
		src->next = NULL;
		*dest_head = src; 
		return 0;
	}

	src->next = *dest_head;
	src->last = NULL;

	if(*dest_head) {
		(*dest_head)->last = src;
	}

	*dest_head = src;

	return 0;
}

static void *slab_alloc(struct slab *slab) {
	for(size_t i = 0; i < slab->total_objects; i++) {
		if(!BIT_TEST(slab->bitmap, i)) {
			BIT_SET(slab->bitmap, i);
			slab->available_objects--;
			memset8(slab->buffer + (i * slab->cache->object_size), 0, slab->cache->object_size);
			return slab->buffer + (i * slab->cache->object_size);
		}
	}

	panic("slab: returning a null pointer");

	return NULL;
}

static void *cache_alloc_obj(struct cache *cache) {
	struct slab *slab = NULL;

	spinlock_irqsave(&cache->lock);

	if(cache->slab_partial) {
		slab = cache->slab_partial;
	} else if(cache->slab_empty) {
		slab = cache->slab_empty;
	}

	if(!slab) {
		slab = cache_alloc_slab(cache);
		cache->slab_empty = slab;
	}

	void *addr = slab_alloc(slab);

	if(slab->available_objects == 0) {
		cache_move_slab(&cache->slab_full, &cache->slab_partial, slab);
	} else if(slab->available_objects == (slab->total_objects - 1)) {
		cache_move_slab(&cache->slab_partial, &cache->slab_empty, slab);
	}

	spinrelease_irqsave(&cache->lock);

	return addr;
}

static size_t slab_get_object_size(struct slab *slab, void *obj) {
	if(!slab)
		return 0;

	spinlock_irqsave(&slab->cache->lock);

	struct slab *root = slab;

	while(slab) {
		if(slab->buffer <= obj && (slab->buffer + slab->cache->object_size * slab->total_objects) > obj) {
			spinrelease_irqsave(&root->cache->lock);
			return slab->cache->object_size;
		}
		slab = slab->next;
	}

	spinrelease_irqsave(&root->cache->lock);

	return 0;
}

static size_t cache_get_object_size(struct cache *cache, void *obj) {
	size_t partial_object_size = slab_get_object_size(cache->slab_partial, obj);
	if(partial_object_size) {
		return partial_object_size;
	}

	size_t full_object_size = slab_get_object_size(cache->slab_full, obj);
	if(full_object_size) {
		return full_object_size;
	}

	return 0;
}

static int slab_free_object(struct slab *slab, void *obj) {
	if(slab == NULL)
		return 0;

	spinlock_irqsave(&slab->cache->lock);

	struct slab *root = slab;

	while(slab) {
		if(slab->buffer <= obj && (slab->buffer + slab->cache->object_size * slab->total_objects) > obj) {
			size_t index = ((uintptr_t)obj - (uintptr_t)slab->buffer) / slab->cache->object_size;
			if(BIT_TEST(slab->bitmap, index)) {
				BIT_CLEAR(slab->bitmap, index);
				slab->available_objects++;
				spinrelease_irqsave(&root->cache->lock);
				return 1;
			}
		}

		slab = slab->next;
	}

	spinrelease_irqsave(&root->cache->lock);

	return 0;
}

static int cache_free_object(struct cache *cache, void *obj) {
	if(slab_free_object(cache->slab_partial, obj)) {
		return 1;
	} else if(slab_free_object(cache->slab_full, obj)) {
		return 1;
	}
	return 0;
}

void slab_cache_create(const char *name, size_t object_size) {
	struct cache cache = { 0 };

	cache.pages_per_slab = DIV_ROUNDUP(object_size * OBJECTS_PER_SLAB + sizeof(struct slab) + OBJECTS_PER_SLAB, PAGE_SIZE);
	cache.object_size = object_size;
	cache.name = name;

	struct slab *root_slab = cache_alloc_slab(&cache);

	*(struct cache*)root_slab->buffer = cache;
	struct cache *new_cache = (struct cache*)root_slab->buffer;

	root_slab->cache = new_cache;
	root_slab->buffer += sizeof(struct cache);
	root_slab->available_objects -= DIV_ROUNDUP(object_size, sizeof(struct cache));
	root_slab->total_objects = root_slab->available_objects;

	new_cache->slab_empty = root_slab;
	new_cache->next = root_cache;

	root_cache = new_cache;
}

void *alloc(size_t size) {
	if(!size) {
		return NULL;
	}

	size_t round_size = pow2_roundup(size + 1);
	if(round_size <= 16) {
		round_size = 32;
	}

	struct cache *cache = root_cache;

	while(cache) {
		if(cache->object_size == round_size) {
			return cache_alloc_obj(cache);
		}
		cache = cache->next;
	}

	panic("slab: returning null");

	return NULL;
}

void free(void *obj) {
	return;

	if(!obj)
		return;

	struct cache *cache = root_cache;

	while(cache) {
		if(cache_free_object(cache, obj)) {
			return;
		}
		cache = cache->next;
	}
}

void *realloc(void *obj, size_t size) {
	if(obj == NULL) {
		return alloc(size);
	}

	struct cache *cache = root_cache;
	size_t object_size = 0;

	while(cache) {
		object_size = cache_get_object_size(cache, obj);	
		if(object_size)
			break;
		cache = cache->next;
	}

	if(object_size >= size) {
		return obj;
	}

	void *ret = alloc(size);

	memcpy8(ret, obj, object_size);
	free(obj);

	return ret;
}
