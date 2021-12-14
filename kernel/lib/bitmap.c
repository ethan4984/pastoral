#include <bitmap.h>
#include <string.h>
#include <mm/slab.h>

void bitmap_init(struct bitmap *bitmap, bool resizable, size_t size) {
	bitmap->size = size; 
	bitmap->data = alloc(DIV_ROUNDUP(size, 8));
	bitmap->resizable = resizable;
}

ssize_t bitmap_alloc(struct bitmap *bitmap) {
	for(size_t i = 0; i < (bitmap->size * 8); i++) {
		if(BIT_TEST(bitmap->data, i) == 0) {
			BIT_SET(bitmap->data, i);
			return i;
		}
	}

	if(bitmap->resizable) {
		bitmap->size += 0x200;
		bitmap->data = realloc(bitmap->data, bitmap->size);

		return bitmap_alloc(bitmap);
	}

	return -1;
}

void bitmap_free(struct bitmap *bitmap, size_t index) {
	if(index > bitmap->size) {
		return;
	}

	BIT_CLEAR(bitmap->data, index);
}
