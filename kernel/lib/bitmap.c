#include <bitmap.h>
#include <string.h>
#include <mm/slab.h>

ssize_t bitmap_alloc(struct bitmap *bitmap) {
	for(size_t i = 0; i < (bitmap->size * 8); i++) {
		if(BIT_TEST(bitmap->data, i) == 0) {
			BIT_SET(bitmap->data, i);
			return i;
		}
	}

	bitmap->size += 0x200;
	bitmap->data = realloc(bitmap->data, bitmap->size);

	return bitmap_alloc(bitmap);
}

void bitmap_free(struct bitmap *bitmap, size_t index) {
	if(index > bitmap->size) {
		return;
	}

	BIT_CLEAR(bitmap->data, index);
}
