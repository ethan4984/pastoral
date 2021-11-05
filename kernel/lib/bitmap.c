#include <bitmap.h>
#include <string.h>

ssize_t bitmap_alloc(struct bitmap *bitmap) {
	for(size_t i = 0; i < bitmap->size; i++) {
		if(BIT_TEST(bitmap->data, i) == 0) {
			BIT_SET(bitmap->data, i);
			return i;
		}
	}
	return -1;
}

void bitmap_free(struct bitmap *bitmap, size_t index) {
	if(index > bitmap->size) {
		return;
	}

	BIT_CLEAR(bitmap->data, index);
}
