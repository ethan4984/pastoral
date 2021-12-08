#pragma once 

#include <mm/slab.h>

#define VECTOR(TYPE) \
	struct { \
		TYPE *elements; \
		size_t element_cnt; \
		size_t buffer_capacity; \
	}

#define VECTOR_INIT(THIS, SIZE) \
	(THIS).buffer_capacity = SIZE; \
	(THIS).elements = alloc((THIS).buffer_capacity);

#define VECTOR_PUSH(THIS, ELEMENT) ({ \
	__label__ _ret; \
	if((THIS).elements == NULL) { \
		VECTOR_INIT(THIS, 1); \
	} \
	size_t _cap = (THIS).element_cnt + 1; \
	if(_cap <= (THIS).buffer_capacity) { \
		goto _ret; \
	} \
	(THIS).buffer_capacity *= 2; \
	(THIS).elements = realloc((THIS).elements, (THIS).buffer_capacity * sizeof(*(THIS).elements)); \
_ret: \
	(THIS).elements[(THIS).element_cnt++] = ELEMENT; \
})

#define VECTOR_INDEX(THIS, ELEMENT, INDEX) ({ \
	if((INDEX) > (THIS).buffer_capacity) { \
		(THIS).buffer_capacity += (INDEX) - (THIS).buffer_capacity; \
		(THIS).elements = realloc((THIS.elements), (THIS).buffer_capacity * sizeof(*(THIS).elements)); \
	} \
	if((INDEX) > (THIS).element_cnt) { \
		(THIS).element_cnt += (INDEX) - (THIS).element_cnt; \
	} \
	(THIS).elements[INDEX] = ELEMENT; \
})

#define VECTOR_REMOVE_BY_INDEX(THIS, INDEX) ({ \
	__label__ _ret; \
	if((THIS).element_cnt < (INDEX)) { \
		goto _ret; \
	} \
	for(size_t _i = (INDEX) + 1; _i < (THIS).element_cnt; _i++) { \
		(THIS).elements[_i - 1] = (THIS).elements[_i]; \
	} \
	(THIS).element_cnt--; \
_ret: \
})

#define VECTOR_REMOVE_BY_VALUE(THIS, VALUE) ({ \
	size_t _j = 0; \
	for(; _j < (THIS).element_cnt; _j++) { \
		if((THIS).elements[_j] == VALUE) { \
			VECTOR_REMOVE_BY_INDEX(THIS, _j); \
			break; \
		} \
	} \
	_j; \
})

#define VECTOR_DELETE(THIS) \
	free((THIS).elements);
