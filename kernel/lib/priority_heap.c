#include <priority_heap.h>
#include <stddef.h>

#define HEAP_ROOT 1

#define HEAP_PARENT(heap, index) ({ \
	struct priority_heap_node *_child = NULL; \
	int _index = (index) / 2 - 1; \
	if(_index < (heap)->nodes.element_cnt) { \
		_child = (heap)->nodes.elements[_index]; \
	} \
	_child; \
})

#define HEAP_LEFT(heap, index) ({ \
	struct priority_heap_node *_child = NULL; \
	int _index = (index) * 2 - 1; \
	if(_index < (heap)->nodes.element_cnt) { \
		_child = (heap)->nodes.elements[_index]; \
	} \
	_child; \
})

#define HEAP_RIGHT(heap, index) ({ \
	struct priority_heap_node *_child = NULL; \
	int _index = (index) * 2; \
	if(_index < (heap)->nodes.element_cnt) { \
		_child = (heap)->nodes.elements[_index]; \
	} \
	_child; \
})

static void max_heapify(struct priority_heap *heap, int index) {
	struct priority_heap_node *root = heap->nodes.elements[index - 1];

	struct priority_heap_node *left = HEAP_LEFT(heap, index);
	struct priority_heap_node *right = HEAP_RIGHT(heap, index);
	struct priority_heap_node *largest_child = left;
	
	if(!left && !right) {
		return;
	} else if(!left && right) {
		largest_child = right;
	} else if(left && !right) {
		largest_child = left;
	} else if(right->key > left->key) {
		largest_child = right;
	}

	if(largest_child->key > root->key) { // max heap property violation	
		struct priority_heap_node tmp = *root;

		*root = *largest_child;
		*largest_child = tmp;

		int index_tmp = root->index;

		root->index = largest_child->index;
		largest_child->index = index_tmp;

		max_heapify(heap, largest_child->index);
	}
}

void priority_heap_delete(struct priority_heap *heap, struct priority_heap_node *node) {
	VECTOR_REMOVE_BY_VALUE(heap->nodes, node);
	max_heapify(heap, heap->nodes.element_cnt);
}

void priority_heap_insert(struct priority_heap *heap, struct priority_heap_node *node) {
	VECTOR_PUSH(heap->nodes, node);
	max_heapify(heap, heap->nodes.element_cnt);
}
