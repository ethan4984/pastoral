#pragma once

#include <vector.h>

struct priority_heap_node {
	int key;
	int index;
	void *data;
};

struct priority_heap {
	VECTOR(struct priority_heap_node*) nodes;
};

void priority_heap_delete(struct priority_heap *heap, struct priority_heap_node *node);
void priority_heap_insert(struct priority_heap *heap, struct priority_heap_node *node);
