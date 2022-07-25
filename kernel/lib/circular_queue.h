#pragma once

#include <lib/types.h>

struct circular_queue {
	void *data;
	size_t size;
	size_t obj_size;
	size_t head;
	size_t tail;

	// This is the only atomic field. However, do not treat
	// this datastructure as a atomic. The rationale for this
	//is to allow polling for the items available in a thread
	// safe manner.
	size_t items;
};

void circular_queue_init(struct circular_queue *queue, size_t size, size_t obj_size);
bool circular_queue_push(struct circular_queue *queue, const void *data);
bool circular_queue_pop(struct circular_queue *queue, void *data);
bool circular_queue_peek(struct circular_queue *queue, void *data);
