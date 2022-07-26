#include <lib/types.h>
#include <lib/termios.h>
#include <lib/circular_queue.h>
#include <drivers/tty/tty.h>


static void do_echo(struct tty *tty, char ch) {
	if(!(tty->termios.c_lflag & ECHO)) {
		return;
	}

	if(ch > 0 && ch < 32 && ch != tty->termios.c_cc[VEOL] && ch != '\t') {
		if(!(tty->termios.c_lflag & ECHOCTL)) {
			return;
		}

		char aux[] = {'^', ch + 64};
		circular_queue_push(&tty->output_queue, &aux[0]);
		circular_queue_push(&tty->output_queue, &aux[1]);
		return;
	}

	circular_queue_push(&tty->output_queue, &ch);
}

static bool pass_to_canon_buf(struct termios *attr, char ch) {
	if(ch == attr->c_cc[VEOL] || ch == '\t' || ch >= 32) {
		return true;
	}

	for(size_t i = 0; i < NCCS; i++) {
		if(attr->c_cc[i] == ch) {
			return false;
		}
	}

	return true;
}

ssize_t tty_handle_canon(struct tty *tty, void *buf, size_t count) {
	char *c_buf = buf;
	ssize_t ret;

	spinlock(&tty->canon_lock);

	// If there is any unread line left, read it.
out:
	struct circular_queue *line_queue;
	if(circular_queue_peek(&tty->canon_queue, &line_queue)) {
		for(ret = 0; ret < (ssize_t)count; ret++) {
			if(!circular_queue_pop(line_queue, c_buf)) {
				break;
			}
			c_buf++;
		}
		if(line_queue->items == 0) {
			// Remove line from queue and free it.
			circular_queue_pop(&tty->canon_queue, &line_queue);
			circular_queue_destroy(line_queue);
			free(line_queue);
		}

		spinrelease(&tty->canon_lock);
		return ret;
	}

	// Wait for characters.
	char ch, aux;
	size_t items = 0;
	line_queue = alloc(sizeof(struct circular_queue));
	circular_queue_init(line_queue, MAX_CANON, sizeof(char));
	circular_queue_push(&tty->canon_queue, &line_queue);

	while (1) {
		while(__atomic_load_n(&tty->input_queue.items, __ATOMIC_RELAXED) == 0);
		spinlock(&tty->input_lock);

		while(circular_queue_pop(&tty->input_queue, &ch)) {
			if(pass_to_canon_buf(&tty->termios, ch)) {
				circular_queue_push(line_queue, &ch);
				items++;
				spinlock(&tty->output_lock);
				do_echo(tty, ch);
				spinrelease(&tty->output_lock);
				tty->driver->ops->flush_output(tty);
			}

			if(ch == tty->termios.c_cc[VEOL] || ch == tty->termios.c_cc[VEOF]) {
				spinrelease(&tty->input_lock);
				goto out;
			}

			if((tty->termios.c_lflag & ECHOE) && (ch == tty->termios.c_cc[VERASE])) {
				// Remove from the line input queue and print a backspace.
				if(items) {
					items--;
					char aux2[] = {'\b', ' ', '\b'};
					spinlock(&tty->output_lock);
					circular_queue_push(&tty->output_queue, &aux2[0]);
					circular_queue_push(&tty->output_queue, &aux2[1]);
					circular_queue_push(&tty->output_queue, &aux2[2]);
					spinrelease(&tty->output_lock);
					tty->driver->ops->flush_output(tty);
					circular_queue_pop_tail(line_queue, &aux);
				}
			}
		}

		spinrelease(&tty->input_lock);
	}

	goto out;
}

ssize_t tty_handle_raw(struct tty *tty, void *buf, size_t count) {
	cc_t min = tty->termios.c_cc[VMIN];
	cc_t time = tty->termios.c_cc[VTIME];
	char *c_buf = buf;
	ssize_t ret;

	if(min == 0 && time == 0) {
		spinlock(&tty->input_lock);
		spinlock(&tty->output_lock);
		for(ret = 0; ret < (ssize_t) count; ret++) {
			if(!circular_queue_pop(&tty->input_queue, c_buf)) {
				break;
			}

			do_echo(tty, *c_buf++);
		}
		spinrelease(&tty->output_lock);
		tty->driver->ops->flush_output(tty);
		spinrelease(&tty->input_lock);

		return ret;
	} else if(min > 0 && time == 0) {
		while(__atomic_load_n(&tty->input_queue.items, __ATOMIC_RELAXED) != min);
		spinlock(&tty->input_lock);
		spinlock(&tty->output_lock);
		for(ret = 0; ret < (ssize_t) count; ret++) {
			circular_queue_pop(&tty->input_queue, c_buf);
			do_echo(tty, *c_buf++);
		}
		spinrelease(&tty->output_lock);
		tty->driver->ops->flush_output(tty);
		spinrelease(&tty->input_lock);

		return ret;
	} else {
		// TODO: TIME != NULL
		return -1;
	}
}
