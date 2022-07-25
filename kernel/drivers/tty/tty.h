#pragma once

#include <fs/fd.h>
#include <lib/cpu.h>
#include <lib/types.h>
#include <lib/termios.h>
#include <lib/ioctl.h>
#include <lib/circular_queue.h>
#include <sched/queue.h>

#define INPUT_BUFFER_SIZE 256
#define OUTPUT_BUFFER_SIZE 256

struct tty;

struct tty_ops {
	int (*connect)(struct tty *);
	int (*ioctl)(struct tty *tty, uint64_t, void *);
	int (*disconnect)(struct tty *);

	void (*flush_output)(struct tty *);
};

extern struct file_ops tty_cdev_ops;

struct tty_driver {
	struct tty_ops *ops;
};

struct tty {
	char lock;
	int refcnt; // To track connections and disconnections.

	struct termios termios;
	struct tty_driver *driver;
	void *private_data;

	struct session *session;
	struct process_group *foreground_group;

	char input_lock;
	struct circular_queue input_queue;

	char output_lock;
	struct circular_queue output_queue;

	struct waitq poll_waitq;
	struct waitq_trigger *poll_trigger;
};

int tty_register(dev_t dev, struct tty *);
int tty_unregister(dev_t dev);
void tty_handle_cc(struct tty *, int cc);
void tty_default_termios(struct termios *);

static inline void tty_lock(struct tty *tty) {
	spinlock(&tty->lock);
}

static inline void tty_unlock(struct tty *tty) {
	spinrelease(&tty->lock);
}
