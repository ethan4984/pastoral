#pragma once

#include <fs/fd.h>
#include <lib/cpu.h>
#include <lib/types.h>
#include <lib/termios.h>
#include <lib/ioctl.h>
#include <lib/circular_queue.h>
#include <sched/queue.h>
#include <lock.h>

#define MAX_LINE 8192
#define MAX_CANON 8192

#define MAX_CANON_LINES 256

#define OUTPUT_BUFFER_SIZE 8192

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
	struct spinlock lock;
	int refcnt; // To track connections and disconnections.

	struct termios termios;
	struct tty_driver *driver;
	void *private_data;

	struct session *session;
	struct process_group *foreground_group;

	struct spinlock input_lock;
	struct circular_queue input_queue;

	struct spinlock output_lock;
	struct circular_queue output_queue;

	struct spinlock canon_lock;
	struct circular_queue canon_queue;

	struct spinlock file_lock;
	VECTOR(struct file_handle*) files;
};

void tty_init(struct tty *);
int tty_register(dev_t dev, struct tty *);
int tty_unregister(dev_t dev);
void tty_default_termios(struct termios *);

ssize_t tty_handle_canon(struct tty *, void *, size_t);
ssize_t tty_handle_raw(struct tty *, void *, size_t);
void tty_handle_signal(struct tty *, char ch);

static inline void tty_lock(struct tty *tty) {
	spinlock_irqsave(&tty->lock);
}

static inline void tty_unlock(struct tty *tty) {
	spinrelease_irqsave(&tty->lock);
}

extern struct tty *active_tty;
