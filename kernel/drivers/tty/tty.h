#pragma once

#include <fs/fd.h>
#include <lib/cpu.h>
#include <lib/types.h>
#include <lib/termios.h>
#include <lib/ioctl.h>


struct tty;

struct tty_ops {
	int (*connect)(struct tty *);
	ssize_t (*read)(struct tty *, void *, size_t);
	ssize_t (*write)(struct tty *, const void *, size_t);
	int (*ioctl)(struct tty *tty, uint64_t, void *);
	int (*disconnect)(struct tty *);
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
	void *input_buffer;
	size_t input_buffer_size;
	size_t input_buffer_head;
	size_t input_buffer_tail;

	void *output_buffer;
	size_t output_buffer_size;
	size_t output_buffer_head;
	size_t output_buffer_tail;
};


int tty_register(dev_t dev, struct tty *);
int tty_unregister(dev_t dev);

static inline void tty_lock(struct tty *tty) {
	spinlock(&tty->lock);
}

static inline void tty_unlock(struct tty *tty) {
	spinrelease(&tty->lock);
}
