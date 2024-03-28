#pragma once

#include <fs/fd.h>
#include <fs/vfs.h>
#include <lib/types.h>

struct cdev;

struct block_ops {
	ssize_t (*read)(struct cdev *, void *, size_t, off_t);
	ssize_t (*write)(struct cdev *, const void *, size_t, off_t);
	ssize_t (*ioctl)(struct cdev *, void *, size_t, off_t);
};

struct cdev {
	struct file_ops *fops;
	struct block_ops *bops;

	void *private_data;

	dev_t rdev;
};


int cdev_open(struct vfs_node *node, struct file_handle *file, int flags);

int cdev_register(struct cdev *cdev);
int cdev_unregister(dev_t dev);
