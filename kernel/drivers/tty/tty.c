#include <fs/cdev.h>
#include <lib/cpu.h>
#include <lib/errno.h>
#include <drivers/tty/tty.h>
#include <fs/fd.h>
#include <sched/sched.h>
#include <sched/signal.h>


static int tty_open(struct vfs_node *, struct file_handle *file);
static ssize_t tty_read(struct file_handle *file, void *buf, size_t count, off_t);
static ssize_t tty_write(struct file_handle *file, const void *buf, size_t count, off_t);
static int tty_close(struct vfs_node *, struct file_handle *file);
static int tty_ioctl(struct file_handle *file, uint64_t req, void *arg);


struct file_ops tty_cdev_ops = {
	.open = tty_open,
	.read = tty_read,
	.write = tty_write,
	.close = tty_close,
	.ioctl = tty_ioctl
};


int tty_register(dev_t dev, struct tty *tty) {
	struct cdev *cdev = alloc(sizeof(struct cdev));
	cdev->fops = &tty_cdev_ops;
	cdev->private_data = tty;
	cdev->rdev = dev;
	if(cdev_register(cdev) == -1) {
		free(cdev);
		return -1;
	}

	return 0;
}

int tty_unregister(dev_t dev) {
	return cdev_unregister(dev);
}

static int tty_open(struct vfs_node *, struct file_handle *file) {
	struct tty *tty = file->private_data;
	if(__atomic_fetch_add(&tty->refcnt, 1, __ATOMIC_RELAXED) == 0)
		if(tty->driver->ops->connect)
			return tty->driver->ops->connect(tty);

	return 0;
}

static ssize_t tty_read(struct file_handle *file, void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	tty_lock(tty);
	ssize_t ret = tty->driver->ops->read(tty, buf, count);
	tty_unlock(tty);
	return ret;
}

static ssize_t tty_write(struct file_handle *file, const void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	tty_lock(tty);
	ssize_t ret = tty->driver->ops->write(tty, buf, count);
	tty_unlock(tty);
	return ret;
}

static int tty_close(struct vfs_node *, struct file_handle *file) {
	struct tty *tty = file->private_data;
	if(__atomic_sub_fetch(&tty->refcnt, 1, __ATOMIC_RELAXED) == 0)
		if(tty->driver->ops->disconnect)
			return tty->driver->ops->disconnect(tty);

	return 0;
}

static int tty_ioctl(struct file_handle *file, uint64_t req, void *arg) {
	struct tty *tty = file->private_data;
	tty_lock(tty);
	switch(req) {
		case TIOCGPGRP: {
			if(!CURRENT_TASK->session || (CURRENT_TASK->session != tty->session)) {
				tty_unlock(tty);
				set_errno(ENOTTY);
				return -1;
			}

			pid_t *pgrp = arg;
			*pgrp = tty->foreground_group->pgid;
			tty_unlock(tty);
			return 0;
		}

		case TIOCSPGRP: {
			if(!CURRENT_TASK->session || (CURRENT_TASK->session != tty->session)) {
				tty_unlock(tty);
				set_errno(ENOTTY);
				return -1;
			}

			pid_t pgrp = *(pid_t *) arg;
			struct process_group *group;
			if(!(group = hash_table_search(&tty->session->group_list, &pgrp, sizeof(pgrp)))) {
				tty_unlock(tty);
				set_errno(EPERM);
				return -1;
			}

			tty->foreground_group = group;
			tty_unlock(tty);
			return 0;
		}

		default:
			if(tty->driver->ops->ioctl) {
				int ret = tty->driver->ops->ioctl(tty, req, arg);
				tty_unlock(tty);
				return ret;
			} else {
				tty_unlock(tty);
				set_errno(ENOTTY);
				return -1;
			}
	}
}
