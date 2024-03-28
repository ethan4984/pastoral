#include <fs/cdev.h>
#include <lib/cpu.h>
#include <lib/errno.h>
#include <lib/hash.h>
#include <lock.h>

static struct spinlock cdev_lock;
static struct hash_table cdev_list;

int cdev_open(struct vfs_node *node, struct file_handle *file, int flags) {
	spinlock_irqsave(&cdev_lock);

	struct cdev *dev = hash_table_search(&cdev_list, &file->stat->st_rdev, sizeof(dev_t));

	if(!dev) {
		spinrelease_irqsave(&cdev_lock);
		set_errno(ENODEV);
		return -1;
	}

	file->ops = dev->fops;
	file->private_data = dev->private_data;

	if(file->ops->open) {
		spinrelease_irqsave(&cdev_lock);
		int ret = file->ops->open(node, file, flags);
		return ret;
	}

	spinrelease_irqsave(&cdev_lock);

	return 0;
}

int cdev_register(struct cdev *cdev) {
	spinlock_irqsave(&cdev_lock);
	struct cdev *aux = hash_table_search(&cdev_list, &cdev->rdev, sizeof(dev_t));
	if(aux) {
		spinrelease_irqsave(&cdev_lock);
		return -1;
	}

	hash_table_push(&cdev_list, &cdev->rdev, cdev, sizeof(cdev->rdev));
	spinrelease_irqsave(&cdev_lock);
	return 0;
}

int cdev_unregister(dev_t dev) {
	spinlock_irqsave(&cdev_lock);
	hash_table_delete(&cdev_list, &dev, sizeof(dev_t));
	spinrelease_irqsave(&cdev_lock);
	return 0;
}
