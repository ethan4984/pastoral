#include <fs/cdev.h>
#include <lib/cpu.h>
#include <lib/errno.h>
#include <lib/hash.h>

static char cdev_lock;
static struct hash_table cdev_list;

int cdev_open(struct vfs_node *node, struct file_handle *file) {
	spinlock(&cdev_lock);
	struct cdev *dev = hash_table_search(&cdev_list, &file->stat->st_rdev, sizeof(dev_t));
	if(!dev) {
		spinrelease(&cdev_lock);
		set_errno(ENODEV);
		return -1;
	}

	file->ops = dev->fops;
	file->private_data = dev->private_data;
	if(file->ops->open) {
		spinrelease(&cdev_lock);
		int ret = file->ops->open(node, file);
		return ret;
	}

	spinrelease(&cdev_lock);
	return 0;
}

int cdev_register(dev_t dev, struct cdev *cdev) {
	spinlock(&cdev_lock);
	struct cdev *aux = hash_table_search(&cdev_list, &dev, sizeof(dev_t));

	if(aux) {
		spinrelease(&cdev_lock);
		return -1;
	}

	hash_table_push(&cdev_list, &dev, cdev, sizeof(dev_t));
	spinrelease(&cdev_lock);
	return 0;
}

int cdev_unregister(dev_t dev) {
	spinlock(&cdev_lock);
	hash_table_delete(&cdev_list, &dev, sizeof(dev_t));
	spinrelease(&cdev_lock);
	return 0;
}
