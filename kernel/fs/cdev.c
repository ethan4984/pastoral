#include <fs/cdev.h>
#include <lib/cpu.h>
#include <lib/errno.h>
#include <lib/hash.h>

static char cdev_lock;
static struct hash_table cdev_list;

int cdev_open(dev_t dev, struct asset **asset) {
	spinlock(&cdev_lock);
	*asset = hash_table_search(&cdev_list, &dev, sizeof(dev_t));
	if(!(*asset)) {
		spinrelease(&cdev_lock);
		set_errno(ENODEV);
		return -1;
	}
	if((*asset)->open) {
		spinrelease(&cdev_lock);
		int ret = (*asset)->open(*asset);
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

	hash_table_push(&cdev_list, &dev, cdev->asset, sizeof(dev_t));
	spinrelease(&cdev_lock);
	return 0;
}

int cdev_unregister(dev_t dev) {
	spinlock(&cdev_lock);
	hash_table_delete(&cdev_list, &dev, sizeof(dev_t));
	spinrelease(&cdev_lock);
	return 0;
}
