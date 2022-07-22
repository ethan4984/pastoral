#pragma once

#include <lib/types.h>

struct cdev {
	struct asset *asset;
};


// Used by the fd open function.
int cdev_open(dev_t dev, struct asset **asset);

int cdev_register(dev_t dev, struct cdev *cdev);
int cdev_unregister(dev_t dev);
