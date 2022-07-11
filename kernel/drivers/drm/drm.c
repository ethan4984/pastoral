#include <drivers/drm/drm.h>
#include <errno.h>
#include <debug.h>
#include <cpu.h>

void drm_device_probe(struct drm_driver *driver, struct vfs_node *vfs_node) {
	struct drm_device *device = alloc(sizeof(struct drm_device));

	device->vfs_node = vfs_node;
	device->driver = driver;

	vfs_node->asset->something = device;
}

int drm_device_ioctl(struct asset *asset, int, uint64_t req, void *args) {
	struct drm_device *device = asset->something;
	if(device == NULL) {
		set_errno(ENOTTY);
		return -1;
	}

	switch(req) {
		DRM_IOCTL_VERSION:
			struct drm_version *version = args;

			version->major = device->driver->major;
			version->minor = device->driver->minor;
			version->patch_level = device->driver->patch_level;
			version->name_length = 0;
			version->name = NULL;
			version->desc_length = 0;
			version->desc = NULL;
			version->date_length = 0;
			version->date = NULL;

			break;
		default:
			print("drm: unrecognised ioctl req {%x}\n", req);
			set_errno(EINVAL);
			return -1;
	}

	return 0;
}
