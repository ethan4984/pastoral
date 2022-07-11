#include <drivers/drm/drm.h>
#include <debug.h>
#include <string.h>
#include <limine.h>

static volatile struct limine_framebuffer_request limine_framebuffer_request = {
	.id = LIMINE_FRAMEBUFFER_REQUEST,
	.revision = 0
};

void gfx_init() {
	struct limine_framebuffer **framebuffers = limine_framebuffer_request.response->framebuffers;
	uint64_t framebuffer_cnt = limine_framebuffer_request.response->framebuffer_count;

	for(size_t i = 0; i < framebuffer_cnt; i++) {
		struct limine_framebuffer *fb = framebuffers[i];
		struct drm_driver *driver = alloc(sizeof(struct drm_driver));

		driver->screen_height = fb->height;
		driver->screen_width = fb->width;
		driver->screen_pitch = fb->pitch;
		driver->framebuffer = fb->address;

		driver->major = 1;
		driver->minor = 0;
		driver->patch_level = 1;

		driver->name = "rawfb_gpu";
		driver->desc = "rawfb_gpu";
		driver->date = "0000/00/00";

		char *device_path = alloc(MAX_PATH_LENGTH);
		sprint(device_path, "/dev/dri/card%d", i);

		struct asset *asset = alloc(sizeof(struct asset));
		struct stat *stat = alloc(sizeof(struct stat));

		stat->st_mode = 0666 | S_IFCHR;

		asset->ioctl = NULL;
		asset->stat = stat;

		struct vfs_node *vfs_node = vfs_create_node_deep(NULL, asset, NULL, device_path);

		drm_device_probe(driver, vfs_node);
		
		print("gfx: %s initialised\n", device_path);
	}
}
