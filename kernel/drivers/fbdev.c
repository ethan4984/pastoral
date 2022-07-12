#include <drivers/fbdev.h>
#include <fs/vfs.h>
#include <limine.h>
#include <vector.h>
#include <string.h>
#include <errno.h>
#include <cpu.h>

VECTOR(struct fb_device*) fbdev_list;

static ssize_t fbdev_write(struct asset *asset, void*, off_t offset, off_t cnt, const void *buf);
static ssize_t fbdev_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf);
static int fbdev_ioctl(struct asset *asset, int fd, uint64_t req, void *args);

void fbdev_init_device(struct limine_framebuffer *framebuffer) {
	struct fb_device *device = alloc(sizeof(struct fb_device));
	device->var = alloc(sizeof(struct fb_var_screeninfo));
	device->fix = alloc(sizeof(struct fb_fix_screeninfo));

	*device->fix = (struct fb_fix_screeninfo) {
		.id = { 0 },
		.smem_start = (uint64_t)framebuffer->address,
		.smem_len = framebuffer->pitch * framebuffer->height,
		.type = 0,
		.type_aux = 0,
		.visual = 2,
		.xpanstep = 0,
		.ypanstep = 0,
		.ywrapstep = 0,
		.line_length = framebuffer->pitch,
		.mmio_start = 0,
		.mmio_len = 0,
		.capabilities = 0,
		.reserved = { 0 }
	};

	*device->var = (struct fb_var_screeninfo) {
		.xres = framebuffer->width,
		.yres = framebuffer->height,
		.xres_virtual = framebuffer->width,
		.yres_virtual = framebuffer->height,
		.xoffset = 0,
		.yoffset = 0,
		.bits_per_pixel = framebuffer->bpp,
		.grayscale = 0,
		.red = (struct fb_bitfield) { framebuffer->red_mask_shift, framebuffer->red_mask_shift, 0 },
		.green = (struct fb_bitfield) { framebuffer->green_mask_shift, framebuffer->green_mask_shift, 0 },
		.blue = (struct fb_bitfield) { framebuffer->blue_mask_shift, framebuffer->blue_mask_shift, 0 },
		.transp = (struct fb_bitfield) { 0, 0, 0 }, 
		.nonstd = 0,
		.activate = 0,
		.height = -1,
		.width = -1,
		.accel_flags = 0,
		.pixclock = 0,
		.left_margin = 0,
		.right_margin = 0,
		.upper_margin = 0,
		.lower_margin = 0,
		.hsync_len = 0,
		.vsync_len = 0,
		.sync = 0,
		.vmode = 0,
		.rotate = 0,
		.colorspace = 0,
		.reserved = { 0 }
	};

	char *device_path = alloc(MAX_PATH_LENGTH);
	sprint(device_path, "/dev/fb%d", fbdev_list.length);

	struct asset *asset = alloc(sizeof(struct asset));
	struct stat *stat = alloc(sizeof(struct stat));

	stat->st_mode = 0666 | S_IFCHR;

	asset->ioctl = fbdev_ioctl;
	asset->write = fbdev_write;
	asset->read = fbdev_read;
	asset->stat = stat;
	asset->something = device;

	struct vfs_node *vfs_node = vfs_create_node_deep(NULL, asset, NULL, device_path);

	device->vfs_node = vfs_node;

	VECTOR_PUSH(fbdev_list, device);
}

static ssize_t fbdev_write(struct asset *asset, void*, off_t offset, off_t cnt, const void *buf) {
	struct fb_device *device = asset->something;
	if(device == NULL) {
		set_errno(EBADF);
		return -1;
	}

	if(offset + cnt > device->fix->smem_len) {
		cnt = device->fix->smem_len - offset;
	}

	memcpy8((void*)device->fix->smem_start, buf, cnt); 

	return cnt;
}

static ssize_t fbdev_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf) {
	struct fb_device *device = asset->something;
	if(device == NULL) {
		set_errno(EBADF);
		return -1;
	}

	if(offset + cnt > device->fix->smem_len) {
		cnt = device->fix->smem_len - offset;
	}

	memcpy8(buf, (void*)device->fix->smem_start, cnt); 

	return cnt;
}

static int fbdev_ioctl(struct asset *asset, int, uint64_t req, void *args) {
	struct fb_device *device = asset->something;

	switch(req) {
		case FBIOGET_VSCREENINFO:
			memcpy8(args, (void*)device->var, sizeof(struct fb_var_screeninfo));
			break;
		case FBIOPUT_VSCREENINFO:
			memcpy8((void*)device->var, args, sizeof(struct fb_var_screeninfo));
			break;
		case FBIOGET_FSCREENINFO:
			memcpy8(args, (void*)device->fix, sizeof(struct fb_fix_screeninfo));
			break;
		case FBIOBLANK:
			break;
		default: 
			set_errno(EINVAL);
			return -1;
	}

	return 0;
}
