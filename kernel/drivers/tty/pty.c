#include <drivers/tty/tty.h>
#include <drivers/tty/pty.h>
#include <fs/cdev.h>
#include <fs/fd.h>
#include <lib/cpu.h>
#include <lib/types.h>
#include <lib/termios.h>
#include <lib/ioctl.h>
#include <lib/errno.h>


#define PTMX_MAJOR 5
#define PTMX_MINOR 2


static int ptmx_open(struct vfs_node *node, struct file_handle *file);
static struct bitmap pty_slave_bitmap = {
	.resizable = true
};
static char pty_lock;

struct file_ops ptmx_ops = {
	.open = ptmx_open
};

int pty_init() {
	struct cdev *cdev = alloc(sizeof(struct cdev));
	cdev->fops = &ptmx_ops;
	cdev->rdev = makedev(PTMX_MAJOR, PTMX_MINOR);
	if(cdev_register(cdev) == -1) {
		return -1;
	}

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);
	stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stat->st_rdev = makedev(PTMX_MAJOR, PTMX_MINOR);
	vfs_create_node_deep(NULL, NULL, NULL, stat, "/dev/ptmx");
	return 0;
}

static int ptmx_open(struct vfs_node *node, struct file_handle *handle) {
	spinlock(&pty_lock);
	spinrelease(&pty_lock);
	set_errno(ENOSYS);
	return -1;
}
