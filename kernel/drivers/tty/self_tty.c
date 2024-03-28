#include <drivers/tty/tty.h>
#include <fs/fd.h>
#include <fs/cdev.h>
#include <fs/vfs.h>
#include <lib/cpu.h>
#include <lib/types.h>
#include <errno.h>

#define SELF_TTY_MAJOR 5

static int self_tty_open(struct vfs_node *node, struct file_handle *file, int);

static struct file_ops self_tty_ops = {
	.open = self_tty_open
};

int self_tty_init() {
	struct cdev *cdev = alloc(sizeof(struct cdev));

	cdev->fops = &self_tty_ops;
	cdev->rdev = makedev(SELF_TTY_MAJOR, 0);

	if(cdev_register(cdev) == -1)
		return -1;

	struct stat *stat = alloc(sizeof(struct stat));

	stat_init(stat);
	stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	stat->st_rdev = makedev(SELF_TTY_MAJOR, 0);

	vfs_create_node_deep(NULL, NULL, NULL, stat, "/dev/tty");

	return 0;
}

static int self_tty_open(struct vfs_node*, struct file_handle *file, int) {
	if(!CURRENT_TASK->session->tty) {
		set_errno(ENODEV);
		return -1;
	}

	file->private_data = CURRENT_TASK->session->tty;
	file->ops = &tty_cdev_ops;

	return 0;
}
