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

#define PTS_MAJOR 136

// Master/slave metadata fields
struct ptm_data;
struct pts_data {
	int slave_no;
	struct tty *tty;
	struct ptm_data *master;
};

struct ptm_data {
	struct tty *tty;
	struct pts_data *slave;
};

// Global state
static struct bitmap pts_bitmap = {
	.resizable = true
};
static char pty_lock;

// Driver operations
static int ptmx_open(struct vfs_node *node, struct file_handle *file);
static void pts_flush_output(struct tty *tty);
static void ptm_flush_output(struct tty *tty);
static int ptm_ioctl(struct tty *tty, uint64_t req, void *arg);

static struct file_ops ptmx_ops = {
	.open = ptmx_open
};

static struct tty_ops pts_ops = {
	.flush_output = pts_flush_output
};

static struct tty_ops ptm_ops = {
	.flush_output = ptm_flush_output,
	.ioctl = ptm_ioctl
};

static struct tty_driver pts_driver = {
	.ops = &pts_ops
};

static struct tty_driver ptm_driver = {
	.ops = &ptm_ops
};

// Implementation

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

static int ptmx_open(struct vfs_node *node, struct file_handle *file) {
	spinlock(&pty_lock);

	int slave_no = bitmap_alloc(&pts_bitmap);
	struct tty *pts_tty = alloc(sizeof(struct tty));
	struct tty *ptm_tty = alloc(sizeof(struct tty));
	struct pts_data *pts_data = alloc(sizeof(struct pts_data));
	struct ptm_data *ptm_data = alloc(sizeof(struct ptm_data));

	pts_tty->driver = &pts_driver;
	pts_tty->private_data = pts_data;
	pts_tty->generate_signals = true;
	pts_data->slave_no = slave_no;
	pts_data->tty = pts_tty;
	pts_data->master = ptm_data;

	ptm_tty->driver = &ptm_driver;
	ptm_tty->private_data = ptm_data;
	ptm_tty->generate_signals = false;
	ptm_tty->refcnt = 1;
	ptm_data->tty = ptm_tty;
	ptm_data->slave = pts_data;

	tty_init(ptm_tty);
	tty_register(makedev(PTS_MAJOR, slave_no), pts_tty);

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);
	stat->st_mode = S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP;
	stat->st_rdev = makedev(PTS_MAJOR, slave_no);
	stat->st_uid = CURRENT_TASK->effective_uid;
	stat->st_gid = CURRENT_TASK->effective_gid;

	char *name = alloc(MAX_PATH_LENGTH);
	sprint(name, "/dev/pts/%d", slave_no);
	vfs_create_node_deep(NULL, NULL, NULL, stat, name);

	file->ops = &tty_cdev_ops;
	file->private_data = ptm_tty;

	spinrelease(&pty_lock);
	return 0;
}

static void pts_flush_output(struct tty *tty) {
	struct pts_data *pts = tty->private_data;
	struct ptm_data *ptm = pts->master;

	spinlock(&pts->tty->output_lock);
	spinlock(&ptm->tty->input_lock);

	char ch;
	while(circular_queue_pop(&pts->tty->output_queue, &ch)) {
		circular_queue_push(&ptm->tty->input_queue, &ch);
	}

	spinrelease(&ptm->tty->input_lock);
	spinrelease(&pts->tty->output_lock);
}

static void ptm_flush_output(struct tty *tty) {
	struct ptm_data *ptm = tty->private_data;
	struct pts_data *pts = ptm->slave;

	spinlock(&ptm->tty->output_lock);
	spinlock(&pts->tty->input_lock);

	char ch;
	while(circular_queue_pop(&ptm->tty->output_queue, &ch)) {
		circular_queue_push(&pts->tty->input_queue, &ch);
	}

	spinrelease(&pts->tty->input_lock);
	spinrelease(&ptm->tty->output_lock);
}

static int ptm_ioctl(struct tty *tty, uint64_t req, void *data) {
	switch(req) {
		case TIOCGPTN: {
			struct ptm_data *ptm = tty->private_data;
			return ptm->slave->slave_no;
		}

		default: {
			set_errno(ENOSYS);
			return -1;
		}
	}
}
