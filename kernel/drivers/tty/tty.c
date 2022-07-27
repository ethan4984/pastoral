#include <fs/cdev.h>
#include <lib/cpu.h>
#include <lib/errno.h>
#include <drivers/tty/tty.h>
#include <fs/fd.h>
#include <sched/sched.h>
#include <sched/signal.h>
#include <lib/debug.h>

static int tty_open(struct vfs_node *, struct file_handle *file);
static ssize_t tty_read(struct file_handle *file, void *buf, size_t count, off_t);
static ssize_t tty_write(struct file_handle *file, const void *buf, size_t count, off_t);
static int tty_close(struct vfs_node *, struct file_handle *file);
static int tty_ioctl(struct file_handle *file, uint64_t req, void *arg);

struct file_ops tty_cdev_ops = {
	.open = tty_open,
	.read = tty_read,
	.write = tty_write,
	.close = tty_close,
	.ioctl = tty_ioctl
};

void tty_init(struct tty *tty) {
	circular_queue_init(&tty->input_queue, MAX_LINE, sizeof(char));
	circular_queue_init(&tty->output_queue, OUTPUT_BUFFER_SIZE, sizeof(char));
	circular_queue_init(&tty->canon_queue, MAX_CANON_LINES, sizeof(struct circular_queue *));
	tty_default_termios(&tty->termios);
}

int tty_register(dev_t dev, struct tty *tty) {
	tty_init(tty);

	struct cdev *cdev = alloc(sizeof(struct cdev));
	cdev->fops = &tty_cdev_ops;
	cdev->private_data = tty;
	cdev->rdev = dev;
	if(cdev_register(cdev) == -1) {
		free(cdev);
		return -1;
	}

	return 0;
}

int tty_unregister(dev_t dev) {
	return cdev_unregister(dev);
}

static int tty_open(struct vfs_node *, struct file_handle *file) {
	struct tty *tty = file->private_data;
	if(__atomic_fetch_add(&tty->refcnt, 1, __ATOMIC_RELAXED) == 0)
		if(tty->driver->ops->connect)
			if(tty->driver->ops->connect(tty) == -1)
				return -1;

	if(!tty->session && !(file->flags & O_NOCTTY)
		&& (CURRENT_TASK->group->pgid == CURRENT_TASK->session->pgid_leader)) {
		tty->session = CURRENT_TASK->session;
		tty->foreground_group = CURRENT_TASK->group;
		CURRENT_TASK->session->tty = tty;
	}

	return 0;
}

static ssize_t tty_read(struct file_handle *file, void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	ssize_t ret;

	tty_lock(tty);
	if(tty->termios.c_lflag & ICANON) {
		ret = tty_handle_canon(tty, buf, count);
	} else {
		ret = tty_handle_raw(tty, buf, count);
	}
	tty_unlock(tty);

	return ret;
}

static ssize_t tty_write(struct file_handle *file, const void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	ssize_t ret;
	const char *b = buf;

	tty_lock(tty);
	spinlock(&tty->output_lock);
	for(ret = 0; ret < (ssize_t)count; ret++) {
		if(!circular_queue_push(&tty->output_queue, b++)) {
			break;
		}
	}
	spinrelease(&tty->output_lock);
	tty->driver->ops->flush_output(tty);
	tty_unlock(tty);

	return ret;
}

static int tty_close(struct vfs_node *, struct file_handle *file) {
	struct tty *tty = file->private_data;
	if(__atomic_sub_fetch(&tty->refcnt, 1, __ATOMIC_RELAXED) == 0)
		if(tty->driver->ops->disconnect)
			return tty->driver->ops->disconnect(tty);

	return 0;
}

static int tty_ioctl(struct file_handle *file, uint64_t req, void *arg) {
	struct tty *tty = file->private_data;
	tty_lock(tty);
	switch(req) {
		case TIOCGPGRP: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TIOCGPGRP)\n", CORE_LOCAL->pid);
#endif
			if(CURRENT_TASK->session != tty->session) {
				tty_unlock(tty);
				print("why is this true\n");
				set_errno(ENOTTY);
				return -1;
			}

			pid_t *pgrp = arg;
			*pgrp = tty->foreground_group->pgid;
			tty_unlock(tty);
			return 0;
		}

		case TIOCSPGRP: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TIOCSPGRP)\n", CORE_LOCAL->pid);
#endif
			if(CURRENT_TASK->session != tty->session) {
				tty_unlock(tty);
				print("why is this true\n");
				set_errno(ENOTTY);
				return -1;
			}

			pid_t pgrp = *(pid_t *) arg;
			struct process_group *group;

			if(!(group = hash_table_search(&tty->session->group_list, &pgrp, sizeof(pid_t)))) {
				tty_unlock(tty);
				set_errno(EPERM);
				return -1;
			}

			tty->foreground_group = group;
			tty_unlock(tty);
			return 0;
		}

		case TIOCSCTTY: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TIOCSCTTY)\n", CORE_LOCAL->pid);
#endif
			tty_unlock(tty);
			return 0;
		}

		case TCGETS: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TCGETS)\n", CORE_LOCAL->pid);
#endif
			spinlock(&tty->input_lock);
			spinlock(&tty->output_lock);
			struct termios *attr = arg;
			*attr = tty->termios;
			spinrelease(&tty->output_lock);
			spinrelease(&tty->input_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETS: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TCSETS)\n", CORE_LOCAL->pid);
#endif
			spinlock(&tty->input_lock);
			spinlock(&tty->output_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			spinrelease(&tty->output_lock);
			spinrelease(&tty->input_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETSW: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TCSETW)\n", CORE_LOCAL->pid);
#endif
			while(__atomic_load_n(&tty->output_queue.items, __ATOMIC_RELAXED));
			spinlock(&tty->output_lock);
			spinlock(&tty->input_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			spinrelease(&tty->input_lock);
			spinrelease(&tty->output_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETSF: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x] tty_ioctl (TCSETF)\n", CORE_LOCAL->pid);
#endif
			while(__atomic_load_n(&tty->output_queue.items, __ATOMIC_RELAXED));
			spinlock(&tty->output_lock);
			spinlock(&tty->input_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			char ch;
			while(circular_queue_pop(&tty->input_queue, &ch));
			spinrelease(&tty->input_lock);
			spinrelease(&tty->output_lock);
			tty_unlock(tty);
			return 0;
		}

		default:
			if(tty->driver->ops->ioctl) {
				int ret = tty->driver->ops->ioctl(tty, req, arg);
				tty_unlock(tty);
				return ret;
			} else {
				tty_unlock(tty);
				print("why is this true\n");
				set_errno(ENOTTY);
				return -1;
			}
	}
}

void tty_default_termios(struct termios *attr) {
	attr->c_lflag = ECHO | ECHOCTL | ECHOE | ISIG | ICANON;

	attr->c_cc[VEOF] = 4;		// ^D
	attr->c_cc[VERASE] = 8;		// ^H
	attr->c_cc[VINTR] = 3;		// ^C
	attr->c_cc[VKILL] = 21;		// ^U
	attr->c_cc[VSTART] = 17;	// ^Q
	attr->c_cc[VSTOP] = 19;		// ^S
	attr->c_cc[VSUSP] = 26;		// ^Z
	attr->c_cc[VEOL] = '\n';
	attr->c_cc[VQUIT] = 28;

	attr->c_cc[VTIME] = 0;
	attr->c_cc[VMIN] = 1;
}
