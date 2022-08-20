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

struct tty *active_tty;

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

	tty_lock(tty);
	VECTOR_PUSH(tty->files, file);
	tty_unlock(tty);

	return 0;
}

static ssize_t tty_read(struct file_handle *file, void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	ssize_t ret;

	// TODO: add check for orphaned process groups.
	if(CURRENT_TASK->session == tty->session) {
		if(CURRENT_TASK->group != tty->foreground_group) {
			if(signal_is_ignored(CURRENT_TASK, SIGTTIN)
				|| signal_is_blocked(CURRENT_TASK, SIGTTIN)) {
				set_errno(EIO);
				return -1;
			}

			signal_send_group(NULL, CURRENT_TASK->group, SIGTTIN);
			set_errno(EINTR);
			return -1;
		}
	}

	if(tty->termios.c_lflag & ICANON) {
		ret = tty_handle_canon(tty, buf, count);
	} else {
		ret = tty_handle_raw(tty, buf, count);
	}

	return ret;
}

static ssize_t tty_write(struct file_handle *file, const void *buf, size_t count, off_t) {
	struct tty *tty = file->private_data;
	ssize_t ret;
	const char *b = buf;

	// TODO: add check for orphaned process groups.
	if(CURRENT_TASK->session == tty->session) {
		if(CURRENT_TASK->group != tty->foreground_group
			&& (tty->termios.c_lflag & TOSTOP)) {

			if(signal_is_ignored(CURRENT_TASK, SIGTTOU)
				|| signal_is_blocked(CURRENT_TASK, SIGTTOU)) {
				set_errno(EIO);
				return -1;
			}

			signal_send_group(NULL, CURRENT_TASK->group, SIGTTOU);
			set_errno(EINTR);
			return -1;
		}
	}

	// Can we at least satisfy a partial write?
	if(file->flags & O_NONBLOCK) {
		if(__atomic_load_n(&tty->output_queue.items, __ATOMIC_RELAXED) > (count % OUTPUT_BUFFER_SIZE)) {
			set_errno(EAGAIN);
			return -1;
		}
	}

	spinlock_irqsave(&tty->output_lock);
	for(ret = 0; ret < (ssize_t)count; ret++) {
		if(!circular_queue_push(&tty->output_queue, b++)) {
			if(file->flags & O_NONBLOCK) {
				break;
			}

			// Try again.
			spinrelease_irqsave(&tty->output_lock);
			tty->driver->ops->flush_output(tty);
			spinlock_irqsave(&tty->output_lock);
		}
	}
	spinrelease_irqsave(&tty->output_lock);
	tty->driver->ops->flush_output(tty);

	return ret;
}

static int tty_close(struct vfs_node *, struct file_handle *file) {
	struct tty *tty = file->private_data;
	if(__atomic_sub_fetch(&tty->refcnt, 1, __ATOMIC_RELAXED) == 0)
		if(tty->driver->ops->disconnect)
			tty->driver->ops->disconnect(tty);

	if(file->refcnt == 1) {
		tty_lock(tty);
		VECTOR_REMOVE_BY_VALUE(tty->files, file);
		tty_unlock(tty);
	}

	return 0;
}

static int tty_ioctl(struct file_handle *file, uint64_t req, void *arg) {
	struct tty *tty = file->private_data;
	tty_lock(tty);
	switch(req) {
		case TIOCGPGRP: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x, tid %x] tty_ioctl (TIOCGPGRP)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			if(CURRENT_TASK->session != tty->session) {
				tty_unlock(tty);
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
			print("syscall: [pid %x, tid %x] tty_ioctl (TIOCSPGRP)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif

			if(CURRENT_TASK->session != tty->session) {
				tty_unlock(tty);
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
			print("syscall: [pid %x, tid %x] tty_ioctl (TIOCSCTTY)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			if(tty->session || (CURRENT_TASK->session->pgid_leader
				!= CURRENT_TASK->group->pgid)) {
					set_errno(EPERM);
					return -1;
			}

			tty->session = CURRENT_TASK->session;
			tty->foreground_group = CURRENT_TASK->group;

			tty_unlock(tty);
			return 0;
		}

		case TCGETS: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x, tid %x] tty_ioctl (TCGETS)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			spinlock_irqsave(&tty->input_lock);
			spinlock_irqsave(&tty->output_lock);
			struct termios *attr = arg;
			*attr = tty->termios;
			spinrelease_irqsave(&tty->output_lock);
			spinrelease_irqsave(&tty->input_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETS: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x, tid %x] tty_ioctl (TCSETS)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			spinlock_irqsave(&tty->input_lock);
			spinlock_irqsave(&tty->output_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			spinrelease_irqsave(&tty->output_lock);
			spinrelease_irqsave(&tty->input_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETSW: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x, tid %x] tty_ioctl (TCSETW)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			while(__atomic_load_n(&tty->output_queue.items, __ATOMIC_RELAXED));
			spinlock_irqsave(&tty->output_lock);
			spinlock_irqsave(&tty->input_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			spinrelease_irqsave(&tty->input_lock);
			spinrelease_irqsave(&tty->output_lock);
			tty_unlock(tty);
			return 0;
		}

		case TCSETSF: {
#ifndef SYSCALL_DEBUG
			print("syscall: [pid %x, tid %x] tty_ioctl (TCSETF)\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
			while(__atomic_load_n(&tty->output_queue.items, __ATOMIC_RELAXED));
			spinlock_irqsave(&tty->output_lock);
			spinlock_irqsave(&tty->input_lock);
			struct termios *attr = arg;
			tty->termios = *attr;
			char ch;
			while(circular_queue_pop(&tty->input_queue, &ch));
			spinrelease_irqsave(&tty->input_lock);
			spinrelease_irqsave(&tty->output_lock);
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
				set_errno(ENOTTY);
				return -1;
			}
	}
}

void tty_default_termios(struct termios *attr) {
	attr->c_lflag = ECHO | ECHOCTL | ECHOE | ISIG | ICANON | TOSTOP;
	attr->c_iflag = 0;

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

void tty_handle_signal(struct tty *tty, char ch) {
	if(tty->termios.c_lflag & ISIG) {
		if(tty->termios.c_cc[VINTR] == ch) {
			signal_send_group(NULL, tty->foreground_group, SIGINT);
		} else if(tty->termios.c_cc[VQUIT] == ch) {
			signal_send_group(NULL, tty->foreground_group, SIGTERM);
		} else if(tty->termios.c_cc[VSUSP] == ch) {
			signal_send_group(NULL, tty->foreground_group, SIGTSTP);
		}
	}
}
