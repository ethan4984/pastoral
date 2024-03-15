#include <net/socket.h>
#include <fs/ramfs.h>
#include <fs/fd.h>
#include <errno.h>
#include <debug.h>
#include <events/io.h>

static ssize_t socket_read(struct file_handle *file, void *buf, size_t cnt, off_t offset);
static ssize_t socket_write(struct file_handle *file, const void *buf, size_t cnt, off_t offset);
static int socket_ioctl(struct file_handle *file, uint64_t req, void *arg);
static int socket_close(struct vfs_node*, struct file_handle *handle);
static int socket_unlink(struct vfs_node*);

extern struct socket_ops unix_ops;

static struct file_ops socket_file_ops = {
	.read = socket_read,
	.write = socket_write,
	.ioctl = socket_ioctl,
	.close = socket_close,
	.unlink = socket_unlink
};

static bool socket_validate_family(int family) {
	if(family != AF_UNIX && family != AF_NETLINK) {
		return false;
	} else {
		return true;
	}
}

static bool socket_validate_type(int type) {
	if(type != SOCK_DGRAM && type != SOCK_RAW && type != SOCK_SEQPACKET && type != SOCK_STREAM) {
		return false;	
	} else {
		return true;
	}
}

static struct socket *socket_create(int family, int type, int protocol) {
	if(!socket_validate_family(family)) {
		set_errno(EAFNOSUPPORT);
		return NULL;
	}

	if(!socket_validate_type(type)) {
		set_errno(EINVAL);
		return NULL;
	}

	struct socket *socket = alloc(sizeof(struct socket));

	socket->family = family; 
	socket->type = type;
	socket->protocol = protocol;
	socket->state = SOCKET_UNCONNECTED;

	switch(family) {
		case AF_UNIX:
			socket->ops = &unix_ops;

			socket->addr = alloc(sizeof(struct socketaddr_un));
			socket->family = AF_UNIX;
			socket->stream_ops = &ramfs_fops;

			break;
		case AF_NETLINK:
			socket->ops = NULL;

			socket->addr = alloc(sizeof(struct socketaddr_un));
			socket->family = AF_UNIX;

			break;
		default:
			set_errno(EINVAL);
			return NULL;
	};

	return socket;
}

static struct fd_handle *search_socket(int sockfd) {
	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return NULL;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		return NULL;
	}

	return fd_handle;
}

static ssize_t socket_read(struct file_handle *handle, void *buf, size_t cnt, off_t) {
	struct socket *socket = handle->private_data;

	if(socket->state != SOCKET_CONNECTED) {
		set_errno(EDESTADDRREQ);
		return -1;
	}

	struct iovec iov = { };
	iov.iov_base = buf;
	iov.iov_len = cnt;

	struct msghdr msg = { };
	msg.msg_name = socket->addr;
	msg.msg_namelen = sizeof(struct socketaddr_un);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return socket->ops->recvmsg(socket, &msg, (handle->flags & O_NONBLOCK) == O_NONBLOCK ? MSG_DONTWAIT : 0);
}

static ssize_t socket_write(struct file_handle *handle, const void *buf, size_t cnt, off_t) {
	struct socket *socket = handle->private_data;

	if(socket->state != SOCKET_CONNECTED) {
		set_errno(EDESTADDRREQ);
		return -1;
	}

	struct iovec iov = { };
	iov.iov_base = (void*)buf;
	iov.iov_len = cnt;

	struct msghdr msg = { };
	msg.msg_name = socket->addr;
	msg.msg_namelen = sizeof(struct socketaddr_un);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return socket->ops->sendmsg(socket, &msg, 0);
}

static int socket_close(struct vfs_node*, struct file_handle *handle) {
	struct socket *socket = handle->private_data;
	struct socket *peer = socket->peer;

	if(peer == NULL || socket->state == SOCKET_UNCONNECTED) {
		return -1;
	}

	socket->state = SOCKET_UNCONNECTED;
	socket->peer = NULL;

	peer->state = SOCKET_UNCONNECTED;
	peer->peer = NULL;

	socket->ops->close(socket);

	return 0;
}

static int socket_unlink(struct vfs_node *) {
	set_errno(ENOSYS);
	return -1;
}

static int socket_ioctl(struct file_handle*, uint64_t, void*) {
	return -1; 
}

struct fd_handle *create_sockfd(struct socket *socket, struct file_handle *file_handle) {
	struct fd_handle *socket_fd_handle = alloc(sizeof(struct fd_handle));
	struct file_handle *socket_file_handle = file_handle;
	fd_init(socket_fd_handle);

	socket_fd_handle->file_handle = file_handle;
	socket_fd_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_table->fd_bitmap);

	socket->file_handle = socket_file_handle;

	stat_update_time(socket_file_handle->stat, STAT_ACCESS | STAT_MOD | STAT_STATUS);

	socket_file_handle->trigger = EVENT_DEFAULT_TRIGGER(&file_handle->waitq);

	struct task *current_task = CURRENT_TASK;

	print("creating socketfd %d\n", socket_fd_handle->fd_number);

	spinlock_irqsave(&current_task->fd_table->fd_lock);
	hash_table_push(&current_task->fd_table->fd_list, &socket_fd_handle->fd_number, socket_fd_handle, sizeof(socket_fd_handle->fd_number));
	spinrelease_irqsave(&current_task->fd_table->fd_lock);

	socket_fd_handle->flags |= POLLOUT;

	return socket_fd_handle;
}

void syscall_socket(struct registers *regs) {
	int family = regs->rdi;
	int type = regs->rsi;
	int protocol = regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] socket: family {%x}, type {%x}, protocol {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, family, type, protocol);
#endif

	struct socket *socket = socket_create(family, type, protocol);
	if(socket == NULL) {
		regs->rax = -1;
		return;
	}

	struct file_handle *socket_file_handle = alloc(sizeof(struct file_handle));
	file_init(socket_file_handle);

	socket_file_handle->ops = &socket_file_ops;
	socket_file_handle->private_data = socket;
	socket_file_handle->stat = alloc(sizeof(struct stat));
	socket_file_handle->stat->st_mode = S_IFSOCK;
	socket_file_handle->flags |= O_RDWR;

	ramfs_create_dangle(socket_file_handle->stat);
	
	struct fd_handle *socket_fd_handle = create_sockfd(socket, socket_file_handle);

	regs->rax = socket_fd_handle->fd_number;
}

void syscall_getsockname(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] getsockname: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->getsockname(socket, addr, addrlen);
}

void syscall_getpeername(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] getpeername: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->getpeername(socket, addr, addrlen);
}

void syscall_listen(struct registers *regs) {
	int sockfd = regs->rdi;
	int backlog = regs->rsi;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] listen: sockfd {%x}, backlog {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, backlog);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->listen(socket, backlog);
}

void syscall_accept(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] accept: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->accept(socket, addr, addrlen, fd_handle->flags);
}

void syscall_bind(struct registers *regs) {
	int sockfd = regs->rdi;
	const struct socketaddr *addr = (void*)regs->rsi;
	socklen_t addrlen = regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] bind: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->bind(socket, addr, addrlen);
}

void syscall_sendmsg(struct registers *regs) {
	int sockfd = regs->rdi;
	struct msghdr *msg = (void*)regs->rsi;
	int flags = regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] sendmsg: sockfd {%x}, msg {%x}, flags {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, msg, flags);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socketaddr *dest = msg->msg_name;
	socklen_t addrlen = msg->msg_namelen;

	struct socket *socket = fd_handle->file_handle->private_data;
	struct socket *peer = socket->peer;

	print("socket: %x | peer %x\n", socket, peer);

	if(socket->state != SOCKET_CONNECTED || peer == NULL) {
		set_errno(ENOTCONN);
		regs->rax = -1;
		return;
	}

	if(socket->type == SOCK_STREAM || socket->type == SOCK_SEQPACKET) {
		if(dest || addrlen) {
			set_errno(EISCONN);
			regs->rax = -1;
			return;
		}
	}

	regs->rax = socket->ops->sendmsg(socket, msg, flags);
}

void syscall_recvmsg(struct registers *regs) {
	int sockfd = regs->rdi;
	struct msghdr *msg = (void*)regs->rsi; 
	int flags = regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] recvmsg: sockfd {%x}, msg {%x}, flags {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, msg, flags);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socketaddr *src = msg->msg_name;
	socklen_t addrlen = msg->msg_namelen;

	struct socket *socket = fd_handle->file_handle->private_data;
	struct socket *peer = socket->peer;

	if(peer->state != SOCKET_CONNECTED || peer == NULL) {
		set_errno(EDESTADDRREQ);
		regs->rax = -1;
		return;
	}

	if(src && addrlen) {
		if(socket->ops->getsockname(peer, src, &addrlen) == -1) {
			regs->rax = -1;
			return;
		}
	}

	regs->rax = socket->ops->recvmsg(socket, msg, flags);
}

void syscall_connect(struct registers *regs) {
	int sockfd = regs->rdi;
	const struct socketaddr *addr = (void*)regs->rsi;
	socklen_t addrlen = regs->rdx;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] connect: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = search_socket(sockfd);
	if(fd_handle == NULL) {
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->ops->connect(socket, addr, addrlen, fd_handle->flags);
}

void syscall_getsockopt(struct registers *regs) {
	int sockfd = regs->rdi;
	int level = regs->rsi;
	int optname = regs->rdx;
	void *optval = (void*)regs->r10;
	socklen_t *optlen = (void*)regs->r8;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] getsockopt: sockfd {%x}, level {%x}, optname {%x}, optval {%x}, optlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, level, optname, optval, optlen);
#endif

	regs->rax = 0;
}

void syscall_setsockopt(struct registers *regs) {
	int sockfd = regs->rdi;
	int level = regs->rsi;
	int optname = regs->rdx;
	void *optval = (void*)regs->r10;
	socklen_t optlen = regs->r8;

#if defined(SYSCALL_DEBUG_SOCKET) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] setsockopt: sockfd {%x}, level {%x}, optname {%x}, optval {%x}, optlen {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sockfd, level, optname, optval, optlen);
#endif

	regs->rax = 0;
}


