#include <fs/socket.h>
#include <fs/ramfs.h>
#include <fs/fd.h>
#include <errno.h>
#include <debug.h>

static ssize_t socket_read(struct file_handle *file, void *buf, size_t cnt, off_t offset);
static ssize_t socket_write(struct file_handle *file, const void *buf, size_t cnt, off_t offset);
static int socket_ioctl(struct file_handle *file, uint64_t req, void *arg);

static int unix_bind(struct socket *socket, const struct socketaddr *addr, socklen_t length);
static int unix_getsockname(struct socket *socket, struct socketaddr *addr, socklen_t *length);
static int unix_getpeername(struct socket *socket, struct socketaddr *addr, socklen_t *length);
static int unix_listen(struct socket *socket, int backlog);
static int unix_accept(struct socket *socket, struct socketaddr *addr, socklen_t *length);
static int unix_connect(struct socket *socket, const struct socketaddr *addr, socklen_t length);
static int unix_recvfrom(struct socket *socket, struct socket *target, void *buffer, size_t len, int flags);
static int unix_sendto(struct socket *socket, struct socket *target, const void *buffer, size_t len, int flags);

static struct file_ops socket_file_ops = {
	.read = socket_read,
	.write = socket_write,
	.ioctl = socket_ioctl
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
			socket->bind = unix_bind;
			socket->connect = unix_connect;
			socket->sendto = unix_sendto;
			socket->recvfrom = unix_recvfrom;
			socket->getsockname = unix_getsockname;
			socket->getpeername = unix_getpeername;
			socket->accept = unix_accept;
			socket->listen = unix_listen;

			socket->addr = alloc(sizeof(struct socketaddr_un));
			socket->family = AF_UNIX;
			socket->stream_ops = &ramfs_fops;

			break;
		case AF_NETLINK:
			socket->bind = NULL;
			socket->connect = NULL;
			socket->sendto = NULL;
			socket->recvfrom = NULL;
			socket->getsockname = NULL;
			socket->getpeername = NULL;
			socket->accept = NULL;
			socket->listen = NULL;

			socket->addr = alloc(sizeof(struct socketaddr_un));
			socket->family = AF_UNIX;

			break;
		default:
			set_errno(EINVAL);
			return NULL;
	};

	return socket;
}

void syscall_socket(struct registers *regs) {
	int family = regs->rdi;
	int type = regs->rsi;
	int protocol = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] socket: family {%x}, type {%x}, protocol {%x}\n", CORE_LOCAL->pid, family, type, protocol);
#endif

	struct socket *socket = socket_create(family, type, protocol);
	if(socket == NULL) {
		regs->rax = -1;
		return;
	}

	struct fd_handle *socket_fd_handle = alloc(sizeof(struct fd_handle));
	struct file_handle *socket_file_handle = alloc(sizeof(struct file_handle));
	fd_init(socket_fd_handle);
	file_init(socket_file_handle);

	socket_file_handle->ops = &socket_file_ops;
	socket_file_handle->private_data = socket;
	socket_file_handle->stat = alloc(sizeof(struct stat));
	socket_file_handle->stat->st_mode = S_IFSOCK;
	socket_file_handle->flags |= O_RDWR;
	
	ramfs_create_dangle(socket_file_handle->stat);

	socket_fd_handle->file_handle = socket_file_handle;
	socket_fd_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap);

	socket->fd_handle = socket_fd_handle;

	stat_update_time(socket_file_handle->stat, STAT_ACCESS | STAT_MOD | STAT_STATUS);

	spinlock_irqsave(&CURRENT_TASK->fd_lock);
	hash_table_push(&CURRENT_TASK->fd_list, &socket_fd_handle->fd_number, socket_fd_handle, sizeof(socket_fd_handle->fd_number));
	spinrelease_irqsave(&CURRENT_TASK->fd_lock);

	regs->rax = socket_fd_handle->fd_number;
}

void syscall_getsockname(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getsockname: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->getsockname(socket, addr, addrlen);
}

void syscall_getpeername(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getpeername: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->getpeername(socket, addr, addrlen);
}

void syscall_listen(struct registers *regs) {
	int sockfd = regs->rdi;
	int backlog = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] backlog: sockfd {%x}, backlog {%x}\n", CORE_LOCAL->pid, sockfd, backlog);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->listen(socket, backlog);
}

void syscall_accept(struct registers *regs) {
	int sockfd = regs->rdi;
	struct socketaddr *addr = (void*)regs->rsi;
	socklen_t *addrlen = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] accept: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->accept(socket, addr, addrlen);
}

void syscall_bind(struct registers *regs) {
	int sockfd = regs->rdi;
	const struct socketaddr *addr = (void*)regs->rsi;
	socklen_t addrlen = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] bind: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->bind(socket, addr, addrlen);
}

void syscall_sendto(struct registers *regs) {
	int sockfd = regs->rdi;
	const void *buf = (void*)regs->rsi;
	size_t len = regs->rdx;
	int flags = regs->r10;
	const struct sockaddr *dest = (void*)regs->r10;
	socklen_t addrlen = regs->r9;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] sendto: sockfd {%x}, buf {%x}, len {%x}, flags {%x}, dest {%x}, addrlen {%x}\n", sockfd, buf, len, flags, dest, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	struct socket *peer = socket->peer;

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

	regs->rax = socket->sendto(socket, peer, buf, len, flags);
}

void syscall_recvfrom(struct registers *regs) {
	int sockfd = regs->rdi;
	void *buf = (void*)regs->rsi;
	size_t len = regs->rdx;
	int flags = regs->r10;
	struct socketaddr *src = (void*)regs->r10;
	socklen_t *addrlen = (void*)regs->r9;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] recvfrom: sockfd {%x}, buf {%x}, len {%x}, flags {%x}, src {%x}, addrlen {%x}\n", sockfd, buf, len, flags, src, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	struct socket *peer = socket->peer;

	if(socket->state != SOCKET_CONNECTED || peer == NULL) {
		set_errno(EDESTADDRREQ);
		regs->rax = -1;
		return;
	}

	if(src && addrlen) {
		if(socket->getsockname(peer, src, addrlen) == -1) {
			regs->rax = -1;
			return;
		}
	}

	regs->rax = socket->recvfrom(socket, peer, buf, len, flags);
}

void syscall_connect(struct registers *regs) {
	int sockfd = regs->rdi;
	const struct socketaddr *addr = (void*)regs->rsi;
	socklen_t addrlen = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] bind: sockfd {%x}, addr {%x}, addrlen {%x}\n", CORE_LOCAL->pid, sockfd, addr, addrlen);
#endif

	struct fd_handle *fd_handle = fd_translate(sockfd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct stat *stat = fd_handle->file_handle->stat;
	if(!S_ISSOCK(stat->st_mode)) {
		set_errno(ENOTSOCK);
		regs->rax = -1;
		return;
	}

	struct socket *socket = fd_handle->file_handle->private_data;
	regs->rax = socket->connect(socket, addr, addrlen);
}

static struct hash_table unix_addr_table;

static int unix_validate_address(struct socketaddr_un *addr, socklen_t length) {
	if((length > sizeof(struct socketaddr_un) ||
			length <= offsetof(struct socketaddr_un, sun_path)) &&
			addr->sun_family != AF_UNIX) {
		set_errno(EINVAL);
		return -1;
	}

	return 0;
}

static struct socket *unix_search_address(struct socketaddr_un *addr, socklen_t length) {
	if(unix_validate_address(addr, length) == -1) {
		return NULL;
	}

	struct socket *socket = hash_table_search(&unix_addr_table, addr, sizeof(struct socketaddr_un));

	return socket; 
}

static int unix_bind(struct socket *socket, const struct socketaddr *socketaddr, socklen_t length) {
	spinlock_irqsave(&socket->lock);

	struct socketaddr_un *socketaddr_un = (void*)socketaddr;

	if(unix_validate_address(socketaddr_un, length) == -1) {
		spinrelease_irqsave(&socket->lock);
		return -1;
	}

	if(socket->state == SOCKET_CONNECTED || socket->state == SOCKET_CONNECTING) {
		set_errno(EINVAL);
		return -1;
	}

	if(unix_search_address(socketaddr_un, length)) {
		set_errno(EADDRINUSE);
		return -1;
	}

	*(struct socketaddr_un*)socket->addr = *socketaddr_un;

	hash_table_push(&unix_addr_table, socket->addr, socket, sizeof(struct socketaddr_un));

	spinrelease_irqsave(&socket->lock);

	return 0;
}

static int unix_listen(struct socket *socket, int backlog) {
	if(socket->type != SOCK_STREAM && socket->type != SOCK_SEQPACKET) {
		set_errno(EOPNOTSUPP);
		return -1;
	}

	socket->state = SOCKET_PASSIVE;
	socket->backlog_max = backlog;
	VECTOR_CLEAR(socket->backlog);

	return 0;
}

static int unix_accept(struct socket *socket, struct socketaddr *addr, socklen_t *length) {
	if(socket->type != SOCK_STREAM && socket->type != SOCK_SEQPACKET) {
		set_errno(EOPNOTSUPP);
		return -1;
	}

	if((socket->fd_handle->flags & O_NONBLOCK) == O_NONBLOCK) {
		goto handle;
	}

	socket->trigger = waitq_alloc(&socket->waitq, EVENT_SOCKET);
	waitq_add(&socket->waitq, socket->trigger);

	int ret = waitq_wait(&socket->waitq, EVENT_SOCKET);
	waitq_release(&socket->waitq, EVENT_SOCKET);

	if(ret == -1) {
		return -1;
	}
handle:
	struct socket *peer;

	if(VECTOR_POP(socket->backlog, peer) == -1) {
		set_errno(EAGAIN);
		return -1;
	}

	if(addr && length) {
		ret = unix_getsockname(peer, addr, length);
		if(ret == -1) {
			return -1;
		}
	}

	socket->state = SOCKET_CONNECTED;
	peer->peer = socket;

	waitq_remove(&socket->waitq, socket->trigger);

	return 0; 
}

static int unix_connect(struct socket *socket, const struct socketaddr *addr, socklen_t length) {
	spinlock_irqsave(&socket->lock);

	struct socketaddr_un *socketaddr_un = (void*)addr;

	if(unix_validate_address(socketaddr_un, length) == -1) {
		return -1;
	}

	if(socket->state == SOCKET_CONNECTED || socket->state == SOCKET_CONNECTING) {
		set_errno(EISCONN);
		return -1;
	}

	struct socket *target_socket = unix_search_address(socketaddr_un, length);
	if(target_socket == NULL) {
		set_errno(EAFNOSUPPORT);
		return -1;
	}

	target_socket->peer = socket;
	target_socket->state = SOCKET_CONNECTED;

	if((socket->fd_handle->flags & O_NONBLOCK) != O_NONBLOCK) {
		waitq_wake(target_socket->trigger);	
	}

	VECTOR_PUSH(target_socket->backlog, socket);

	spinrelease_irqsave(&socket->lock);

	return 0;
}

static int unix_getsockname(struct socket *socket, struct socketaddr *_ret, socklen_t *length) {
	spinlock_irqsave(&socket->lock);

	socklen_t len = *length; 

	if(!len) {
		set_errno(EINVAL);
		return -1;
	}

	struct socketaddr_un *addr = (void*)socket->addr;
	struct socketaddr_un *ret = (void*)_ret;

	ret->sun_family = addr->sun_family;
	len -= sizeof(ret->sun_family);

	for(size_t i = 0; i < len; i++) {
		ret->sun_path[i] = addr->sun_path[i];
	}

	*length = sizeof(sa_family_t) + strlen(addr->sun_path);

	spinrelease_irqsave(&socket->lock);

	return 0;
}

static int unix_getpeername(struct socket *socket, struct socketaddr *_ret, socklen_t *length) {
	spinlock_irqsave(&socket->lock);

	if(socket->state != SOCKET_CONNECTED) {
		set_errno(ENOTCONN);
		return -1;
	}

	socklen_t len = *length; 

	if(!len) {
		set_errno(EINVAL);
		return -1;
	}

	struct socketaddr_un *peer_addr = (void*)socket->peer->addr;
	struct socketaddr_un *ret = (void*)_ret;

	ret->sun_family = peer_addr->sun_family;
	len -= sizeof(ret->sun_family);

	for(size_t i = 0; i < len; i++) {
		ret->sun_path[i] = peer_addr->sun_path[i];
	}

	*length = sizeof(sa_family_t) + strlen(peer_addr->sun_path);

	spinrelease_irqsave(&socket->lock);

	return 0;
}

static int unix_sendto(struct socket*, struct socket *target, const void *buffer, size_t len, int) {
	struct file_handle *file_handle = target->file_handle;

	ssize_t ret = target->stream_ops->write(file_handle, buffer, len, file_handle->stat->st_size);

	if((target->fd_handle->flags & O_NONBLOCK) != O_NONBLOCK) {
		waitq_wake(file_handle->trigger);
	}

	return ret;
}

static int unix_recvfrom(struct socket*, struct socket *target, void *buffer, size_t len, int) {
	struct file_handle *file_handle = target->file_handle;

	if((target->fd_handle->flags & O_NONBLOCK) == O_NONBLOCK) {
		goto handle;
	}

	file_handle->trigger = waitq_alloc(&file_handle->waitq, EVENT_WRITE);
	waitq_add(&file_handle->waitq, file_handle->trigger);

	ssize_t ret = waitq_wait(&file_handle->waitq, EVENT_WRITE);
	waitq_release(&file_handle->waitq, EVENT_WRITE);

	if(ret == -1) {
		return -1;
	}
handle:
	ret = target->stream_ops->read(file_handle, buffer, len, file_handle->stat->st_size);

	waitq_remove(&file_handle->waitq, file_handle->trigger);

	return ret;
}

static ssize_t socket_read(struct file_handle *handle, void *buf, size_t cnt, off_t) {
	struct socket *socket = handle->private_data;
	struct socket *peer = socket->peer;

	if(socket->state != SOCKET_CONNECTED) {
		// TODO block until connected
		set_errno(EDESTADDRREQ);
		return -1;
	}

	return socket->recvfrom(socket, peer, buf, cnt, 0); 
}

static ssize_t socket_write(struct file_handle *handle, const void *buf, size_t cnt, off_t) {
	struct socket *socket = handle->private_data;
	struct socket *peer = socket->peer;

	if(socket->state != SOCKET_CONNECTED) {
		// TODO block until connected
		set_errno(EDESTADDRREQ);
		return -1;
	}

	return socket->sendto(socket, peer, buf, cnt, 0); 
}

static int socket_ioctl(struct file_handle*, uint64_t, void*) {
	return -1; 
}
