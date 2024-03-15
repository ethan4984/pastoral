#include <net/socket.h>
#include <fs/ramfs.h>
#include <fs/fd.h>
#include <errno.h>
#include <debug.h>
#include <events/io.h>

static int unix_bind(struct socket *socket, const struct socketaddr *addr, socklen_t length);
static int unix_getsockname(struct socket *socket, struct socketaddr *addr, socklen_t *length);
static int unix_getpeername(struct socket *socket, struct socketaddr *addr, socklen_t *length);
static int unix_listen(struct socket *socket, int backlog);
static int unix_accept(struct socket *socket, struct socketaddr *addr, socklen_t *length, int flags);
static int unix_connect(struct socket *socket, const struct socketaddr *addr, socklen_t length, int flags);
static int unix_recvmsg(struct socket *socket, struct msghdr *msg, int flags);
static int unix_sendmsg(struct socket *socket, const struct msghdr *msg, int flags);
static int unix_close(struct socket *socket);

struct socket_ops unix_ops = (struct socket_ops) {
	.bind = unix_bind,
	.getsockname = unix_getsockname,
	.getpeername = unix_getpeername,
	.listen = unix_listen,
	.accept = unix_accept,
	.connect = unix_connect,
	.recvmsg = unix_recvmsg,
	.sendmsg = unix_sendmsg,
	.close = unix_close
};

#define SOCKET_IO_MONITOR(SOCKET, BLOCKING) ({ \
	(struct io_monitor) { \
		.waitq = &(SOCKET)->file_handle->waitq, \
		.events = &(SOCKET)->file_handle->status, \
		.trigger = (SOCKET)->file_handle->trigger, \
		.cleanup = NULL, \
		.init = NULL, \
		.blocking = BLOCKING \
	}; \
})

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

	struct socket *socket = hash_table_search(&unix_addr_table, addr->sun_path, strlen(addr->sun_path));

	return socket; 
}

static int unix_bind(struct socket *socket, const struct socketaddr *socketaddr, socklen_t length) {
	struct socketaddr_un *socketaddr_un = (void*)socketaddr;

	if(unix_validate_address(socketaddr_un, length) == -1) {
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

	char *path = alloc(strlen(socketaddr_un->sun_path));
	strcpy(path, socketaddr_un->sun_path);

	while(*path == '/') path++;

	int cutoff = find_last_char(path, '/');
	const char *name; 
	const char *dirpath;

	if(cutoff == -1) {
		name = path; 
		dirpath = "./";
	} else {
		name = path + cutoff + 1;
		dirpath = path;
		path[cutoff] = '\0';
	}

	struct vfs_node *path_parent;
	if(user_lookup_at(AT_FDCWD, dirpath, AT_SYMLINK_FOLLOW, X_OK, &path_parent) == -1) {
		return -1;
	}

	struct vfs_node *path_node = vfs_search_relative(path_parent, name, false);
	if(path_node == NULL) {
		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat); 
		stat->st_mode = S_IFSOCK;
		stat->st_uid = CURRENT_TASK->effective_uid;

		if((path_parent->stat->st_mode & S_ISGID) == S_ISGID) {
			stat->st_gid = path_parent->stat->st_gid;
		} else {
			stat->st_gid = CURRENT_TASK->effective_gid;
		}

		path_node = vfs_create(path_parent, name, stat);
	}

	socket->file_handle->vfs_node = path_node;

	*(struct socketaddr_un*)socket->addr = *socketaddr_un;

	hash_table_push(&unix_addr_table, socketaddr_un->sun_path, socket, strlen(socketaddr_un->sun_path));

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

static int unix_accept(struct socket *socket, struct socketaddr *addr, socklen_t *length, int flags) {
	if(socket->type != SOCK_STREAM && socket->type != SOCK_SEQPACKET) {
		set_errno(EOPNOTSUPP);
		return -1;
	}

	struct io_monitor monitor = SOCKET_IO_MONITOR(socket, (flags & O_NONBLOCK) == O_NONBLOCK);
	struct io_event connection = (struct io_event) {
		.events = POLLIN,
		.exclusive = true
	};

	int ret = io_wait(&monitor, &connection);
	if(ret == -1) return -1;

	struct socket *peer;

	if(VECTOR_POP(socket->backlog, peer) == -1) {
		set_errno(EAGAIN);
		return -1;
	}

	if(!socket->backlog.length) {
		io_release(&monitor, POLLIN);
	}

	VECTOR_PUSH(socket->backlog, peer);

	if(addr && length) {
		ret = unix_getsockname(peer, addr, length);
		if(ret == -1) {
			return -1;
		}
	}

	socket->peer = peer;

	struct io_monitor peer_monitor = SOCKET_IO_MONITOR(socket->peer, (flags & O_NONBLOCK) != O_NONBLOCK);
	io_set(&peer_monitor, POLLOUT);
	
	socket->state = SOCKET_CONNECTED;
	peer->state = SOCKET_CONNECTED;

	struct fd_handle *socket_fd_handle = create_sockfd(peer, peer->file_handle);
	
	return socket_fd_handle->fd_number;
}

static int unix_connect(struct socket *socket, const struct socketaddr *addr, socklen_t length, int flags) {
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

	VECTOR_PUSH(target_socket->backlog, socket);

	socket->peer = target_socket;
	socket->state = SOCKET_CONNECTING;

	struct io_monitor monitor = SOCKET_IO_MONITOR(socket, (flags & O_NONBLOCK) != O_NONBLOCK);
	struct io_monitor peer_monitor = SOCKET_IO_MONITOR(socket->peer, (flags & O_NONBLOCK) != O_NONBLOCK);

	struct io_event connection = (struct io_event) {
		.events = POLLOUT,
		.exclusive = true
	};

	io_set(&peer_monitor, POLLIN);

	int ret = io_wait(&monitor, &connection);
	if(ret == -1) return -1;

	io_set(&monitor, POLLOUT);

	if(socket->state != SOCKET_CONNECTING) {
		set_errno(EHOSTUNREACH);
		return 0;
	}

	socket->state = SOCKET_CONNECTED;

	return 0;
}

static int unix_getsockname(struct socket *socket, struct socketaddr *_ret, socklen_t *length) {
	//spinlock_irqsave(&socket->lock);

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

	//spinrelease_irqsave(&socket->lock);

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

static int unix_sendmsg(struct socket *socket, const struct msghdr *msg, int flags) {
	struct file_handle *file_handle = socket->peer->file_handle;

	struct io_monitor peer_monitor = SOCKET_IO_MONITOR(socket, (flags & MSG_DONTWAIT) == MSG_DONTWAIT);

	void *bufferbase = msg->msg_iov[0].iov_base;
	size_t transfer_size = msg->msg_iov[0].iov_len;

	ssize_t ret = socket->peer->stream_ops->write(file_handle, bufferbase, transfer_size, file_handle->stat->st_size);

	file_handle->stat->st_size += ret;
	file_handle->position += ret;

	print("waking file hande %x %x\n", socket->file_handle, socket->peer->file_handle);

	io_set(&peer_monitor, POLLIN);

	return ret;
}

static int unix_recvmsg(struct socket *socket, struct msghdr *msg, int flags) {
	struct file_handle *file_handle = socket->peer->file_handle;
	off_t offset = file_handle->position;

	struct io_monitor monitor = SOCKET_IO_MONITOR(socket->peer, (flags & MSG_DONTWAIT) != MSG_DONTWAIT);
	struct io_event data_to_read = {
		.events = POLLIN,
		.exclusive = true
	};

	int ret = io_wait(&monitor, &data_to_read);
	if(ret == -1) return -1;

	for(int i = 0; i < msg->msg_iovlen; i++) {
		void *bufferbase = msg->msg_iov[i].iov_base;
		size_t transfer_size = msg->msg_iov[i].iov_len;

		print("recvmsg %x %x %x %x %x\n", file_handle, bufferbase, transfer_size, offset, file_handle->stat->st_size);
		ret = socket->stream_ops->read(file_handle, bufferbase, transfer_size, offset);

		if(!ret) {
			set_errno(EAGAIN);
			ret = -1;
			break;
		}

		offset += ret;
	}

	if(file_handle->position >= file_handle->stat->st_size) {
		io_release(&monitor, POLLIN);
	}

	return ret;
}

static int unix_close(struct socket *socket) {
	if(socket == NULL) {
		return -1;
	}

	if(socket->addr) {
		hash_table_delete(&unix_addr_table, socket->addr, sizeof(struct socketaddr_un));
	}

	return 0;
}
