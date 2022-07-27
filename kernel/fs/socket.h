#pragma once

#include <sched/queue.h>
#include <types.h>

#define SOCKET_CONNECTED 0
#define SOCKET_UNCONNECTED 1
#define SOCKET_CONNECTING 2
#define SOCKET_DISCONNECTING 3
#define SOCKET_PASSIVE 4

#define PF_INET 1
#define PF_INET6 2
#define PF_UNIX 3
#define PF_LOCAL 3
#define PF_UNSPEC 4
#define PF_NETLINK 5
#define PF_BRIDGE 6
#define PF_APPLETALK 7
#define PF_BLUETOOTH 8
#define PF_DECnet 9
#define PF_IPX 10
#define PF_ISDN 11
#define PF_SNA 12
#define PF_PACKET 13

#define AF_INET PF_INET
#define AF_INET6 PF_INET6
#define AF_UNIX PF_UNIX
#define AF_LOCAL PF_LOCAL
#define AF_UNSPEC PF_UNSPEC
#define AF_NETLINK PF_NETLINK
#define AF_BRIDGE PF_BRIDGE
#define AF_PACKET PF_PACKET

#define SOCK_DGRAM 1
#define SOCK_RAW 2
#define SOCK_SEQPACKET 3
#define SOCK_STREAM 4
#define SOCK_NONBLOCK 0x10000
#define SOCK_CLOEXEC 0x20000
#define SOCK_RDM 0x40000

typedef unsigned int sa_family_t;
typedef unsigned long socklen_t;

struct socketaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct socketaddr_un {
	sa_family_t sun_family;
	char sun_path[108];
};

struct socket {
	int family;
	int type;
	int protocol;
	int state;

	struct socketaddr *addr;

	int (*bind)(struct socket*, const struct socketaddr*, socklen_t);
	int (*connect)(struct socket*, const struct socketaddr*, socklen_t);
	int (*sendto)(struct socket*, struct socket*, const void*, size_t, int);
	int (*recvform)(struct socket*, struct socket*, void*, size_t, int);
	int (*getsockname)(struct socket*, struct socketaddr*, socklen_t*);
	int (*getpeername)(struct socket*, struct socketaddr*, socklen_t*);
	int (*accept)(struct socket*, struct socketaddr*, socklen_t*);
	int (*listen)(struct socket*, int);

	struct waitq waitq;
	struct waitq_trigger *trigger;

	struct socket *peer;
	VECTOR(struct socket*) backlog;
	int backlog_max;

	struct file_handle *file_handle;
	struct fd_handle *fd_handle;

	char lock;
};
