#pragma once

#include <types.h>

#define SOCKET_CONNECTED 0
#define SOCKET_UNCONNECTED 1
#define SOCKET_CONNECTING 2
#define SOCKET_DISCONNECTING 3
#define SOCKET_PASSIVE 4

#define AF_LOCAL 1
#define AF_UNIX AF_LOCAL
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5

typedef unsigned short sa_family_t;
typedef int socklen_t;

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

	struct socket *peer;
	VECTOR(struct socket*) backlog;
	int backlog_max;

	struct file_handle *file_handle;

	char lock;
};
