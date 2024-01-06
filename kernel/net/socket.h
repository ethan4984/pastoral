#pragma once

#include <sched/queue.h>
#include <types.h>
#include <lock.h>

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

#define MSG_CTRUNC 0x1
#define MSG_DONTROUTE 0x2
#define MSG_EOR 0x4
#define MSG_OOB 0x8
#define MSG_NOSIGNAL 0x10
#define MSG_PEEK 0x20
#define MSG_TRUNC 0x40
#define MSG_WAITALL 0x80
#define MSG_CONFIRM 0x800

#define MSG_DONTWAIT 0x1000
#define MSG_CMSG_CLOEXEC 0x2000

typedef unsigned int sa_family_t;
typedef unsigned int socklen_t;

struct socketaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct socketaddr_un {
	sa_family_t sun_family;
	char sun_path[108];
};

struct iovec {
	void *iov_base;
	size_t iov_len;
};

struct msghdr {
	void *msg_name;
	socklen_t msg_namelen;
	struct iovec *msg_iov;
	int msg_iovlen;
	void *msg_control; 
	socklen_t msg_controllen;
	int msg_flags;
};

struct socket {
	int family;
	int type;
	int protocol;
	int state;

	struct socketaddr *addr;

	int (*bind)(struct socket*, const struct socketaddr*, socklen_t);
	int (*connect)(struct socket*, const struct socketaddr*, socklen_t, int);
	int (*sendmsg)(struct socket*, const struct msghdr*, int);
	int (*recvmsg)(struct socket*, struct msghdr*, int);
	int (*getsockname)(struct socket*, struct socketaddr*, socklen_t*);
	int (*getpeername)(struct socket*, struct socketaddr*, socklen_t*);
	int (*accept)(struct socket*, struct socketaddr*, socklen_t*, int);
	int (*listen)(struct socket*, int);

	struct socket *peer;
	VECTOR(struct socket*) backlog;
	int backlog_max;

	struct file_handle *file_handle;
	struct file_ops *stream_ops;

	struct spinlock lock;
};
