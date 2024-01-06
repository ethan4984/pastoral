#pragma once

#include <types.h>
#include <vector.h>
#include <sched/queue.h>
#include <lock.h>
#include <cpu.h>

#define SIG_ERR ((void*)-1)
#define SIG_DFL ((void*)0)
#define SIG_IGN ((void*)1)

#define SIGABRT 6
#define SIGFPE 8
#define SIGILL 4
#define SIGINT 2
#define SIGSEGV 11
#define SIGTERM 15
#define SIGPROF 27
#define SIGIO 29
#define SIGPWR 30
#define SIGRTMIN 35
#define SIGRTMAX 64

#define SIGHUP    1
#define SIGQUIT   3
#define SIGTRAP   5
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGKILL   9
#define SIGUSR1   10
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGWINCH  28
#define SIGPOLL   29
#define SIGSYS    31
#define SIGUNUSED SIGSYS
#define SIGCANCEL 32

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SA_RESTORER 0x04000000

#define SIGNAL_MAX 32

#define SIGMASK(SIG) (1ull << ((SIG) - 1))

union sigval {
	int sival_int;
	void *sival_ptr;
};

struct siginfo {
	int si_signo;
	int si_code;
	int si_errno;
	pid_t si_pid;
	uid_t si_uid;
	void *si_addr;
	int si_status;
	union sigval si_value;
};

struct sigaction {
	union {
		void (*sa_handler)(int signum);
		void (*sa_sigaction)(int signum, struct siginfo *siginfo, void *context);
	} handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer);
};

struct ucontext {
	uint64_t flags;
	struct ucontext *link;
	struct stack stack;
	struct registers registers;
	sigset_t signum;
};

struct signal_queue;
struct event_trigger;

struct signal {
	int refcnt;
	int signum;

	struct siginfo *siginfo;
	//struct sigaction *sigaction;

	struct waitq_trigger *trigger;

	struct signal_queue *queue;
};

struct task;

struct signal_queue {
	struct spinlock siglock;
	sigset_t sigmask;

	struct signal queue[SIGNAL_MAX];
	sigset_t sigpending;
	sigset_t sigdelivered;
	bool active;

	struct waitq waitq;

	struct task *task;
};

struct process_group;

int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int sigpending(sigset_t *set);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int signal_send_task(struct task *sender, struct task *target, int sig);
int signal_send_group(struct task *sender, struct process_group *target, int sig);
int signal_check_permissions(struct task *sender, struct task *target);
int signal_is_valid(int sig);
int signal_dispatch(struct task *task, struct registers *state);

int signal_is_blocked(struct task *task, int sig);
int signal_is_ignored(struct task *task, int sig);
