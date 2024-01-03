#include <sched/futex.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>

static struct hash_table futex_list;

int futex(uintptr_t uaddr, int ops, int expected, const struct timespec *timeout) {
	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	uint64_t uaddr_page = uaddr & ~(0xfff);
	struct page *page = hash_table_search(task->page_table->pages, &uaddr_page, sizeof(uaddr_page));
	if(page == NULL) {
		set_errno(EFAULT);
		return -1;
	}

	uint64_t futex_paddr = page->frame->addr + (uaddr & (0xfff));

	switch(ops) {
		case FUTEX_WAIT: {
			if(*(uint32_t*)uaddr != expected) {
				set_errno(EAGAIN);
				return -1;
			}

			struct futex *futex = hash_table_search(&futex_list, &futex_paddr, sizeof(futex_paddr));
			if(futex == NULL) {
				futex = alloc(sizeof(struct futex));

				futex->paddr = futex_paddr;

				hash_table_push(&futex_list, &futex->paddr, futex, sizeof(futex->paddr));
				VECTOR_PUSH(page->frame->locks, futex);
			}

			futex->expected = expected;
			futex->operation = ops;
			futex->paddr = futex_paddr;

			if(timeout) {
				waitq_set_timer(&futex->waitq, timeout);
			}

			futex->trigger = waitq_alloc(&futex->waitq, EVENT_LOCK);
			waitq_add(&futex->waitq, futex->trigger);

			waitq_wait(&futex->waitq, EVENT_LOCK);
			waitq_release(&futex->waitq, EVENT_LOCK);

			waitq_remove(&futex->waitq, futex->trigger);

			break;
		}
		case FUTEX_WAKE: {
			struct futex *futex = hash_table_search(&futex_list, &futex_paddr, sizeof(futex_paddr));
			if(futex == NULL) {
				return 0;
			}

			hash_table_delete(&futex_list, &futex_paddr, sizeof(futex_paddr));

			waitq_wake(futex->trigger);

			break;
		}
		default:
			set_errno(EINVAL);
			return -1;
	}

	return 0;
}

void syscall_futex(struct registers *regs) {
	uint32_t *uaddr = (void*)regs->rdi;
	int op = regs->rsi;
	uint32_t val = regs->rdx; 
	const struct timespec *timeout = (void*)regs->r10;

#if defined(SYSCALL_SCHED_DEBUG)
	print("syscall: [pid %x, tid %x] futex: uaddr {%x}, op {%x}, val {%x}, timeout {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, uaddr, op, val, timeout);
#endif

	regs->rax = futex((uintptr_t)uaddr, op, val, timeout);
}
