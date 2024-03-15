#include <sched/sched.h>
#include <events/queue.h>
#include <events/io.h>

static bool io_check_events(struct io_event *io_event, int *events) {
	if(io_event == NULL || events == NULL) {
		return false;
	}

	if(io_event->exclusive) {
		return (*events & io_event->events) ? true : false;
	} else {
		return ((*events & io_event->events) == io_event->events) ? true : false;
	}
}

int io_wait(struct io_monitor *monitor, struct io_event *io_event) {
	if(monitor == NULL || monitor->events == NULL) {
		return -1;
	}

	for(;;) {
		if(monitor->init) {
			monitor->init();
		}

		if(io_check_events(io_event, monitor->events)) {
			break;
		}

		if(!monitor->blocking) {
			break;
		}	

		int ret = waitq_block(monitor->waitq, NULL);
		if(ret == -1) {
			return -1;
		}
	}

	if(monitor->cleanup) {
		monitor->cleanup();
	}

	return 0;
}

int io_release(struct io_monitor *monitor, int events) {
	if(monitor == NULL) {
		return -1;
	}

	*monitor->events &= ~events;
	waitq_arise(monitor->trigger, CURRENT_TASK);

	return 0;
}

int io_set(struct io_monitor *monitor, int events) {
	if(monitor == NULL) {
		return -1;
	}

	*monitor->events |= events;
	waitq_arise(monitor->trigger, CURRENT_TASK);

	return 0;
}
