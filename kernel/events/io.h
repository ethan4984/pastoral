#include <stdbool.h>
#include <stddef.h>

#define POLLIN 0x01
#define POLLOUT 0x02
#define POLLPRI 0x04
#define POLLHUP 0x08
#define POLLERR 0x10
#define POLLRDHUP 0x20
#define POLLNVAL 0x40
#define POLLWRNORM 0x80

/*	ideally I want a system that would function like this:
 *		within the socket struct, will contain an io monitor
 *
 *		io_wait(socket->monitor, connection);
 *		io_wait(socket->monitor, read);
 *
 *		io_set(socket->monitor, connection); 
 *		io_set(socket->monitor, read); 
 */

struct io_monitor {
	struct waitq *waitq;
	struct waitq_trigger *trigger;
	int *events;

	void (*cleanup)();
	void (*init)();

	bool blocking;
};

struct io_event {
	int events;
	bool exclusive;
};

int io_wait(struct io_monitor *monitor, struct io_event *event);
int io_release(struct io_monitor *monitor, int events);
int io_set(struct io_monitor *monitor, int event);
