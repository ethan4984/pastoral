#include <fs/fd.h>
#include <fs/cdev.h> 
#include <debug.h>
#include <drivers/random.h>

static ssize_t urandom_read(struct file_handle *file, void *buf, size_t cnt, off_t off);
static ssize_t urandom_write(struct file_handle *file, const void *buf, size_t cnt, off_t off);
static int urandom_ioctl(struct file_handle *file, uint64_t req, void *args);

static struct file_ops urandom_ops = {
	.read = urandom_read, 
	.write = urandom_write,
	.ioctl = urandom_ioctl
};

struct {
	uint8_t *pool;
	size_t incr;
	size_t size;

	uint64_t (*rand)();
	struct spinlock lock;
} entropy;

int entropy_push(void *data, size_t data_size) {
	uint64_t hash = fnv_hash(data, data_size);
	uint64_t randomness = fnv_hash((void*)&hash, sizeof(hash));

	if(entropy.pool == NULL || entropy.size == 0) {
		return 0;
	}

	int i = 0;
	for(; i < sizeof(randomness); i++) {
		if(entropy.incr >= entropy.size) {
			entropy.incr = 0;
		}

		entropy.pool[entropy.incr++] = (randomness >> (i * 8) & 0xff);
	}

	return sizeof(randomness);
}

int entropy_gather_pool(void *buf, size_t buf_size) {
	if(entropy.incr <= 0) {
		return 0;
	}

	size_t bytes_to_gather = entropy.incr - buf_size ? buf_size : entropy.incr;
	size_t starting_byte = entropy.incr - buf_size ? entropy.incr - buf_size : 0;

	memcpy8(buf, entropy.pool + starting_byte, bytes_to_gather);

	entropy.incr -= bytes_to_gather;

	return bytes_to_gather;
}

static ssize_t urandom_read(struct file_handle*, void *buf, size_t cnt, off_t) {
	int bytes_gathered = entropy_gather_pool(buf, cnt);

	for(int i = bytes_gathered; i < cnt; i++) {
		*(uint8_t*)(buf + i) = (rdseed() * rdtsc()) & 0xff;
		print("%x", *(uint8_t*)(buf + i));
	}

	print("\n");

	return cnt;
}

static ssize_t urandom_write(struct file_handle *, const void *, size_t cnt, off_t) {
	return cnt;
}

static int urandom_ioctl(struct file_handle*, uint64_t, void *) {
	return 0;	
}

void random_init() {
	struct cpuid_state cpuid_state = cpuid(0, 7);

	if(cpuid_state.rbx & (1 << 18)) {
		entropy.rand = rdseed;
	} else {
		cpuid_state = cpuid(0, 1);
		if(cpuid_state.rcx & (1 << 30)) {
			entropy.rand = rdrand;
		} else {
			panic("random: rdseed and rdrand unsupported");
		}
	}

	entropy.pool = alloc(256);
	entropy.incr = 0;
	entropy.size = 256;

	struct cdev *urandom_cdev = alloc(sizeof(struct cdev));
	urandom_cdev->fops = &urandom_ops;
	urandom_cdev->private_data = NULL;
	urandom_cdev->rdev = makedev(URANDOM_MAJOR, URANDOM_MINOR);
	cdev_register(urandom_cdev);

	print("urandom: registered\n");

	const char *urandom_path = "/dev/urandom";

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);
	stat->st_mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) | S_IFCHR;
	stat->st_rdev = makedev(URANDOM_MAJOR, URANDOM_MINOR);
	
	vfs_create_node_deep(NULL, NULL, NULL, stat, urandom_path);
}
