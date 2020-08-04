// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Asynchronous IO callback abstraction for io_uring support
*/

/*    Handling IO requests asynchonously
 *
 *  With io_uring it is possible to drastically reduce the number of syscalls and therefore
 *  context switches when doing IO. For it to work efficiently, many requests should be
 *  queued into the submission queue (SQE) to never let the kernel processing starve.
 *  The result of the request can be asynchronously read from the completion queue (CQE).
 *  Therefore the replacement functions defined herein for IO system calls need to be used
 *  in an asynchronous fashion.
 */

#include <sys/eventfd.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <liburing.h>
#include "uring.h"
#include "async.h"
#include "peer.h"
#include "fastd.h"


#define URING_SQ_SIZE 		512			/* The number of entries the submission queue can hold */
#define URING_CQ_SIZE 		(URING_SQ_SIZE * 2)	/* The number of entries the completion queue can hold */
#define URING_RECVMSG_NUM	64			/* The maximum number of recvmsg operations per socket */
#define URING_READ_NUM		64			/* The maximum number of read operations per fd */

#define FASTD_URING_TIMEOUT	((__u64) -1337)		/* Used as a magic value for marking a timeout CQE */
#define FASTD_URING_POLL	((__u64) -1336)		/* Used as a magic value for marking a poll */

typedef struct fastd_uring_priv {
	fastd_poll_fd_t *fd;
	fastd_uring_action_t action;
	void (*caller_func)(ssize_t, void *);
	void *caller_priv;
	uring_sched_t schedule;
} uring_priv_t;

/* HINT: 	
io_uring allows pre-registered buffers to be used

but setting them with buffer select is not fast, but only
thought to reduce the number of buffers blocked by IO
sqe->buf_group = fd->type; // the buffer group of fixed buffers
io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
	
*/

int uring_read_flags;
int uring_recvmsg_flags;

struct io_uring_cqe *uring_cqes[URING_CQ_SIZE];


bool firstrun;


/*    Helper functions
 */

/** Returns the time to the next task or -1 */
static inline int task_timeout(void) {
	fastd_timeout_t timeout = fastd_task_queue_timeout();
	if (timeout == FASTD_TIMEOUT_INV)
		return -1;

	int diff_msec = timeout - ctx.now;
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}

/** Allocate and initialize a uring_priv */
static inline uring_priv_t *uring_priv_new(fastd_poll_fd_t *fd,
		    fastd_uring_action_t action, void *data, void (*cb)(ssize_t, void *)) {
	uring_priv_t *priv = fastd_new0(uring_priv_t);

	priv->fd = fd;
	priv->action = action;
	priv->caller_priv = data;
	priv->caller_func = cb;

	return priv;
}

/** Free a uring_priv */
static inline void uring_priv_free(uring_priv_t *priv) {
	free(priv);
}

/** Submit pending io_uring submission entries */
static int uring_submit(void) {
	uring_debug("uring_submit()");
	if(!ctx.uring_must_submit)
		return 0;
	uring_debug("uring_submit()1");
	ctx.uring_must_submit = false;


	int ret = io_uring_submit(&ctx.uring);
	uring_debug("uring_submit()2");
	if (ret < 0) {
		uring_debug("uring_submit() failed: %s\n", strerror(-ret));
		exit_bug("uring_submit");
	} else {
		uring_debug("submitted %i SQEs", ret);
	}
	uring_debug("uring_submit()3");
	if(ret == 0) {
		exit_bug("submit without CQEs");
	}

	return ret;
}

/** Acquire a submission entry from io_uring or fail */
static inline struct io_uring_sqe *uring_get_sqe() {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx.uring);

	if (!sqe)
		exit_bug("No SQE available");

	return sqe;
}

/** Finish the preparation of a submission entry */
static inline void uring_priv_set(struct io_uring_sqe *sqe, uring_priv_t *priv, int flags) {
	const char *inout;

	if (priv->action == URING_INPUT) {
		inout = "URING_INPUT";
	} else {
		inout = "URING_OUTPUT";
	}

	uring_debug("uring_priv_set() called, fd=%i, action=%s, data=%p", priv->fd->fd, inout, priv);
	
	io_uring_sqe_set_flags(sqe, flags);
	io_uring_sqe_set_data(sqe, priv);
}

static const char *uring_op_strs[] = {
	"NOP", "READV", "WRITEV", "FSYNC", "READ_FIXED", "WRITE_FIXED", "POLL_ADD", "POLL_REMOVE",
	"SYNC_FILE_RANGE", "SENDMSG", "RECVMSG", "TIMEOUT", "TIMEOUT_REMOVE", "ACCEPT", "ASYNC_CANCEL",
	"LINK_TIMEOUT", "CONNECT", "FALLOCATE", "OPENAT", "CLOSE", "FILES_UPDATE", "STATX", "READ",
	"WRITE", "FADVISE", "MADVISE", "SEND", "RECV", "OPENAT2", "EPOLL_CTL", "SPLICE", "PROVIDE_BUFFERS",
	"REMOVE_BUFFERS",
};

static inline int uring_is_supported() {
	struct io_uring_probe *probe = io_uring_get_probe();

	if (!probe)
		return 0;

	if (!io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
		pr_debug("IORING_OP_PROVIDE_BUFFERS not supported\n");
		exit(0);
	}

	uring_debug("Supported io_uring operations:");
	for (int i = 0; i < IORING_OP_LAST; i++)
		if(io_uring_opcode_supported(probe, i))
			pr_debug("%s", uring_op_strs[i]);

	pr_debug("\n");

	free(probe);

	return 1;
}

/* registers a file descriptor for IOSQE_FIXED_FILE use */
static void uring_fixed_file_register(fastd_poll_fd_t *fd) {
	/* NOTE: The SQPOLL feature requires file descriptors to be registered
	 * before using them. See https://github.com/axboe/liburing/issues/83
	 */
	uring_debug("uring_fixed_file_register() called");
	int ret;

	fd->uring_idx = ctx.uring_fixed_file_fps_cnt;
	ctx.uring_fixed_file_fps[fd->uring_idx] = fd->fd;

	if (ctx.uring_fixed_file_fps_cnt < 1) {
		__s32 fds[64];

		fds[0] = fd->fd;
		for (size_t i = 1; i < 64; i++) {
			fds[i] = -1;
		}

		ret = io_uring_register_files(&ctx.uring, fds, 64);
	} else {
		ret = io_uring_register_files_update(&ctx.uring, fd->uring_idx, &fd->fd, 1);
	}

	ctx.uring_fixed_file_fps_cnt++;

	if(ret < 0)
		exit_bug("err_uring_fixed_file_register: BUG");
}

/*    Scheduling functions for deferred ring submissions
 *
 *  io_uring sometimes has trouble with file descriptor access conflicts resulting in
 *  resource busy errors. We try to mitigate this effect by chaining and submitting
 *  writes/sendmsgs in batches.
 */

static inline void fastd_uring_schedule_add(uring_sched_op_t op, uring_priv_t *priv) {
	uring_sched_t **head;
	uring_sched_t **tail;
	
	priv->schedule.op = op;
	uring_debug("Scheduling %p op=%i fd=%i", priv, op, priv->fd->fd);
	if(priv->action == URING_OUTPUT) {
		head = &priv->fd->output_queue.head;
		tail = &priv->fd->output_queue.tail;
	} else {
		head = &priv->fd->input_queue.head;
		tail = &priv->fd->input_queue.tail;
	}

	if (!*tail) {
		*tail = &priv->schedule;
	} else {
		(*head)->next = &priv->schedule;
	}

	*head = &priv->schedule;
}

/* Add a schedule queue (B) on top of another (A) and clear its pointers */
static void uring_schedule_chain(uring_sched_queue_t *queue_a, uring_sched_queue_t *queue_b) {
	if(!queue_a->tail) {
		queue_a->tail = queue_b->tail;
		queue_a->head = queue_b->head;
	} else {
		queue_a->head->next = queue_b->tail;
		queue_a->head = queue_b->head;
	}

	queue_b->tail= NULL;
	queue_b->head = NULL;
}

static void uring_schedule_execute(uring_sched_queue_t *queue) {
	uring_sched_t *entry;

	if(queue->tail)
		ctx.uring_must_submit = true;

	for(entry = queue->tail; entry; entry = entry->next) {
		uring_priv_t *priv = container_of(entry, uring_priv_t, schedule);
		struct io_uring_sqe *sqe = uring_get_sqe();

		if(priv->action == URING_INPUT) {
			priv->fd->input_pending++;
			/* We add a poll to the beginning to mitigate access race conditions */
/*
			if(entry == queue->tail) {
				io_uring_prep_poll_add(sqe, priv->fd->fd, POLLIN);
				io_uring_sqe_set_flags(sqe, IOSQE_IO_HARDLINK);
				sqe->user_data = FASTD_URING_POLL;
				sqe = uring_get_sqe();
			}*/

			if(URING_OP_RECVMSG == priv->schedule.op) {
				uring_debug("executing a RECVMSG");
				io_uring_prep_recvmsg(sqe, priv->fd->uring_idx, entry->msg, entry->flags);
			} else { /* URING_OP_READ == op */
				uring_debug("executing a READ");
				io_uring_prep_read(sqe, priv->fd->uring_idx, entry->buf, entry->count, 0);
			}
		} else {
			priv->fd->output_pending++;
			ctx.uring_output_pending++;
/*
			if(entry == queue->tail) {
				io_uring_prep_poll_add(sqe, priv->fd->fd, POLLOUT);
				io_uring_sqe_set_flags(sqe, IOSQE_IO_HARDLINK);
				sqe->user_data = FASTD_URING_POLL;
				sqe = uring_get_sqe();
			}*/

			if(URING_OP_SENDMSG == priv->schedule.op) {
				uring_debug("executing a SENDMSG");
				io_uring_prep_sendmsg(sqe, priv->fd->uring_idx, entry->msg, entry->flags);
			} else { /* URING_OP_WRITE == op */
				uring_debug("executing a WRITE");
				io_uring_prep_write(sqe, priv->fd->uring_idx, entry->buf, entry->count, 0);
			}
		}

		if (entry != queue->head) {
			/* hardlink the entries to make sure to avoid conflicts */
			uring_priv_set(sqe, priv, IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE);
		} else { /* the first SQE without a link marks the end of the chain */
			uring_priv_set(sqe, priv, IOSQE_FIXED_FILE);
		}
	}

	queue->tail = NULL;
	queue->head = NULL;
}

/*    Replacement functions for file and socket operations
 *
 *  With io_uring IO operations complete in an async manner. Therefore the replacement
 *  functions defined herein offer another two parameters - A callback function which
 *  will be called on completion of the operation and a pointer which will be handed to the
 *  callback function along with the result of the operation as parameters.
 */

/** Used when the kernel doesn't support io_uring */
void fastd_uring_recvmsg_unsupported(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(recvmsg(fd->fd, msg, flags), data);
}

void fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	uring_priv_t *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	priv->schedule.msg = msg;
	priv->schedule.flags = flags;

	fastd_uring_schedule_add(URING_OP_RECVMSG, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_sendmsg_unsupported(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(sendmsg(fd->fd, msg, flags), data);
}

void fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	uring_priv_t *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);

	priv->schedule.msg = msg;
	priv->schedule.flags = flags;

	fastd_uring_schedule_add(URING_OP_SENDMSG, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_read_unsupported(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(read(fd->fd, buf, count), data);
}

void fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	uring_priv_t *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	priv->schedule.buf = buf;
	priv->schedule.count = count;

	fastd_uring_schedule_add(URING_OP_READ, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_write_unsupported(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(write(fd->fd, buf, count), data);
}

void fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	uring_priv_t *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);

	priv->schedule.buf = buf;
	priv->schedule.count = count;

	fastd_uring_schedule_add(URING_OP_WRITE, priv);
}

void uring_poll_add(fastd_poll_fd_t *fd, short poll_mask) {
	uring_priv_t *priv = uring_priv_new(fd, URING_INPUT, NULL, NULL);
	struct io_uring_sqe *sqe = uring_get_sqe();

	io_uring_prep_poll_add(sqe, fd->fd, poll_mask);
	uring_priv_set(sqe, priv, 0);
	ctx.uring_must_submit = true;
	uring_submit();
}

void uring_poll_remove(fastd_poll_fd_t *fd) {
	struct io_uring_sqe *sqe = uring_get_sqe();

	io_uring_prep_poll_remove(sqe, &fd);
	uring_priv_set(sqe, (uring_priv_t *)&fd, 0);
	ctx.uring_must_submit = true;
	uring_submit();
}


/* Adds a timeout entry to the SQE queue */
static inline void uring_timeout_add(int timeout) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct __kernel_timespec ts = {
			.tv_sec = timeout / 1000,
			.tv_nsec = (timeout % 1000) * 1000000
		};

	io_uring_prep_timeout(sqe, &ts, 0, 0);
	sqe->user_data = FASTD_URING_TIMEOUT;
	ctx.uring_must_submit = true;
	uring_submit();
}

/*    Input submission trigger
 */

/* creates a new URING_INPUT submission */
static inline void uring_sqe_input(fastd_poll_fd_t *fd) {
	uring_debug("sqe input for fd=%i type=%i", fd->fd, fd->type);
	switch(fd->type) {
	case POLL_TYPE_IFACE: {
			fd->input_pending--;
			uring_debug("iface handle \n");
			fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);

			fastd_iface_handle(iface);

			break;
		}
	case POLL_TYPE_SOCKET: {
			fd->input_pending--;
			uring_debug("socket handle \n");
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

			if(firstrun) {
				firstrun = false;
			/* FIXME The first batch of recvmsgs receive bogus data.
			 * Thus we fill the queue only after receiving the first packet
			 */
				for(int i = 0; i < URING_RECVMSG_NUM; i++)
					fastd_receive(sock);
			} else {
				fastd_receive(sock);
			}

			break;
		}
	case POLL_TYPE_ASYNC:
		uring_debug("async handle \n");
		fastd_async_handle();
		uring_poll_add(fd, POLLIN);
		break;
	case POLL_TYPE_STATUS:
		uring_debug("status handle \n");
		fastd_status_handle();
		uring_poll_add(fd, POLLIN);
		break;
	default:
		uring_debug("unknown FD type %i", fd->type);
		exit_bug("uring_fdtype");
	}
}

/* handles a completion queue event */
static inline void uring_cqe_handle(struct io_uring_cqe *cqe) {
	uring_priv_t *priv = (uring_priv_t *)io_uring_cqe_get_data(cqe);

	if (priv->action == URING_OUTPUT) 
		ctx.uring_output_pending--;

	if (priv->caller_func)
		priv->caller_func(cqe->res, priv->caller_priv);
	
	if (priv->action == URING_OUTPUT)
		goto free;

	if (cqe->res < 0) {
		if(priv->action == URING_INPUT && cqe->res == -EAGAIN && priv->fd->type == POLL_TYPE_SOCKET) {
			uring_debug("recvmsg fail");
		} else if(priv->action == URING_INPUT && cqe->res == -EAGAIN && priv->fd->type == POLL_TYPE_IFACE) {
			uring_debug("read fail");
		} else {
			pr_debug("res=%i fd-type=%i %p", cqe->res, priv->fd->type, priv);
			exit_bug("CQE fail");
		}
	}

	/* FIXME: we should not reset the connection more than once, but we need
	 * to go through every outstanding completion to free the privs.
	 * Therefore it needs be made sure that the reset only happens once by e.g.
	 * checking for a new fd number. This needs a FLUSH.
	 */
	if (cqe->res == -ECANCELED && POLL_TYPE_SOCKET == priv->fd->type) {
		fastd_socket_t *sock = container_of(priv->fd, fastd_socket_t, fd);

		/* the connection is broken */
		if (sock->peer)
			fastd_peer_reset_socket(sock->peer);
		else
			fastd_socket_error(sock);

		goto free;
	}

	uring_sqe_input(priv->fd);

free:
	uring_priv_free(priv);
}

static uring_submit_prepare() {
	uring_schedule_execute(&ctx.iface->fd.output_queue);

	for (int i = 0; i < ctx.n_socks; i++) {
		fastd_poll_fd_t *fd = &ctx.socks[i];
		uring_schedule_execute(&fd->output_queue);
	}

	if (!ctx.iface->fd.input_pending)
		uring_schedule_execute(&ctx.iface->fd.input_queue);

	for (int i = 0; i < ctx.n_socks; i++) {
		fastd_poll_fd_t *fd = &ctx.socks[i];
		if (!fd->input_pending)
			uring_schedule_execute(&fd->input_queue);
	}
}

static struct io_uring_cqe *uring_get_cqe() {
	struct io_uring_cqe *cqe;
	ctx.uring_cqe_pos++;

	if (ctx.uring_cqe_pos < ctx.uring_cqe_count)
		return uring_cqes[ctx.uring_cqe_pos];
	
	if (ctx.uring_cqe_count)
		io_uring_cq_advance(&ctx.uring, ctx.uring_cqe_count);

	uring_debug("stopped %i/%i %i", ctx.uring_cqe_pos, ctx.uring_cqe_count, ctx.uring_output_pending);
	
	if (io_uring_cq_ready(&ctx.uring) == 0) {
		uring_submit_prepare();
		uring_debug("URINGENTER");
		int ret;

		if (ctx.uring_must_submit) {
			uring_debug("submit_and_wait");
			ret = io_uring_submit_and_wait(&ctx.uring, ctx.uring_output_pending + 1);
			ctx.uring_must_submit = false;
		} else  {
			ret = io_uring_wait_cqe_nr(&ctx.uring, &cqe, ctx.uring_output_pending + 1);
		}

		uring_debug("URINGRETURN");
		if (ret < 0) {
		    pr_debug("io_uring_wait_cqe ret=%i\n", ret);
		    exit_bug("io_uring_wait_cqe");
		}
	}

	ctx.uring_cqe_count = io_uring_peek_batch_cqe(&ctx.uring, uring_cqes, sizeof(uring_cqes) / sizeof(uring_cqes[0]));

	if(ctx.uring_cqe_count == 0)
		exit_bug("uring_nocqe");

	ctx.uring_cqe_pos = 0;

	return uring_cqes[0];
}

void fastd_uring_handle(void) {
	int timeout = task_timeout();
	bool time_updated = false;
	unsigned count = 0;

	sigset_t set, oldset;
	sigemptyset(&set);
	pthread_sigmask(SIG_SETMASK, &set, &oldset);

        uring_timeout_add(timeout);
	while(1) {
		struct io_uring_cqe *cqe = uring_get_cqe();
		count++;

		if(!time_updated) {
			fastd_update_time();
			time_updated = true;
		}
		
		if (FASTD_URING_TIMEOUT == cqe->user_data)
			break;

		if(cqe->user_data != FASTD_URING_POLL)
			uring_cqe_handle(cqe);
	}

	uring_submit_prepare();
	uring_submit();

	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
}

/*    File descriptor registration and teardown
 */

/* Initializes the fds and generates input CQEs */
void fastd_uring_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_uring_fd_register: invalid FD");

	uring_debug("uring_register fdtype=%i\n", fd->type);
	switch(fd->type) {
	case POLL_TYPE_IFACE:
			uring_fixed_file_register(fd);

			fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);
			for(int i = 0; i < URING_READ_NUM; i++)
				fastd_iface_handle(iface);

			/* FIXME non-fixed files can only be used after registration of all fixed files?! */
			if(ctx.status_fd.fd != -1)
				uring_poll_add(&ctx.status_fd, POLLIN);
			uring_poll_add(&ctx.async_rfd, POLLIN);

			break;
	case POLL_TYPE_SOCKET: {
			uring_fixed_file_register(fd);
			/* FIXME: It seems there is a bug where the first recvmsg will always return length 38
			 * Thus we only schedule a single recvmsg which will fail and afterwards everything works
			 * as expected #crazyworkaround
			 */
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

			fastd_receive(sock);

			break;
		}
	case POLL_TYPE_ASYNC:
	case POLL_TYPE_STATUS:
		break;
	default:
		uring_debug("uring wrong fd type received %i", fd->type);
		break;
	}
}

bool fastd_uring_fd_close(fastd_poll_fd_t *fd) {
	/* FIXME: Block new input, insert a flush and only close it afterwards Hint: Set fixed file index -1 */
	
	switch(fd->type) {
	case POLL_TYPE_ASYNC:
	case POLL_TYPE_STATUS:
		uring_poll_remove(fd);
		break;
	}

	return (close(fd->fd) == 0);
}

void fastd_uring_init(void) {
	if (!uring_is_supported()) {
		ctx.func_recvmsg = fastd_uring_recvmsg_unsupported;
		ctx.func_sendmsg = fastd_uring_sendmsg_unsupported;
		ctx.func_read = fastd_uring_read_unsupported;
		ctx.func_write = fastd_uring_write_unsupported;
		ctx.func_fd_register = fastd_poll_fd_register;
		ctx.func_fd_close = fastd_poll_fd_close;
		ctx.func_io_handle = fastd_poll_handle;
		ctx.func_io_free = fastd_poll_free;
		fastd_poll_init();

		return;
	}

	ctx.func_recvmsg = fastd_uring_recvmsg;
	ctx.func_sendmsg = fastd_uring_sendmsg;
	ctx.func_read = fastd_uring_read;
	ctx.func_write = fastd_uring_write;
	ctx.func_fd_register = fastd_uring_fd_register;
	ctx.func_fd_close = fastd_uring_fd_close;
	ctx.func_io_handle = fastd_uring_handle;
	ctx.func_io_free = fastd_uring_free;

	memset(&ctx.uring_params, 0, sizeof(ctx.uring_params));

	ctx.uring_recvmsg_num = 0;
	ctx.uring_read_num = 0;
	ctx.uring_sqe_must_link = false;
	firstrun = true;

	/* TODO: Try SQPOLL mode - needs privileges
	 * NOTE: We found SQPOLL mode to be too resource intensive for sockets (throughput dropped to half).
	if (!geteuid()) {
		uring_debug("uring: Activating SQPOLL mode - Experimental! \n");
		ctx.uring_params.flags |= IORING_SETUP_SQPOLL;
		ctx.uring_params.sq_thread_idle = 8000;
	}
	*/

	if (io_uring_queue_init_params(URING_SQ_SIZE, &ctx.uring, &ctx.uring_params) < 0)
        	exit_bug("uring init failed");

	/* Without FASTPOLL non-blocking IO seems to be computation intensive.
	 * It might be possible to LINK a poll to the beginning of a read to
	 * mitigate missing FASTPOLL support?!
	 */
	if (!(ctx.uring_params.features & IORING_FEAT_FAST_POLL))
		uring_debug("uring fast poll not supported by the kernel.");

	/* NOTE: With NODROP we can make sure that CQEs won't be dropped
	 * if the ring is full by blocking new SQEs. Actually we want to
	 * define the ring big enough to never let this happen.
	 */
	if (!(ctx.uring_params.features & IORING_FEAT_NODROP)) {
		uring_debug("uring nodrop not supported by the kernel.");
		/*ctx.uring_params.flags |= IORING_SETUP_CQ_NODROP;*/
	}
}

void fastd_uring_free(void) {
	/* TODO: Find out if it triggers error cqes and if our privs get freed */
	/* TODO: If a file subscriptr was fixed, unregister*/
	/* TODO create a NOP with flag IOSQE_IO_DRAIN and cancel any new submissions */
	
	/* TODO Check on return value*/
	io_uring_unregister_files(&ctx.uring);
	io_uring_queue_exit(&ctx.uring);
}
