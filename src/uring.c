// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Asynchronous IO callback abstraction for io_uring support
*/

/*** Handles IO requests asynchonously and mostly without context switches
 * For io_uring to work efficiently, many requests should be queued into the submission queue (SQ)
 * to never let the kernel processing starve because of unavailable userspace-mapped memory.
 * The result of the request can be asynchronously read from the completion queue (CQE).
 * Therefore the replacement functions defined herein for IO system calls like read, write etc.
 * require the caller to specify a function pointer for a callback with the result of the function
 * equivalent and a caller-defined pointer which will then be called asynchronously on processing of
 * the result in the completion queue.
 ***/

#include <sys/eventfd.h>
#include <liburing.h>
#include "uring.h"
#include "async.h"
#include "peer.h"
#include "fastd.h"


#define MAX_URING_SIZE 256		/**/
#define MAX_READ_SUBMISSIONS 64		/**/
#define MAX_PACKETS			/**/
#define URING_FD_READ_COUNT	/* Number of read operations being initially submitted for each fd */


typedef enum fastd_poll_uring_type {
	URING_INPUT,
	URING_OUTPUT,
	URING_BUFFER,
} fastd_uring_action_t;

typedef struct {
	fastd_uring_action_t action;
	fastd_poll_fd_t *fd;
	size_t bid;
	void (*caller_func)(ssize_t, void *);
	void *caller_priv;
} uring_priv_t;


/*** Helper functions ***/
 
 static inline void uring_eventfd_read() {
	eventfd_t v;
	int ret = eventfd_read(ctx.uring_fd.fd, &v);
#ifdef URING_DEBUG
	pr_debug("eventfd_read result=%i", ret);
#endif
	if (ret < 0) exit_bug("eventfd_read");
}

/** Returns the time to the next task, 0 on timeout or -1 in case of infinite time */
static inline int time_remaining() {
	fastd_timeout_t timeout = fastd_task_queue_timeout();

	if (timeout == FASTD_TIMEOUT_INV)
		return -1;

	fastd_update_time();
	
	int diff_msec = timeout - ctx.now;
	if (diff_msec < 0)
		return 0;
	
	return diff_msec;
}

static inline void uring_add_timeout() {
	struct io_uring_sqe *sqe = uring_get_sqe();
	int timeout = time_remaining();
	struct __kernel_timespec ts = {
		ts->tv_sec = timeout / 1000;
		ts->tv_nsec = (timeout % 1000) * 1000000;
	}

	io_uring_prep_timeout(sqe, ts, 1);
	sqe->user_data = LIBURING_TIMEOUT;

	io_uring_submit(&ctx.ring);
}

static void uring_priv_init(void) {
	const int buffer_count = 64 * 2 * 4;
	fastd_buffer_group_init(BUFFER_GROUP_URING, buffer_count, sizeof(uring_priv_t), 0, 0);
}

/** Get a buffer for an uring_priv */
static inline uring_priv_t *uring_priv_acquire(fastd_poll_fd_t *fd,
		    fastd_uring_action_t action, void *data, void (*cb)(ssize_t, void *)) {
	fastd_buffer_group_entry *entry = fastd_buffer_group_entry_acquire(BUFFER_GROUP_URING);
	uring_priv_t *priv = (uring_priv_t *)entry->buf.data;

	priv->fd = fd;
	priv->bid = entry->bid;
	priv->action = action;
	priv->caller_priv = data;
	priv->caller_func = cb;

	return priv;
}

/** Release an uring_priv */
static inline void uring_priv_free(uring_priv_t *priv) {
	fastd_buffer_group_entry *entry = ctx.buffers[BUFFER_GROUP_URING][priv->bid];
	fastd_buffer_release(entry->buf);
}

/** Get an unused submit queue pointer */
static inline struct io_uring_sqe *uring_get_sqe() {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx.uring);

	if (!sqe)
		exit_bug("No SQE available");

	return sqe;
}

/** Submit an IO operation and attach a pointer to the operation's private data */
static inline void uring_submit_priv(struct io_uring_sqe *sqe, void *priv) {
#ifdef URING_DEBUG
	const char *inout;
	if (priv->action == URING_INPUT)
		inout = "URING_INPUT";
	else
		inout = "URING_OUTPUT";

	pr_debug("uring_submit_priv() called, fd=%i, action=%s", priv->fd->fd, inout);
#endif

	io_uring_sqe_set_data(sqe, priv);

	if (io_uring_submit(&ctx.uring)) {
		pr_debug(stderr, "failed to submit to sqe: %s\n", strerror(-ret));
		exit_bug("uring_submit_priv()");
	}
}

static void uring_buffer_provide(struct fastd_buffer_group_entry *entry) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(0, URING_BUFFER, NULL, NULL);

	io_uring_prep_provide_buffers(sqe, entry->buf.data, entry->buf.len, 1, entry->gid, entry->bid);

	uring_submit_priv(sqe, entry);
	//struct fastd_buffer_group_entry *entry = ctx.buffers[gid].entries[bid];
}

void uring_fixed_buffer_prepare(fastd_buffer_group_id_t gid) {
	uring_buffer_provide(fastd_buffer_group_entry_acquire(gid));
}

void fastd_uring_fixed_buffer_init(int gid) {
	struct fastd_buffer_group *group = ctx.buffers[gid];

	/* NOTE: io_uring allows fixed pre-defined buffers to be shared with the kernel for
	 * read and write operations. This saves mapping them into kernel space every time.
	 */
	for (int i = 0; i < group->count; i++)
		uring_buffer_provide(group->entries[i]);

		io_uring_wait_cqe(&ctx.uring, &cqe);

		if (cqe->res < 0)
			exit_bug("fixed_buffer_init");

		io_uring_cqe_seen(&ctx.uring, cqe);
	}
}

void fastd_uring_accept(fastd_poll_fd_t *fd, struct sockaddr *addr, socklen_t *addrlen, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(fd, URING_INPUT, data, cb);

	io_uring_prep_accept(sqe, fd->uring_idx, addr, addrlen, 0);
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	uring_submit_priv(sqe, priv);
}

void fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(fd, URING_INPUT, data, cb);

	io_uring_prep_read(sqe, fd->uring_idx, buf, count, 0);
	sqe->buf_group = fd->buffer_gid;
	io_uring_sqe_set_flags(sqe, IOSQE_ASYNC | IOSQE_FIXED_FILE);
	uring_submit_priv(sqe, priv);
}

void fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(fd, URING_INPUT, data, cb);

	io_uring_prep_recvmsg(sqe, fd->uring_idx, msg, flags);

	sqe->buf_group = fd->buffer_gid;
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT);
	uring_submit_priv(sqe, priv);
}

void fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(fd, URING_OUTPUT, data, cb);

	io_uring_prep_sendmsg(sqe, fd->uring_idx, msg, flags);
	//io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
	io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	uring_submit_priv(sqe, priv);
}

void fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	uring_priv_t *priv = uring_priv_acquire(fd, URING_OUTPUT, data, cb);

	io_uring_prep_write(sqe, fd->uring_idx, buf, count, 0);
	io_uring_sqe_set_flags(sqe, IOSQE_ASYNC | IOSQE_FIXED_FILE);
	uring_submit_priv(sqe, priv);
}

/* creates a new input operation submission for the given fd */
static inline void uring_sqe_input(fastd_poll_fd_t *fd) {
#ifdef uring_debug
	pr_debug("sqe input for fd=%i", fd->fd);
#endif
	switch(fd->type) {
	case POLL_TYPE_IFACE: {
			fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);
			fastd_iface_handle(iface);

			break;
		}
	case POLL_TYPE_SOCKET: {
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);
			fastd_receive(sock);

			break;
		}
	case POLL_TYPE_ASYNC:
		fastd_async_handle();

		break;
	case POLL_TYPE_STATUS:
		fastd_status_handle();

		break;
	default:
		pr_debug("unknown FD type %i", fd->type);
	}
}

/* handles a completed IO operation */
static inline void uring_cqe_handle(struct io_uring_cqe *cqe) {
	uring_priv_t *priv = (uring_priv_t *)io_uring_cqe_get_data(cqe);

	pr_debug("handle cqe %i\n", cqe->res);

	if (!priv) {
		pr_debug("err no priv\n");
		return;
	}

	if (URING_BUFFER == priv->action) {
		if(cqe->res < 0) {
			exit_bug("cqebuf");
		}
	}

	if (priv->action == URING_OUTPUT) {
		goto free;
	}

#ifdef URING_DEBUG
	pr_debug("priv %p\n", priv);
	pr_debug("fd type %i\n", priv->fd->type);

	if (priv->action == URING_OUTPUT)
		pr_debug("output\n");
#endif

	priv->caller_func(cqe->res, priv->caller_priv);

	if (cqe->res < 0) {
		pr_debug("CQE failed %s\n", strerror(-cqe->res));
		goto input;
	}

#ifdef URING_DEBUG
	pr_debug("Callback returned");
#endif

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

input:
	uring_sqe_input(priv->fd);

free:
	uring_priv_free(priv);
}

/* Registers a file descriptor for IOSQE_FIXED_FILE */
static void uring_fixed_fd_add(fastd_poll_fd_t *fd) {
#ifdef URING_DEBUG
	pr_debug("uring_iface_register() called");
#endif
	/* NOTE: For the io_uring SQPOLL mode to work a set of file descriptors must be registered
	 * by the kernel using the IORING_REGISTER_FILES opcode beforehand.
	 * The IO operation submissions must then use the index of the file descriptor in the registered array.
	 */

	int ret;

	fd->uring_idx = ctx.uring_fixed_file_fps_cnt;
	ctx.uring_fixed_file_fps[fd->uring_idx] = fd->fd;

	if (!ctx.uring_fixed_file_fps_cnt) {
		__s32 fds[64];

		for (size_t i = 1; i < 64; i++)
			fds[i] = -1;
		fds[0] = fd->fd;

		ret = io_uring_register_files(&ctx.uring, fds, 64);
	} else
		ret = io_uring_register_files_update(&ctx.uring, fd->uring_idx, &fd->fd, 1);

	ctx.uring_fixed_file_fps_cnt++;

	if(ret < 0) {
		pr_debug("%s", strerror(-cqe->res));
		exit_bug("err_uring_fixed_file_register");
	}
}

/* Initializes the fds and triggers input CQE creation */
void fastd_uring_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_uring_fd_register: invalid FD");

	pr_debug("uring: registering fd of type %i\n", fd->type);

	uring_update_fds(fd);

	switch(fd->type) {
	case POLL_TYPE_IFACE:
	case POLL_TYPE_SOCKET:
			/* Fill the sqe with read/recvmsg attempts */
			for(int i = 0; i < URING_FD_READ_COUNT; i++)
				uring_sqe_input(fd);

			break;
		}
	case POLL_TYPE_ASYNC:
		pr_debug("Setting async input \n");
	case POLL_TYPE_STATUS:
		pr_debug("Setting status input \n");
		uring_sqe_input(fd);
		break;
	default:
		pr_debug("uring wrong fd type received %i", fd->type);
		break;
	}
}

void fastd_uring_handle(void) {
#ifdef URING_DEBUG
	pr_debug("fastd_uring_poll() called");
#endif
	struct io_uring_cqe *cqe;
	unsigned head, count, i = 0;

	uring_eventfd_read();
	uring_add_timeout();

	io_uring_for_each_cqe(&ctx.uring, head, cqe) {
		if (cqe->user_data == LIBURING_TIMEOUT && !time_remaining())
			break;

		uring_cqe_handle(cqe);
		count++;

		/* NOTE: As we submit new SQEs while processing CQEs these
		 * can trigger another CQE. Therefore care must be taken
		 * to advance the CQ at least every MAX_URING_SIZE / 2 CQEs
		 * to make sure nothing is dropped because of a full CQE queue.
		 */
		if (count > MAX_URING_SIZE / 2) {
			io_uring_cq_advance(&ctx.uring, count);
			count = 0;
		}
	}

	io_uring_cq_advance(&ctx.uring, count);

#ifdef URING_DEBUG
	pr_debug("handled %i CQEs", count);
#endif
}

/*** UNIT TESTS */

struct utest {
	struct sockaddr addr;
	struct msghdr msg;
	struct iovec iov;
};

fastd_poll_fd_t uring_test_fd;

void fastd_uring_sock_init_test_callback(ssize_t ret, void *p) {
	struct utest *test = p;

	if (ret == -22) {
		pr_debug("recvmsg failed with error code %i: %s ", ret, strerror(-ret));
		exit_bug("unittest");
	}

	pr_debug("Received %i bytes", ret);
	free(p);
}

void fastd_uring_sock_init_test(fastd_poll_fd_t *fd) {
	struct io_uring_cqe *cqe;

	struct utest *test = malloc(sizeof(struct utest));
	memset(test, 0, sizeof(struct utest));
	test->iov.iov_len = 2048;
	test->iov.iov_base = malloc(2048);
	test->msg.msg_name = &test->addr;
	test->msg.msg_namelen = sizeof(test->addr);
	test->msg.msg_iov = &test->iov;
	test->msg.msg_iovlen = 1;
	fastd_uring_recvmsg(fd, &test->msg, MSG_WAITALL, &test, fastd_uring_sock_init_test_callback);

	io_uring_submit(&ctx.uring);
	io_uring_wait_cqe(&ctx.uring, &cqe);
	pr_debug("UT %i", cqe->res);
	pr_debug("%s", strerror(-cqe->res));
	pr_debug("pt %p", io_uring_cqe_get_data(cqe));
	if (cqe->res < 0) {
		printf("cqe->res = %d\n", cqe->res);
		exit(1);
	}

	io_uring_cqe_seen(&ctx.uring, cqe);
}

void fastd_uring_test_sock() {
	struct sockaddr_in serv_addr;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(5000);
	serv_addr.sin_addr.s_addr = INADDR_ANY;


	if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		exit_bug("binding socket failed\n");
	}

	pr_debug("INIT SOCKET TEST");

	uring_test_fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	fastd_uring_sock_init_test(&uring_test_fd);
}

/*** Initialization functions
 * Please note:
 * These functions should only be called before running any regular IO
 */

/** Register an eventfd for using it with fastd_poll */
static void uring_register_eventfd() {
	ctx.uring_fd = FASTD_POLL_FD(POLL_TYPE_URING, eventfd(0, 0));
	if (ctx.uring_fd.fd < 0)
		exit_bug("eventfd");

	io_uring_register_eventfd(&ctx.uring, ctx.uring_fd.fd);
	fastd_poll_fd_register(&ctx.uring_fd);
}

/* Called on exit of the application */
void fastd_uring_free(void) {
	/* TODO: flush the queue? */
	io_uring_queue_exit(&ctx.uring);
}

static const char *op_strs[] = {
        "IORING_OP_NOP",
        "IORING_OP_READV",
        "IORING_OP_WRITEV",
        "IORING_OP_FSYNC",
        "IORING_OP_READ_FIXED",
        "IORING_OP_WRITE_FIXED",
        "IORING_OP_POLL_ADD",
        "IORING_OP_POLL_REMOVE",
        "IORING_OP_SYNC_FILE_RANGE",
        "IORING_OP_SENDMSG",
        "IORING_OP_RECVMSG",
        "IORING_OP_TIMEOUT",
        "IORING_OP_TIMEOUT_REMOVE",
        "IORING_OP_ACCEPT",
        "IORING_OP_ASYNC_CANCEL",
        "IORING_OP_LINK_TIMEOUT",
        "IORING_OP_CONNECT",
        "IORING_OP_FALLOCATE",
        "IORING_OP_OPENAT",
        "IORING_OP_CLOSE",
        "IORING_OP_FILES_UPDATE",
        "IORING_OP_STATX",
        "IORING_OP_READ",
        "IORING_OP_WRITE",
        "IORING_OP_FADVISE",
        "IORING_OP_MADVISE",
        "IORING_OP_SEND",
        "IORING_OP_RECV",
        "IORING_OP_OPENAT2",
        "IORING_OP_EPOLL_CTL",
        "IORING_OP_SPLICE",
        "IORING_OP_PROVIDE_BUFFERS",
        "IORING_OP_REMOVE_BUFFERS",
};

static int uring_create(void) {
	if(!uring_is_supported)
		return 0;

	memset(&ctx.uring_params, 0, sizeof(ctx.uring_params));

	/* with SQPOLL a kernel thread takes care of new submissions thus saving syscalls */
	if (!geteuid()) {
		ctx.uring_params.flags |= IORING_SETUP_SQPOLL;
		ctx.uring_params.sq_thread_idle = 8000;
	}

	if (io_uring_queue_init_params(MAX_URING_SIZE, &ctx.uring, &ctx.uring_params) < 0) {
        	pr_debug("uring init failed");
        	fastd_uring_free();
        	return 0;
        }

	/* NOTE: fast poll mode allows to use non-blocking sockets in an async manner
	 * while without fast poll they spin crippling the performance
	 */
	if (!(ctx.uring_params.features & IORING_FEAT_FAST_POLL)) {
		pr_debug("uring fast poll is not supported by the kernel");
		fastd_uring_free();
		return 0;
	}

	return 1;
}

void fastd_uring_init(void) {
	struct io_uring_probe *probe = io_uring_get_probe();

	if (!probe)
		return 0;
		
	if (!io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
		pr_debug("IORING_OP_PROVIDE_BUFFERS not supported\n");
		return 0;
	}
	
	if (!io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
		pr_debug("IORING_OP_PROVIDE_BUFFERS not supported\n");
		return 0;
	}

	pr_debug("Supported io_uring operations:\n");
	for (int i = 0; i < IORING_OP_LAST; i++)
		if(io_uring_opcode_supported(probe, i))
			pr_debug("%s\n", op_strs[i]);

	free(probe);

	return 1;


	if (!uring_create()) {
		ctx.uring_supported = false;
		ctx.func_fd_register = fastd_poll_fd_register;
		ctx.func_fd_close = fastd_poll_fd_close;
		ctx.func_io_handle = fastd_poll_handle;
		ctx.func_io_free = fastd_poll_free;
		ctx.func_accept = fastd_uring_accept_unsupported;

		return;
	}

	ctx.uring_supported = true;
	ctx.func_fd_register = fastd_poll_fd_register;
	ctx.func_fd_close = fastd_poll_fd_close;
	ctx.func_io_handle = fastd_poll_handle;
	ctx.func_io_free = fastd_poll_free;
	ctx.func_accept = fastd_uring_accept;

	uring_priv_init();

	uring_register_eventfd();

	/* DEBUG: At this point a unit test can be run: fastd_uring_test_sock(); */
}
