// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Asynchronous IO callback abstraction for io_uring support
*/

/*** Handling IO requests asynchonously
 * For io_uring to work efficiently, many requests should be queued into the submission queue (sqe)
 * to never let the kernel processing starve because of unavailable userspace-mapped memory.
 * The result of the request can be asynchronously read from the completion queue (cqe).
 * Therefore the replacement functions defined herein for IO system calls like read, write etc.
 * require the caller to specify a function pointer for a callback with the result of the function
 * equivalent and a caller-defined pointer which will then be called asynchronously on processing of
 * the result in the completion queue.
 ***/

#include <sys/epoll.h>
#include <liburing.h>
#include "uring.h"
#include "async.h"
#include "peer.h"
#include "fastd.h"

#define MAX_URING_SIZE 256		/**/
#define MAX_READ_SUBMISSIONS 64		/**/
#define MAX_PACKETS			/**/

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
static inline struct fastd_uring_priv *uring_priv_new(fastd_poll_fd_t *fd, 
		    fastd_uring_action_t action, void *data, void (*cb)(ssize_t, void *)) {
	struct fastd_uring_priv *priv = fastd_new0(struct fastd_uring_priv);

	priv->fd = fd;
	priv->action = action;
	priv->caller_priv = data;
	priv->caller_func = cb;

	return priv;
}

/** Free a uring_priv */
static inline void uring_priv_free(struct fastd_uring_priv *priv) {
	free(priv);
}

/** Handles a file descriptor that was selected on by poll.c or uring.c */
static inline void fastd_handle_poll_fd(fastd_poll_fd_t *fd, bool input, bool error) {
	/* NOTE: Used as a helper function by uring.c */
	switch (fd->type) {
	case POLL_TYPE_ASYNC:
		if (input)
			fastd_async_handle();
		break;

	case POLL_TYPE_STATUS:
		if (input)
			fastd_status_handle();
		break;

	case POLL_TYPE_IFACE: {
		fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);

		if (input)
			fastd_iface_handle(iface);

		break;
	}

	case POLL_TYPE_SOCKET: {
		fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

		if (error) {
			if (sock->peer)
				fastd_peer_reset_socket(sock->peer);
			else
				fastd_socket_error(sock);

			return;
		}

		if (input)
			fastd_receive(sock);

		break;
	}

	default:
		exit_bug("unknown FD type");
	}

	if (error)
		exit_error("unexpected poll error");
}

static inline void uring_submit_priv(struct io_uring_sqe *sqe, struct fastd_uring_priv *priv) {
	io_uring_sqe_set_data(sqe, priv);

	if(ctx.uring_params.features & IORING_FEAT_FAST_POLL) {
		/* In fast poll mode we don't need to submit often
		 * if ever and if then it is being done by fastd_uring_handle().
		 * TODO: Check if this handling is correct */
		/*io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
		sqe->flags |= IOSQE_IO_LINK;*/
		return;
	}

	io_uring_submit(&ctx.uring);
}

static inline struct io_uring_sqe *uring_get_sqe() {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx.uring);

	if (!sqe)
		exit_bug("No SQE available");

	return sqe;
}

/* TODO: fixed_buffer
 * io_uring allows fixed pre-defined buffers to be shared with the kernel to be used for
 * read and write operations on file descriptors.

void fastd_uring_fixed_buffer_alloc() {

}

 */

/* registers the TUN/TAP file descriptor for IOSQE_FIXED_FILE */
static inline void uring_iface_register(fastd_poll_fd_t *fd) {
/* TODO: Currently unsupported - Try to fix it
'''
  To  successfully  use  this feature, the application must register a set of files to be
  used for IO through io_uring_register(2) using the IORING_REGISTER_FILES opcode.  Fail-
  ure to do so will result in submitted IO being errored with EBADF.
'''

NOTE: 	Needs to set io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
	
Example code:
	int ret;

	ctx.uring_fixed_file_fps[0] = fd->fd;

	ret = io_uring_register_files(&ctx.ring, ctx.uring_fixed_file_fps, 1);

	if(ret)
		error_bug("err_uring_fixed_file_register: %s", strerror(-ret));
*/
}

/*
TODO: Eventually replace the function pointers with macros. E.g.
#ifdef HAVE_LIBURING
#define fastd_read(fd, buf, count, data, cb) { \
		if (ctx.uring_supported) \
			fastd_uring_read(fd, buf, count, data, &cb); \
		else cb(read(fd->fd, buf, count), data); } \
#endif
*/

/** Used when the kernel doesn't support io_uring */
void fastd_uring_accept_unsupported(fastd_poll_fd_t *fd, struct sockaddr *addr, socklen_t *addrlen, void *data, void (*cb)(ssize_t, void *)) {
	cb(accept(fd->fd, addr, addrlen), data);
}

void fastd_uring_accept(fastd_poll_fd_t *fd, struct sockaddr *addr, socklen_t *addrlen, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_accept(sqe, fd->fd, addr, addrlen, 0);
	uring_submit_priv(sqe, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_recvmsg_unsupported(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(recvmsg(fd->fd, msg, flags), data);
}

void fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_recvmsg(sqe, fd->fd, msg, 0);
	uring_submit_priv(sqe, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_sendmsg_unsupported(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(sendmsg(fd->fd, msg, flags), data);
}

void fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);

	io_uring_prep_sendmsg(sqe, fd->fd, msg, 0);
	uring_submit_priv(sqe, priv);
}

/* NOTE: read and write operations must only be performed on the TUN/TAP iface fp
 * as they are registered as fixed files with fixed buffers.
 * TODO: It would be nice to have fixed buffer support for io_uring_prep_read_fixed()
 */

/** Used when the kernel doesn't support io_uring */
void fastd_uring_read_unsupported(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(read(fd->fd, buf, count), data);
}

void fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_read(sqe, fd->fd, buf, count, 0);
	uring_submit_priv(sqe, priv);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_write_unsupported(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(write(fd->fd, buf, count), data);
}

void fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);

	io_uring_prep_write(sqe, fd->fd, buf, count, 0);
	uring_submit_priv(sqe, priv);
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

static inline int uring_is_supported() {
	struct io_uring_probe *probe = io_uring_get_probe();

	if (!probe) {
		ctx.func_recvmsg = &fastd_uring_recvmsg_unsupported;
		ctx.func_sendmsg = &fastd_uring_sendmsg_unsupported;
		ctx.func_read = &fastd_uring_read_unsupported;
		ctx.func_write = &fastd_uring_write_unsupported;

		fastd_poll_init();

		return 0;
	}

	printf("Supported io_uring operations:");
	for (int i = 0; i < IORING_OP_LAST; i++)
		if(io_uring_opcode_supported(probe, i))
			printf("%s", op_strs[i]);

	printf("\n");

	free(probe);

	return 1;
}


void fastd_uring_init(void) {
	if (!uring_is_supported()) {
		ctx.func_recvmsg = &fastd_uring_recvmsg_unsupported;
		ctx.func_sendmsg = &fastd_uring_sendmsg_unsupported;
		ctx.func_read = &fastd_uring_read_unsupported;
		ctx.func_write = &fastd_uring_write_unsupported;
		ctx.func_fd_register = &fastd_poll_fd_register;
		ctx.func_fd_close = &fastd_poll_fd_close;
		fastd_poll_init();

		return;
	}

	ctx.func_recvmsg = &fastd_uring_recvmsg;
	ctx.func_sendmsg = &fastd_uring_sendmsg;
	ctx.func_read = &fastd_uring_read;
	ctx.func_write = &fastd_uring_write;
	ctx.func_fd_register = &fastd_uring_fd_register;
	ctx.func_fd_close = &fastd_uring_fd_close;

	memset(&ctx.uring_params, 0, sizeof(ctx.uring_params));
	/* TODO: Try SQPOLL mode - needs privileges
	if (!geteuid()) {
		fprint("uring: Activating SQPOLL mode - Experimental! \n");
		ctx.uring_params.flags |= IORING_SETUP_SQPOLL;
		ctx.uring_params.sq_thread_idle = 8000;
	}*/

	if (io_uring_queue_init_params(MAX_URING_SIZE, &ctx.uring, &ctx.uring_params) < 0)
        	exit_bug("uring init failed");

	/* TODO: Find more about FAST_POLL and try to fix it */
	if (!(ctx.uring_params.features & IORING_FEAT_FAST_POLL))
		printf("uring fast poll not supported by the kernel.");

}

void fastd_uring_free(void) {
	/* TODO: Find out if it triggers error cqes and if our privs get freed */
	io_uring_queue_exit(&ctx.uring);
}

/* creates a new URING_INPUT submission */
static inline void uring_sqe_input(fastd_poll_fd_t *fd) {
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
		exit_bug("unknown FD type");
	}
}

/* handles a completion queue event */
static inline void uring_cqe_handle(struct io_uring_cqe *cqe) {
	struct fastd_uring_priv *priv = (struct fastd_uring_priv *)io_uring_cqe_get_data(cqe);

	priv->caller_func(cqe->res, priv->caller_priv);

	/* FIXME: we should not reset the connection more than once, but we need
	 * to go through every outstanding completion to free the privs.
	 * Therefore it needs be made sure that the reset only happens once by e.g.
	 * checking for a new fd number.
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

	if (priv->action == URING_OUTPUT)
		goto free;

	uring_sqe_input(priv->fd);

	io_uring_cqe_seen(&ctx.uring, cqe);

free:
	uring_priv_free(priv);
}

/* Initializes the fds and generates input cqes */
void fastd_uring_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_uring_fd_register: invalid FD");

	/* register the file descriptor as a "fixed file" */
	if(POLL_TYPE_IFACE == fd->type)
		uring_iface_register(fd);

	switch(fd->type) {
	case POLL_TYPE_SOCKET:
	case POLL_TYPE_IFACE: {
			
			/* fill the submission queue with many read submissions */
			for(int i = 0; i < MAX_READ_SUBMISSIONS; i++)
				uring_sqe_input(fd);
			break;
		}
	case POLL_TYPE_ASYNC:
	case POLL_TYPE_STATUS:
		fastd_handle_poll_fd(fd, true, false);

		break;
	default:
		exit_bug("unknown FD type");
	}
}

bool fastd_uring_fd_close(fastd_poll_fd_t *fd) {
	/* FIXME: The remaining privs need to be freed on cqe fails */
	return (close(fd->fd) == 0);
}

void fastd_uring_handle(void) {
	struct io_uring_cqe *cqe;
	struct io_uring_cqe *cqes[MAX_URING_BACKLOG_SIZE];
	int timeout = task_timeout();
	int cqe_count, ret, i;

	struct __kernel_timespec ts = {
		.tv_sec = timeout / 1000,
		.tv_nsec = (timeout % 1000) * 1000,
	};

	ret = io_uring_wait_cqe_timeout(&ctx.uring, &cqe, &ts);
	if (ret < 0)
	    exit_bug("uring_wait_cqe_timeout failed");

	fastd_update_time();

	cqe_count = io_uring_peek_batch_cqe(&ctx.uring, cqes, sizeof(cqes) / sizeof(cqes[0]));

	for (i = 0; i < cqe_count; ++i)
		uring_cqe_handle(cqes[i]);

	io_uring_submit(&ctx.uring);
}
