// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

#pragma once

#include "poll.h"
#include "buffer.h"

typedef enum fastd_poll_uring_type {
	URING_INPUT,
	URING_OUTPUT,
} fastd_uring_action_t;

struct fastd_uring_priv {
	fastd_uring_action_t action;
	fastd_poll_fd_t *fd;
	void (*caller_func)(ssize_t, void *);
	void *caller_priv;
};

void fastd_uring_init(void);
void fastd_uring_free(void);

void fastd_uring_recvmsg_unsupported(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_sendmsg_unsupported(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_read_unsupported(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_write_unsupported(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));
void fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));

void fastd_uring_fd_register(fastd_poll_fd_t *fd);
bool fastd_uring_fd_close(fastd_poll_fd_t *fd);
void fastd_uring_handle(void);
