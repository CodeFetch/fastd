// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

#pragma once

#include "poll.h"
#include "buffer.h"

void __fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void __fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *));
void __fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));
void __fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *));

#define fastd_uring_read(fd, buf, count, data, cb) { \
		if (ctx.uring_supported) { \
			__fastd_uring_read(fd, buf, count, data, &cb); \
		} else { \
			cb(read(fd->fd, buf, count), data); \
		} \
	}

#define fastd_uring_recvmsg(fd, buf, count, data, cb) { \
		if (ctx.uring_supported) { \
			__fastd_uring_read(fd, buf, count, data, &cb); \
		} else { \
			cb(read(fd->fd, buf, count), data); \
		} \
	}

#define fastd_uring_sendmsg(fd, buf, count, data, cb) { \
		if (ctx.uring_supported) { \
			__fastd_uring_read(fd, buf, count, data, &cb); \
		} else { \
			cb(read(fd->fd, buf, count), data); \
		} \
	}
	
#define fastd_uring_write(fd, buf, count, data, cb) { \
		if (ctx.uring_supported) { \
			__fastd_uring_read(fd, buf, count, data, &cb); \
		} else { \
			cb(read(fd->fd, buf, count), data); \
		} \
	}

void fastd_uring_fd_register(fastd_poll_fd_t *fd);
bool fastd_uring_fd_close(fastd_poll_fd_t *fd);
void fastd_uring_handle(void);
void fastd_uring_init(void);
void fastd_uring_free(void);
