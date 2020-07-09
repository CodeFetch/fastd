// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable polling API
*/


#pragma once


#include "types.h"

#ifdef HAVE_LIBURING
struct uring_schedule {
	uring_sched_op_t op;
	struct msghdr *msg;
	void *buf;
	size_t count;
	int flags;
	struct uring_schedule *next;
};

struct uring_schedule_queue {
	struct uring_schedule *head;
	struct uring_schedule *tail;
};
#endif

/** A file descriptor to poll on */
struct fastd_poll_fd {
	fastd_poll_type_t type;             /**< What the file descriptor is used for */
	int fd;                             /**< The file descriptor itself */
#ifdef HAVE_LIBURING
	int uring_idx;
	int input_pending;                  /**< The number of pending input requests */
	int output_pending;                 /**< The number of pending output requests */
	uring_sched_queue_t input_queue;    /**< The queues for scheduled IO */
	uring_sched_queue_t output_queue;   /**< The queues for scheduled IO */
#endif
};

/** Initializes the poll interface */
void fastd_poll_init(void);
/** Frees the poll interface */
void fastd_poll_free(void);

/** Returns a fastd_poll_fd_t structure */
#define FASTD_POLL_FD(type, fd) ((fastd_poll_fd_t){ type, fd })

/** Registers a new file descriptor to poll on */
void fastd_poll_fd_register(fastd_poll_fd_t *fd);
/** Unregisters and closes a file descriptor */
bool fastd_poll_fd_close(fastd_poll_fd_t *fd);

/** Waits for the next input event */
void fastd_poll_handle(void);
