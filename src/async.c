// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Asynchronous notifications
*/


#include "async.h"
#include "fastd.h"

#include <sys/uio.h>


/** The packet header used on the async notification sockets */
typedef struct fastd_async_hdr {
	fastd_async_type_t type; /**< The type of the notification */
	size_t len;              /**< The length of the notification payload */
} fastd_async_hdr_t;


/** Initializes the async notification sockets */
void fastd_async_init(void) {
	int fds[2];

	/* use socketpair with SOCK_DGRAM instead of pipe2 with O_DIRECT to keep this portable */
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, fds))
		exit_errno("socketpair");

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fds[0]);
	fastd_setnonblock(fds[1]);
#endif

	ctx.async_rfd = FASTD_POLL_FD(POLL_TYPE_ASYNC, fds[0]);
	ctx.async_wfd = fds[1];

#ifdef HAVE_LIBURING
	ctx.func_fd_register(&ctx.async_rfd);
#else
	fastd_poll_fd_register(&ctx.async_rfd);
#endif
}

/** Handles a DNS resolver response */
static void handle_resolve_return(const fastd_async_resolve_return_t *resolve_return) {
	fastd_peer_t *peer = fastd_peer_find_by_id(resolve_return->peer_id);
	if (!peer || !fastd_peer_is_enabled(peer))
		return;

	if (fastd_peer_is_dynamic(peer))
		exit_bug("resolve return for dynamic peer");

	fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, resolve_return->remote);
	fastd_peer_handle_resolve(peer, remote, resolve_return->n_addr, resolve_return->addr);
}

#ifdef WITH_DYNAMIC_PEERS

/** Handles a on-verify response */
static void handle_verify_return(const fastd_async_verify_return_t *verify_return) {
	fastd_peer_t *peer = fastd_peer_find_by_id(verify_return->peer_id);
	if (!peer)
		return;

	if (!fastd_peer_is_dynamic(peer))
		exit_bug("verify return for permanent peer");

	fastd_peer_set_verified(peer, verify_return->ok);

	conf.protocol->handle_verify_return(
		peer, verify_return->sock, &verify_return->local_addr, &verify_return->remote_addr,
		verify_return->protocol_data, verify_return->ok);
}

#endif

struct async_priv {
	struct msghdr msg;
	struct iovec vec[2];
	fastd_async_hdr_t header;
	uint8_t *buf;
};

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_async_handle_callback_first(ssize_t ret, void *p);
void fastd_async_handle_callback_second(ssize_t ret, void *p);
#endif

/** Reads and handles a single notification from the async notification socket */
void fastd_async_handle(void) {
#ifdef HAVE_LIBURING
	struct async_priv *priv = fastd_new_aligned(struct async_priv, 16);
#else
	uint8_t tmp_priv[sizeof(struct async_priv)] __attribute__((aligned(8))) = {};
	struct async_priv *priv = tmp_priv;
#endif

	priv->vec[0].iov_base = &priv->header;
	priv->vec[0].iov_len = sizeof(priv->header);

	priv->msg.msg_iov = priv->vec;
	priv->msg.msg_iovlen = 1;

#ifndef HAVE_LIBURING
	ssize_t ret = recvmsg(ctx.async_rfd.fd, &priv->msg, MSG_PEEK)
#else
	ctx.func_recvmsg(&ctx.async_rfd, &priv->msg, MSG_PEEK, priv, fastd_async_handle_callback_first);
}

void fastd_async_handle_callback_first(ssize_t ret, void *p) {
	struct async_priv *priv = p;
#endif

	if (ret < 0)
		exit_errno("fastd_async_handle: recvmsg");

#ifdef HAVE_LIBURING
	priv->buf = fastd_alloc_aligned(priv->header.len, 16);
#else
	uint8_t buf[priv->header.len] __attribute__((aligned(8)));
	priv->buf = buf;
#endif
	priv->vec[1].iov_base = priv->buf;
	priv->vec[1].iov_len = sizeof(priv->buf);
	priv->msg.msg_iovlen = 2;

#ifndef HAVE_LIBURING
	ret = recvmsg(ctx.async_rfd.fd, &priv->msg, 0);
#else
	ctx.func_recvmsg(&ctx.async_rfd, &priv->msg, 0, priv, fastd_async_handle_callback_second);
}

void fastd_async_handle_callback_second(ssize_t ret, void *p) {
	struct async_priv *priv = p;
#endif
	if (ret < 0)
		exit_errno("fastd_async_handle: recvmsg");

	switch (priv->header.type) {
	case ASYNC_TYPE_NOP:
		break;

	case ASYNC_TYPE_RESOLVE_RETURN:
		handle_resolve_return((const fastd_async_resolve_return_t *)priv->buf);
		break;

#ifdef WITH_DYNAMIC_PEERS
	case ASYNC_TYPE_VERIFY_RETURN:
		handle_verify_return((const fastd_async_verify_return_t *)priv->buf);
		break;
#endif

	default:
		exit_bug("fastd_async_handle: unknown type");
	}

#ifdef HAVE_LIBURING
	free(priv->buf);
	free(priv);
#endif
}

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_async_enqueue_callback(ssize_t ret, void *p);
#endif

/** Enqueues a new async notification */
void fastd_async_enqueue(fastd_async_type_t type, const void *data, size_t len) {
#ifdef HAVE_LIBURING
	struct async_priv *priv = fastd_new_aligned(struct async_priv, 16);
#else
	uint8_t tmp_priv[sizeof(struct async_priv)] __attribute__((aligned(8))) = {};
	struct async_priv *priv = tmp_priv;
#endif
	/* use memset to zero the holes in the struct to make valgrind happy */
	memset(&priv->header, 0, sizeof(priv->header));
	priv->header.type = type;
	priv->header.len = len;

	priv->vec[0].iov_base = &priv->header;
	priv->vec[0].iov_len = sizeof(priv->header);
	priv->vec[1].iov_base = (void *)data;
	priv->vec[1].iov_len = len;

	priv->msg.msg_iov = priv->vec;
	priv->msg.msg_iovlen = len ? 2 : 1;

#ifndef HAVE_LIBURING
	ssize_t ret = sendmsg(ctx.async_wfd.fd, &priv->msg, 0);
#else
	ctx.func_sendmsg(&ctx.async_rfd, &priv->msg, 0, priv, fastd_async_enqueue_callback);
}

void fastd_async_enqueue_callback(ssize_t ret, void *p) {
#endif
	if (ret < 0)
		pr_warn_errno("fastd_async_enqueue: sendmsg");
}
