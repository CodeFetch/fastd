// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2019, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Android port contributor:
  Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
  All rights reserved.
*/

/**
   \file

   Functions for sending packets
*/


#include "fastd.h"
#include "peer.h"

#include <sys/uio.h>


/** Adds packet info to ancillary control messages */
static inline void add_pktinfo(struct msghdr *msg, const fastd_peer_address_t *local_addr) {
#ifdef __ANDROID__
	/* PKTINFO will mess with Android VpnService.protect(socket) */
	if (conf.android_integration)
		return;
#endif
	if (!local_addr)
		return;

	struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + msg->msg_controllen);

#ifdef USE_PKTINFO
	if (local_addr->sa.sa_family == AF_INET) {
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in_pktinfo pktinfo = {};
		pktinfo.ipi_spec_dst = local_addr->in.sin_addr;
		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
		return;
	}
#endif

	if (local_addr->sa.sa_family == AF_INET6) {
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in6_pktinfo pktinfo = {};
		pktinfo.ipi6_addr = local_addr->in6.sin6_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
			pktinfo.ipi6_ifindex = local_addr->in6.sin6_scope_id;

		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
	}
}

struct send_priv {
	uint8_t cbuf[1024];
	fastd_buffer_t buffer;
	uint8_t packet_type;
	fastd_peer_t *peer;
	fastd_peer_address_t remote_addr6;
	fastd_poll_fd_t fd;
	size_t stat_size;
	struct iovec iov[2];
	struct msghdr msg;
};

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_send_callback_first(ssize_t ret, void *p);
#endif

/** Sends a packet of a given type */
static void send_type(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size) {
	if (!sock)
		exit_bug("send: sock == NULL");

#ifdef HAVE_LIBURING
	struct send_priv *priv = fastd_new_aligned(struct send_priv, 16);
#else
	uint8_t tmp_priv[sizeof(struct send_priv)] __attribute__((aligned(8))) = {};
	struct send_priv *priv = tmp_priv;
#endif

	priv->buffer = buffer;
	priv->packet_type = packet_type;
	priv->peer = peer;
	memcpy(&priv->fd, &sock->fd, sizeof(priv->fd));
	priv->stat_size = stat_size;

	/* TODO: find out if using remote_addr is save */

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		priv->msg.msg_name = (void *)&remote_addr->in;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		priv->msg.msg_name = (void *)&remote_addr->in6;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug("unsupported address family");
	}

	if (sock->bound_addr->sa.sa_family == AF_INET6) {
		priv->remote_addr6 = *remote_addr;
		fastd_peer_address_widen(&priv->remote_addr6);

		priv->msg.msg_name = (void *)&priv->remote_addr6.in6;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in6);
	}

	priv->iov[0].iov_base = &priv->packet_type;
	priv->iov[0].iov_len = 1;
	priv->iov[1].iov_base = buffer.data;
	priv->iov[1].iov_len = buffer.len;

	priv->msg.msg_iov = priv->iov;
	priv->msg.msg_iovlen = buffer.len ? 2 : 1;
	priv->msg.msg_control = priv->cbuf;
	priv->msg.msg_controllen = 0;

	add_pktinfo(&priv->msg, local_addr);

	if (!priv->msg.msg_controllen)
		priv->msg.msg_control = NULL;

#ifndef HAVE_LIBURING
	int ret = sendmsg(sock->fd.fd, &priv->msg, 0);
#else
	ctx.func_sendmsg(&priv->fd, &priv->msg, 0, priv, fastd_send_callback_first);
}

/* forward declaration */
void fastd_send_callback_second(ssize_t ret, void *p);

void fastd_send_callback_first(ssize_t ret, void *p) {
	struct send_priv *priv = p;
#endif
	if (ret < 0 && priv->msg.msg_controllen) {
		switch (errno) {
		case EINVAL:
		case ENETUNREACH:
			pr_debug2("sendmsg: %s (trying again without pktinfo)", strerror(errno));

			if (priv->peer && !fastd_peer_handshake_scheduled(priv->peer))
				fastd_peer_schedule_handshake_default(priv->peer);

			priv->msg.msg_control = NULL;
			priv->msg.msg_controllen = 0;

#ifdef HAVE_LIBURING
			ctx.func_sendmsg(&priv->fd, &priv->msg, 0, priv, fastd_send_callback_second);
#else
			ret = sendmsg(priv->fd.fd, &priv->msg, 0);
#endif
		}
	}

#ifdef HAVE_LIBURING
}

void fastd_send_callback_second(ssize_t ret, void *p) {
	struct send_priv *priv = p;
#endif

	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			pr_debug2_errno("sendmsg");
			fastd_stats_add(priv->peer, STAT_TX_DROPPED, priv->stat_size);
			break;

		case ENETDOWN:
		case ENETUNREACH:
		case EHOSTUNREACH:
			pr_debug_errno("sendmsg");
			fastd_stats_add(priv->peer, STAT_TX_ERROR, priv->stat_size);
			break;

		default:
			pr_warn_errno("sendmsg");
			fastd_stats_add(priv->peer, STAT_TX_ERROR, priv->stat_size);
		}
	} else {
		fastd_stats_add(priv->peer, STAT_TX, priv->stat_size);
	}

	fastd_buffer_free(priv->buffer);

#ifdef HAVE_LIBURING
	free(priv);
#endif
}

/** Sends a payload packet */
void fastd_send(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_DATA, buffer, stat_size);
}

/** Sends a handshake packet */
void fastd_send_handshake(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t buffer) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_HANDSHAKE, buffer, 0);
}

/** Encrypts and sends a payload packet to all peers */
static inline void send_all(fastd_buffer_t buffer, fastd_peer_t *source) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, i);
		if (dest == source || !fastd_peer_is_established(dest))
			continue;

		/* optimization, primarily for TUN mode: don't duplicate the buffer for the last (or only) peer */
		if (i == VECTOR_LEN(ctx.peers) - 1) {
			conf.protocol->send(dest, buffer);
			return;
		}

		conf.protocol->send(
			dest, fastd_buffer_dup(buffer, conf.min_encrypt_head_space, conf.min_encrypt_tail_space));
	}

	fastd_buffer_free(buffer);
}

/** Handles sending of a payload packet to a single peer in TAP mode */
static inline bool send_data_tap_single(fastd_buffer_t buffer, fastd_peer_t *source) {
	if (conf.mode != MODE_TAP)
		return false;

	if (buffer.len < sizeof(fastd_eth_header_t)) {
		pr_debug("truncated ethernet packet");
		fastd_buffer_free(buffer);
		return true;
	}

	if (!source) {
		fastd_eth_addr_t src_addr = fastd_buffer_source_address(buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(NULL, src_addr);
	}

	fastd_eth_addr_t dest_addr = fastd_buffer_dest_address(buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return false;

	fastd_peer_t *dest;
	bool found = fastd_peer_find_by_eth_addr(dest_addr, &dest);

	if (!found)
		return false;

	if (!dest || dest == source) {
		fastd_buffer_free(buffer);
		return true;
	}

	conf.protocol->send(dest, buffer);
	return true;
}

/** Sends a buffer of payload data to other peers */
void fastd_send_data(fastd_buffer_t buffer, fastd_peer_t *source, fastd_peer_t *dest) {
	if (dest) {
		conf.protocol->send(dest, buffer);
		return;
	}

	if (send_data_tap_single(buffer, source))
		return;

	/* TUN mode or multicast packet */
	send_all(buffer, source);
}
