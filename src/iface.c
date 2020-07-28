// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Android port contributor:
  Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
  All rights reserved.
*/

/**
   \file

   Management of the TUN/TAP interface
*/

#include "config.h"
#include "fastd.h"
#include "peer.h"
#include "poll.h"

#include <net/if.h>
#include <sys/ioctl.h>

#ifdef __linux__

#include <linux/if_tun.h>

#else

#ifndef __APPLE__
#include <net/if_tun.h>
#endif

#ifdef __FreeBSD__
#include <net/if_tap.h>
#endif

#endif


/** Defines if the platform uses an address family header on TUN interfaces */
#if defined(__linux__) || defined(__APPLE__)
static const bool multiaf_tun = false;
#else
static const bool multiaf_tun = true;
#endif


/** The actual interface type */
typedef enum fastd_iface_type {
	IFACE_TYPE_UNSPEC = 0, /**< Unknown interface */
	IFACE_TYPE_TAP,        /**< TAP interface */
	IFACE_TYPE_TUN,        /**< TUN interface */
} fastd_iface_type_t;

/** Returns the interface type for the configured mode of operation */
static inline fastd_iface_type_t get_iface_type(void) {
	switch (conf.mode) {
	case MODE_TAP:
	case MODE_MULTITAP:
		return IFACE_TYPE_TAP;

	case MODE_TUN:
		return IFACE_TYPE_TUN;

	default:
		return IFACE_TYPE_UNSPEC;
	}
}

static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu);
static void cleanup_iface(fastd_iface_t *iface);


#ifdef __linux__

/** Opens the TUN/TAP device helper shared by Android and Linux targets */
static bool open_iface_linux(fastd_iface_t *iface, const char *ifname, uint16_t mtu, const char *dev_name) {
	struct ifreq ifr = {};

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR | O_NONBLOCK));
	if (iface->fd.fd < 0)
		exit_errno("could not open TUN/TAP device file");

	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		ifr.ifr_flags = IFF_TAP;
		break;

	case IFACE_TYPE_TUN:
		ifr.ifr_flags = IFF_TUN;
		break;

	default:
		exit_bug("invalid mode");
	}

	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(iface->fd.fd, TUNSETIFF, &ifr) < 0) {
		pr_error_errno("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
		return false;
	}

	iface->name = fastd_strndup(ifr.ifr_name, IFNAMSIZ - 1);

	if (ioctl(ctx.ioctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno("SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != mtu) {
		ifr.ifr_mtu = mtu;
		if (ioctl(ctx.ioctl_sock, SIOCSIFMTU, &ifr) < 0) {
			pr_error_errno("unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed");
			return false;
		}
	}

	return true;
}

/** Removes TUN/TAP interfaces on platforms which need this */
static void cleanup_iface(UNUSED fastd_iface_t *iface) {}

#endif

#if defined(__ANDROID__)

/** Opens the TUN/TAP device */
static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu) {
	if (conf.android_integration) {
		if (get_iface_type() != IFACE_TYPE_TUN)
			exit_bug("Non-TUN iface type with Android integration");

		pr_debug("using android TUN fd");
		iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, fastd_android_receive_tunfd());
		fastd_android_send_pid();

		return true;
	} else {
		/* this requires root on Android */
		return open_iface_linux(iface, ifname, mtu, "/dev/tun");
	}
}

#elif defined(__linux__)

/** Opens the TUN/TAP device */
static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu) {
	return open_iface_linux(iface, ifname, mtu, "/dev/net/tun");
}

#elif defined(__FreeBSD__) || defined(__OpenBSD__)

/** Sets the MTU of the TUN/TAP device */
static bool set_tun_mtu(fastd_iface_t *iface, uint16_t mtu) {
	struct tuninfo tuninfo;

	if (ioctl(iface->fd.fd, TUNGIFINFO, &tuninfo) < 0)
		exit_errno("TUNGIFINFO ioctl failed");

	tuninfo.mtu = mtu;

	if (ioctl(iface->fd.fd, TUNSIFINFO, &tuninfo) < 0) {
		pr_error_errno("TUNSIFINFO ioctl failed");
		return false;
	}

	return true;
}

#ifdef __FreeBSD__

/** Sets the MTU of the TAP device */
static bool set_tap_mtu(fastd_iface_t *iface, uint16_t mtu) {
	struct tapinfo tapinfo;

	if (ioctl(iface->fd.fd, TAPGIFINFO, &tapinfo) < 0)
		exit_errno("TAPGIFINFO ioctl failed");

	tapinfo.mtu = mtu;

	if (ioctl(iface->fd.fd, TAPSIFINFO, &tapinfo) < 0) {
		pr_error_errno("TAPSIFINFO ioctl failed");
		return false;
	}

	return true;
}

/** Sets up the TUN device */
static bool setup_tun(fastd_iface_t *iface, uint16_t mtu) {
	int one = 1;
	if (ioctl(iface->fd.fd, TUNSIFHEAD, &one) < 0) {
		pr_error_errno("TUNSIFHEAD ioctl failed");
		return false;
	}

	return set_tun_mtu(iface, mtu);
}

/** Sets up the TAP device */
static bool setup_tap(fastd_iface_t *iface, uint16_t mtu) {
	struct ifreq ifr = {};

	if (ioctl(iface->fd.fd, TAPGIFNAME, &ifr) < 0)
		exit_errno("TAPGIFNAME ioctl failed");

	free(iface->name);
	iface->name = fastd_strndup(ifr.ifr_name, IFNAMSIZ - 1);

	return set_tap_mtu(iface, mtu);
}

/** Opens the TUN/TAP device */
static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu) {
	char dev_name[5 + IFNAMSIZ] = "/dev/";
	const char *type;
	bool cleanup = true;

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		type = "tap";
		break;

	case IFACE_TYPE_TUN:
		type = "tun";
		break;

	default:
		exit_bug("invalid mode");
	}

	if (ifname) {
		if (strlen(ifname) <= 3 || strncmp(ifname, type, 3) != 0) {
			pr_error("Invalid %s interface `%s'", type, ifname);
			return false;
		}

		strncat(dev_name, ifname, IFNAMSIZ - 1);

		if (if_nametoindex(ifname))
			cleanup = false;
	} else {
		strncat(dev_name, type, IFNAMSIZ - 1);
	}

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR | O_NONBLOCK));
	if (iface->fd.fd < 0) {
		pr_error_errno("could not open TUN/TAP device file");
		return false;
	}

	if (!(iface->name = fdevname_r(iface->fd.fd, fastd_alloc(IFNAMSIZ), IFNAMSIZ)))
		exit_errno("could not get TUN/TAP interface name");

	iface->cleanup = cleanup;

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		if (!setup_tap(iface, mtu))
			return false;
		break;

	case IFACE_TYPE_TUN:
		if (!setup_tun(iface, mtu))
			return false;
		break;

	default:
		exit_bug("invalid mode");
	}

	return true;
}

/** Removes TUN/TAP interfaces on platforms which need this */
static void cleanup_iface(fastd_iface_t *iface) {
	if (!iface->cleanup)
		return;

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);

	if (ioctl(ctx.ioctl_sock, SIOCIFDESTROY, &ifr) < 0)
		pr_warn_errno("unable to destroy TUN/TAP interface");
}

#else /* __OpenBSD__ */

/** Opens the TUN/TAP device */
static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu) {
	if (!ifname) {
		pr_error("config error: no interface name given.");
		return false;
	}

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		if (strncmp(ifname, "tap", 3) != 0) {
			pr_error("config error: `%s' doesn't seem to be a TAP device", ifname);
			return false;
		}
		break;

	case IFACE_TYPE_TUN:
		if (strncmp(ifname, "tun", 3) != 0) {
			pr_error("config error: `%s' doesn't seem to be a TUN device", ifname);
			return false;
		}
		break;

	default:
		exit_bug("invalid mode");
	}

	char dev_name[5 + IFNAMSIZ] = "/dev/";
	strncat(dev_name, ifname, IFNAMSIZ - 1);

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR | O_NONBLOCK));
	if (iface->fd.fd < 0) {
		pr_error_errno("could not open TUN device file");
		return false;
	}

	iface->name = fastd_strndup(ifname, IFNAMSIZ - 1);

	if (!set_tun_mtu(iface, mtu))
		return false;

	return true;
}

/** Removes TUN/TAP interfaces on platforms which need this */
static void cleanup_iface(UNUSED fastd_iface_t *iface) {}

#endif

#elif __APPLE__

/** Opens the TUN/TAP device */
static bool open_iface(fastd_iface_t *iface, const char *ifname, uint16_t mtu) {
	const char *devtype;
	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		devtype = "tap";
		break;

	case IFACE_TYPE_TUN:
		devtype = "tun";
		break;

	default:
		exit_bug("invalid mode");
	}

	char dev_name[5 + IFNAMSIZ] = "/dev/";
	if (!ifname) {
		pr_error("config error: no interface name given.");
		return false;
	} else if (strncmp(ifname, devtype, 3) != 0) {
		pr_error("config error: `%s' doesn't seem to be a %s device", ifname, devtype);
		return false;
	} else {
		strncat(dev_name, ifname, IFNAMSIZ - 1);
	}

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR | O_NONBLOCK));
	if (iface->fd.fd < 0) {
		pr_error_errno("could not open TUN device file");
		return false;
	}

	iface->name = fastd_strndup(ifname, IFNAMSIZ - 1);

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;
	if (ioctl(ctx.ioctl_sock, SIOCSIFMTU, &ifr) < 0) {
		pr_error_errno("SIOCSIFMTU ioctl failed");
		return false;
	}

	return true;
}

/** Removes TUN/TAP interfaces on platforms which need this */
static void cleanup_iface(UNUSED fastd_iface_t *iface) {}

#else

#error unknown TUN/TAP implementation

#endif

struct iface_priv {
	fastd_iface_t *iface;
	fastd_buffer_t buffer;
};

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_iface_handle_callback(ssize_t len, void *p);
#endif

/** Reads a packet from the TUN/TAP device */
void fastd_iface_handle(fastd_iface_t *iface) {
#ifdef HAVE_LIBURING
	struct iface_priv *priv = fastd_new_aligned(struct iface_priv, 16);
#else
	uint8_t tmp_priv[sizeof(struct iface_priv)] __attribute__((aligned(8))) = {};
	struct iface_priv *priv = tmp_priv;
#endif
	size_t max_len = fastd_max_payload(iface->mtu);

	priv->iface = iface;

	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN)
		priv->buffer = fastd_buffer_alloc(max_len + 4, conf.min_encrypt_head_space + 12, conf.min_encrypt_tail_space);
	else
		priv->buffer = fastd_buffer_alloc(max_len, conf.min_encrypt_head_space, conf.min_encrypt_tail_space);

#ifndef HAVE_LIBURING
	ssize_t len = read(iface->fd.fd, buffer.data, max_len);
#else
	ctx.func_read(&iface->fd, priv->buffer.data, max_len, priv, &fastd_iface_handle_callback);
}

void fastd_iface_handle_callback(ssize_t len, void *p) {
	struct iface_priv *priv = p;
#endif
	if (len < 0) {
		pr_debug("read callback error");
		goto free;
		}

	priv->buffer.len = len;

	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN)
		fastd_buffer_push_head(&priv->buffer, 4);

	fastd_send_data(priv->buffer, NULL, priv->iface->peer);

free:
#ifdef HAVE_LIBURING
	free(priv);
#endif
}

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_iface_write_callback(ssize_t ret, void *p);
#endif

/** Writes a packet to the TUN/TAP device */
void fastd_iface_write(fastd_iface_t *iface, fastd_buffer_t buffer) {
	if (!buffer.len) {
		pr_debug("fastd_iface_write: truncated packet");
		return;
	}

	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN) {
		uint8_t version = *((uint8_t *)buffer.data) >> 4;
		uint32_t af;

		switch (version) {
		case 4:
			af = htonl(AF_INET);
			break;

		case 6:
			af = htonl(AF_INET6);
			break;

		default:
			pr_debug("fastd_iface_write: unknown IP version %u", version);
			return;
		}

		fastd_buffer_pull_head(&buffer, 4);
		memcpy(buffer.data, &af, 4);
	}

#ifndef HAVE_LIBURING
	if (write(iface->fd.fd, buffer.data, buffer.len) < 0)
		pr_debug2_errno("write");

#else
	ctx.func_write(&iface->fd, buffer.data, buffer.len, NULL, fastd_iface_write_callback);
}

void fastd_iface_write_callback(ssize_t ret, void *p) {
	if (ret < 0)
		pr_debug2_errno("write");
	else
		uring_debug("fastd_iface_write_callback() successful");
#endif
}

/** Opens a new TUN/TAP interface, optionally associated with a specific peer */
fastd_iface_t *fastd_iface_open(fastd_peer_t *peer) {
	const char *ifname = conf.ifname;
	char ifnamebuf[IFNAMSIZ];

	if (peer) {
		if (peer->ifname)
			ifname = peer->ifname;
		else if (!fastd_config_single_iface() && !(ifname && strchr(ifname, '%')))
			ifname = NULL;
	}

	const char *percent = ifname ? strchr(ifname, '%') : NULL;
	if (percent) {
		if (peer) {
			char prefix[percent - ifname + 1];
			memcpy(prefix, ifname, percent - ifname);
			prefix[percent - ifname] = 0;

			ifname = NULL;

			switch (percent[1]) {
			case 'n':
				if (peer->name) {
					snprintf(
						ifnamebuf, sizeof(ifnamebuf), "%s%s%s", prefix, peer->name,
						percent + 2);
					ifname = ifnamebuf;
				}

				break;

			case 'k': {
				char buf[17];
				if (conf.protocol->describe_peer(peer, buf, sizeof(buf))) {
					snprintf(ifnamebuf, sizeof(ifnamebuf), "%s%s%s", prefix, buf, percent + 2);
					ifname = ifnamebuf;
				}
			} break;

			default:
				exit_bug("fastd_iface_open: invalid interface pattern");
			}
		} else {
			pr_error("invalid TUN/TAP device name: `%%n' and `%%k' patterns can't be used in TAP mode");
			return NULL;
		}
	}

	fastd_iface_t *iface = fastd_new0(fastd_iface_t);
	iface->peer = peer;
	iface->mtu = fastd_peer_get_mtu(peer);
	iface->fd.fd = -1;

	pr_debug("initializing TUN/TAP device...");

	if (!open_iface(iface, ifname, iface->mtu)) {
		if (iface->fd.fd >= 0) {
			if (close(iface->fd.fd) == 0)
				cleanup_iface(iface);
			else
				pr_warn_errno("closing TUN/TAP: close");
		}

		free(iface->name);
		free(iface);
		return NULL;
	}

	if (iface->name)
		pr_debug("TUN/TAP device `%s' initialized.", iface->name);
	else
		pr_debug("TUN/TAP device initialized.");

#ifdef HAVE_LIBURING
	fastd_uring_fd_register(&iface->fd);
	//FIXME ctx.func_fd_register(&iface->fd);
#else
	fastd_poll_fd_register(&iface->fd);
#endif

	return iface;
}

/** Closes the TUN/TAP device */
void fastd_iface_close(fastd_iface_t *iface) {
#ifdef HAVE_LIBURING
	if (!ctx.func_fd_close(&iface->fd))
#else
	if (!fastd_poll_fd_close(&iface->fd))
#endif
		cleanup_iface(iface);
	else
		pr_warn_errno("closing TUN/TAP: close");

	free(iface->name);
	free(iface);
}
