// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * DEVICE - NEWIP device support.
 * Based on net/ipv4/devinet.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/nip_fib.h>
#include <net/nip_addrconf.h>
#include "tcp_nip_parameter.h"

int ninet_gifconf(struct net_device *dev, char __user *buf, int len, int size)
{
	struct ninet_dev *nin_dev = __nin_dev_get(dev);
	const struct ninet_ifaddr *ifa;
	struct ifreq ifr;
	int done = 0;

	if (WARN_ON(size > sizeof(struct ifreq)))
		goto out;
	if (!nin_dev)
		goto out;

	list_for_each_entry(ifa, &nin_dev->addr_list, if_list) {
		ifa = rcu_dereference_protected(ifa, lockdep_is_held(&ifa->lock));
		if (!ifa) {
			done = -EFAULT;
			break;
		}
		if (!buf) {
			done += size;
			continue;
		}
		if (len < size)
			break;
		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifa->rt->dst.dev->name);

		(*(struct sockaddr_nin *)&ifr.ifr_addr).sin_family = AF_NINET;
		memcpy(&((struct sockaddr_nin *)&ifr.ifr_addr)->sin_addr, &ifa->addr,
		       sizeof(struct nip_addr));

		if (copy_to_user(buf + done, &ifr, size)) {
			done = -EFAULT;
			break;
		}
		len -= size;
		done += size;
	}
out:
	return done;
}

