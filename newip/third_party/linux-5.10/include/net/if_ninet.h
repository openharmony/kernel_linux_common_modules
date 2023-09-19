/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on include/net/if_inet6.h
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 * NewIP inet interface/address list definitions
 * Linux NewIP INET implementation
 */
#ifndef _NET_IF_NINET_H
#define _NET_IF_NINET_H

#include <linux/nip.h>

#define NIP_IOCTL_FLAG_INVALID  35

enum {
	NINET_IFADDR_STATE_NEW,
	NINET_IFADDR_STATE_DEAD,
};

struct ninet_ifaddr {
	struct nip_addr addr;

	/* In seconds, relative to tstamp. Expiry is at tstamp + HZ * lft. */
	__u32 valid_lft;
	__u32 preferred_lft;
	refcount_t refcnt;

	/* protect one ifaddr itself */
	spinlock_t lock;

	int state;

	__u32 flags;

	unsigned long cstamp; /* created timestamp */
	unsigned long tstamp; /* updated timestamp */

	struct ninet_dev *idev;
	struct nip_rt_info *rt;

	struct hlist_node addr_lst;
	struct list_head if_list;

	struct rcu_head rcu;
};

struct ninet_dev {
	struct net_device *dev;

	struct list_head addr_list;

	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;

	struct neigh_parms *nd_parms;
	struct nip_devconf cnf;

	unsigned long tstamp; /* newip InterfaceTable update timestamp */
	struct rcu_head rcu;
};

int ninet_gifconf(struct net_device *dev, char __user *buf, int len, int size);
int nip_dev_ifconf(struct net *net, struct ifconf *ifc, int size);
int ninet_ioctl_cmd(struct socket *sock, const struct iovec *iov);

#endif
