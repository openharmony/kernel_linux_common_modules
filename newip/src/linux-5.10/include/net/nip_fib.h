/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Linux NewIP INET implementation
 *
 * Based on include/net/ip6_fib.h
 */
#ifndef _NET_NEWIP_FIB_H
#define _NET_NEWIP_FIB_H

#include <net/netlink.h>
#include <net/inetpeer.h>
#include <net/dst.h>
#include <linux/ipv6_route.h>
#include <linux/rtnetlink.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>

#include <linux/newip_route.h>
#include "nip.h"
#include "flow_nip.h"

#define NIN_ROUTE_HSIZE_SHIFT	4
#define NIN_ROUTE_HSIZE		(1 << NIN_ROUTE_HSIZE_SHIFT)

struct nip_fib_config {
	u32 fc_table;
	u32 fc_metric;
	int fc_ifindex;
	u32 fc_flags;
	u32 fc_protocol;
	u32 fc_type;  /* only 8 bits are used */

	struct nip_addr fc_dst;
	struct nip_addr fc_src;
	struct nip_addr fc_gateway;

	struct nl_info fc_nlinfo;
	unsigned long fc_expires;
};

struct nip_fib_node {
	struct hlist_node fib_hlist;
	struct nip_rt_info *nip_route_info;
	struct rcu_head rcu;
};

struct nip_fib_table;

struct nip_rt_info {
	struct dst_entry dst;
	struct dst_entry *from;
	struct nip_fib_table *rt_table;
	struct nip_fib_node __rcu *rt_node;
	struct ninet_dev *rt_idev;
	struct nip_rt_info *__percpu *rt_pcpu;

	atomic_t rt_ref;

	uint32_t rt_flags;
	struct nip_addr gateway;
	struct nip_addr rt_dst;
	struct nip_addr rt_src;

	u32 rt_metric;
	u32 rt_pmtu;
	u8 rt_protocol;
};

static inline struct ninet_dev *nip_dst_idev(struct dst_entry *dst)
{
	return ((struct nip_rt_info *)dst)->rt_idev;
}

struct nip_fib_table {
	u32 nip_tb_id;
	spinlock_t nip_tb_lock;
	struct hlist_head nip_tb_head[NIN_ROUTE_HSIZE];
	unsigned int flags;
};

#define NIP_RT_TABLE_MAIN		RT_TABLE_MAIN
#define NIP_RT_TABLE_LOCAL		RT_TABLE_LOCAL

typedef struct nip_rt_info *(*nip_pol_lookup_t) (struct net *,
						 struct nip_fib_table *,
						 struct flow_nip *, int);

struct nip_fib_table *nip_fib_get_table(struct net *net, u32 id);

struct dst_entry *nip_fib_rule_lookup(struct net *net, struct flow_nip *fln,
				      int flags, int *tbl_type, nip_pol_lookup_t lookup);

#define NIP_RT_EXPIRES_FLAGS 12
static inline void nip_rt_set_expires(struct nip_rt_info *rt,
				      unsigned long expires)
{
	rt->dst.expires = expires;

	rt->rt_flags |= NIP_RT_EXPIRES_FLAGS;
}

static inline void nip_rt_clean_expires(struct nip_rt_info *rt)
{
	rt->rt_flags &= ~NIP_RT_EXPIRES_FLAGS;
	rt->dst.expires = 0;
}

static inline void nip_rt_put(struct nip_rt_info *rt)
{
	BUILD_BUG_ON(offsetof(struct nip_rt_info, dst) != 0);
	dst_release(&rt->dst);
}

void nip_rt_free_pcpu(struct nip_rt_info *non_pcpu_rt);

static inline void nip_rt_hold(struct nip_rt_info *rt)
{
	atomic_inc(&rt->rt_ref);
}

static inline void nip_rt_release(struct nip_rt_info *rt)
{
	if (atomic_dec_and_test(&rt->rt_ref)) {
		nip_rt_free_pcpu(rt);
		dst_dev_put(&rt->dst);

		dst_release(&rt->dst);
	}
}

int nip_fib_init(void);

void nip_fib_gc_cleanup(void);

struct nip_fib_node *nip_fib_locate(struct hlist_head *nip_tb_head,
				    const struct nip_addr *daddr);

void nip_fib_clean_all(struct net *net,
		       int (*func)(struct nip_rt_info *, void *arg), void *arg);

int nip_fib_add(struct nip_fib_table *table, struct nip_rt_info *rt);

int nip_fib_del(struct nip_rt_info *rt_info, struct nl_info *info);

int nip_set_route_netlink(struct net *net, struct nip_rtmsg *rtmsg);

int nip_del_route_netlink(struct net *net, struct nip_rtmsg *rtmsg);

#endif /* _NET_NEWIP_FIB_H */
