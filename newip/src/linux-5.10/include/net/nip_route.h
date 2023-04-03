/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Based on include/net/ip6_route.h
 */
#ifndef _NET_NIP_ROUTE_H
#define _NET_NIP_ROUTE_H

#include <net/net_namespace.h>
#include "nip_fib.h"
#include "nip_addrconf.h"

#define NIP_RT_PRIO_USER 1024

struct nip_rt_info *nip_addrconf_dst_alloc(struct ninet_dev *idev,
					   const struct nip_addr *addr);


int nip_route_input(struct sk_buff *skb);
struct dst_entry *nip_route_input_lookup(struct net *net,
					 struct net_device *dev,
					 struct flow_nip *fln, int flags, int *tbl_type);

struct dst_entry *nip_route_output_flags(struct net *net, const struct sock *sk,
					 struct flow_nip *fln, int flags);


static inline struct dst_entry *nip_route_output(struct net *net,
						 const struct sock *sk,
						 struct flow_nip *fln)
{
	return nip_route_output_flags(net, sk, fln, 0);
}

struct nip_rt_info *nip_pol_route(struct net *net, struct nip_fib_table *table,
				  int oif, struct flow_nip *fln, int flags);

bool nip_bind_addr_check(struct net *net,
			 struct nip_addr *addr);

int nip_ins_rt(struct nip_rt_info *rt);
int nip_del_rt(struct nip_rt_info *rt);

static inline int nip_route_get_saddr(struct net *net, struct nip_rt_info *rt,
				      const struct nip_addr *daddr,
				      struct nip_addr *saddr)
{
	struct ninet_dev *idev =
	    rt ? nip_dst_idev((struct dst_entry *)rt) : NULL;
	int err = 0;

	err = nip_dev_get_saddr(net, idev ? idev->dev : NULL, daddr, saddr);

	return err;
}

void nip_rt_ifdown(struct net *net, struct net_device *dev);

int nip_route_ioctl(struct net *net, unsigned int cmd, struct nip_rtmsg *rtmsg);

int nip_route_init(void);

void nip_route_cleanup(void);

#endif /* _NET_NIP_ROUTE_H */
