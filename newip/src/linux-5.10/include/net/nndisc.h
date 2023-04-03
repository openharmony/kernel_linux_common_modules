/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Based on include/net/ndisc.h
 */
#ifndef _NNDISC_H
#define _NNDISC_H

#include <net/neighbour.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/hash.h>
#include <linux/nip_icmp.h>

#define NEWIP_NEIGH_BUCKET_MAX 8
extern struct neigh_table nnd_tbl;

#define NIP_ARP_NS  0x01 /* ARP request */
#define NIP_ARP_NA  0x02 /* ARP response */

struct nnd_msg {
	struct nip_icmp_hdr icmph;
	__u8 data[0];
};

static inline bool neigh_key_eq800(const struct neighbour *n, const void *pkey)
{
	struct nip_addr *a1, *a2;

	a1 = (struct nip_addr *)(pkey);
	a2 = (struct nip_addr *)(n->primary_key);

#define RIGHT_POS_3 3
	return a1->bitlen == a2->bitlen && a1->bitlen <= NIP_ADDR_BIT_LEN_MAX &&
	       memcmp(&a1->v.u, &a2->v.u, a1->bitlen >> RIGHT_POS_3) == 0;
}

static inline u32 nndisc_hashfn(const void *pkey, const struct net_device *dev,
				__u32 *hash_rnd)
{
	return (*(int *)pkey % NEWIP_NEIGH_BUCKET_MAX);
}

static inline struct neighbour *__nip_neigh_lookup_noref(struct net_device *dev,
							 const void *pkey)
{
	return ___neigh_lookup_noref(&nnd_tbl, neigh_key_eq800, nndisc_hashfn,
				     pkey, dev);
}

static inline struct neighbour *__nip_neigh_lookup(struct net_device *dev,
						   const void *pkey)
{
	struct neighbour *n;

	rcu_read_lock_bh();
	n = __nip_neigh_lookup_noref(dev, pkey);
	if (n && !refcount_inc_not_zero(&n->refcnt))
		n = NULL;
	rcu_read_unlock_bh();

	return n;
}

int nndisc_rcv(struct sk_buff *skb);

int nndisc_init(void);

#endif
