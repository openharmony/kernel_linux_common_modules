/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on include/net/ip.h
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Changes:
 *		Mike McLagan    :       Routing by source
 *
 * Based on include/net/protocol.h
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Definitions for the NewIP module.
 */
#ifndef _NET_NEWIP_H
#define _NET_NEWIP_H

#include <net/dst.h>
#include <net/protocol.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/nip.h>

#include <net/tcp.h>
#include <uapi/linux/nip_addr.h>
#include "if_ninet.h"
#include "flow_nip.h"

#define NIP_MAX_SOCKET_NUM 1024

struct ninet_protocol {
	void (*early_demux)(struct sk_buff *skb);

	int (*handler)(struct sk_buff *skb);

	void (*err_handler)(struct sk_buff *skb,
			    struct ninet_skb_parm *opt,
			    u8 type, u8 code, int offset, __be32 info);
	unsigned int flags;
};

#define NIPCB(skb)  ((struct ninet_skb_parm *)&(TCP_SKB_CB(skb)->header.hnip))

extern const struct ninet_protocol __rcu *ninet_protos[MAX_INET_PROTOS];
extern const struct proto_ops ninet_dgram_ops;
extern const struct proto_ops ninet_stream_ops;
extern struct neigh_table nnd_tbl;

int tcp_nip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl);
void tcp_nip_actual_send_reset(struct sock *sk, struct sk_buff *skb, u32 seq,
				 u32 ack_seq, u32 win, int rst, u32 priority);
int nip_rcv(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *pt, struct net_device *orig_dev);
struct nip_rt_info *nip_dst_alloc(struct net *net, struct net_device *dev,
				  int flags);

static inline bool nip_addr_and_ifindex_eq(const struct nip_addr *a1,
			       const struct nip_addr *a2, int ifindex1, int ifindex2)
{
	return (a1->bitlen == a2->bitlen) && (a1->bitlen <= NIP_ADDR_BIT_LEN_MAX) &&
	       (memcmp(&a1->v.u, &a2->v.u, a1->bitlen >> 3) == 0) && (ifindex1 == ifindex2);
};

static inline bool nip_addr_eq(const struct nip_addr *a1,
			       const struct nip_addr *a2)
{
	return (a1->bitlen == a2->bitlen) && (a1->bitlen <= NIP_ADDR_BIT_LEN_MAX) &&
	       (memcmp(&a1->v.u, &a2->v.u, a1->bitlen >> 3) == 0);
};

static inline u32 nip_addr_hash(const struct nip_addr *a)
{
	u32 tmp[4];
	u8 len = a->bitlen >> 3;

	/* set unused bit to 0 */
	memset(tmp, 0, NIP_ADDR_BIT_LEN_16);
	memcpy(tmp, &a->v.u,
	       len > NIP_ADDR_BIT_LEN_16 ? NIP_ADDR_BIT_LEN_16 : len);

	return (__force u32)(tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3]);
}

int nip_send_skb(struct sk_buff *skb);

void ninet_destroy_sock(struct sock *sk);
int nip_datagram_dst_update(struct sock *sk, bool fix_sk_saddr);
int ninet_add_protocol(const struct ninet_protocol *prot, unsigned char protocol);
int ninet_del_protocol(const struct ninet_protocol *prot, unsigned char protocol);
int ninet_register_protosw(struct inet_protosw *p);
void ninet_unregister_protosw(struct inet_protosw *p);
int nip_input(struct sk_buff *skb);
int nip_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int nip_forward(struct sk_buff *skb);

unsigned int tcp_nip_sync_mss(struct sock *sk, u32 pmtu);
unsigned int tcp_nip_current_mss(struct sock *sk);
int tcp_nip_send_mss(struct sock *sk, int *size_goal, int flags);

struct nip_addr *nip_nexthop(struct nip_rt_info *rt, struct nip_addr *daddr);
struct dst_entry *nip_sk_dst_lookup_flow(struct sock *sk, struct flow_nip *fln);
struct dst_entry *nip_dst_lookup_flow(struct net *net, const struct sock *sk,
				      struct flow_nip *fln,
				      const struct nip_addr *final_dst);
u_char *nip_get_mac(struct nip_addr *nipaddr, struct net_device *dev);
struct net_device *nip_get_defaultdev(void);
int nip_init_dev(void);

int _nip_udp_output(struct sock *sk, void *from, int datalen,
		    int transhdrlen, const struct nip_addr *saddr,
		    ushort sport, const struct nip_addr *daddr,
		    ushort dport, struct dst_entry *dst);

/* functions defined in nip_sockglue.c */
int nip_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		   unsigned int optlen);
int nip_getsockopt(struct sock *sk, int level,
		   int optname, char __user *optval, int __user *optlen);

/* functions defined in nip_addrconf.c */
int nip_addrconf_get_ifaddr(struct net *net, unsigned int cmd, void __user *arg);

#endif
