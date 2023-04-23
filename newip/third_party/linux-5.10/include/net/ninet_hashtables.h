/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on include/net/inet6_hashtables.h
 * Authors:	Lotsa people, from code originally in tcp
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the BSD Socket
 * interface as the means of communication with the user level.
 */
#ifndef NINET_HASHTABLES_H
#define NINET_HASHTABLES_H

#if IS_ENABLED(CONFIG_NEWIP)
#include <linux/nip.h>
#include <linux/types.h>
#include <linux/jhash.h>

#include <net/inet_sock.h>

#include <net/nip.h>
#include <net/netns/hash.h>

struct inet_hashinfo;

int ninet_hash(struct sock *sk);
void ninet_unhash(struct sock *sk);
int ninet_hash_connect(struct inet_timewait_death_row *death_row,
		       struct sock *sk);

int __ninet_hash(struct sock *sk, struct sock *osk);


static inline unsigned int __ninet_ehashfn(const u32 lhash,
					   const u16 lport,
					   const u32 fhash,
					   const __be16 fport,
					   const u32 initval)
{
	const u32 ports = (((u32) lport) << 16) | (__force u32) fport;

	return jhash_3words(lhash, fhash, ports, initval);
}

struct sock *__ninet_lookup_established(struct net *net,
					struct inet_hashinfo *hashinfo,
					const struct nip_addr *saddr,
					const __be16 sport,
					const struct nip_addr *daddr,
					const u16 hnum, const int dif);

struct sock *ninet_lookup_listener(struct net *net,
				   struct inet_hashinfo *hashinfo,
				   struct sk_buff *skb, int doff,
				   const struct nip_addr *saddr,
				   const __be16 sport,
				   const struct nip_addr *daddr,
				   const unsigned short hnum, const int dif, const int sdif);

static inline struct sock *__ninet_lookup(struct net *net,
					  struct inet_hashinfo *hashinfo,
					  struct sk_buff *skb, int doff,
					  const struct nip_addr *saddr,
					  const __be16 sport,
					  const struct nip_addr *daddr,
					  const u16 hnum,
					  const int dif, bool *refcounted)
{
	struct sock *sk = __ninet_lookup_established(net, hashinfo, saddr,
						     sport, daddr, hnum, dif);
	*refcounted = true;
	if (sk)
		return sk;
	*refcounted = false;
	return ninet_lookup_listener(net, hashinfo, skb, doff, saddr, sport,
				     daddr, hnum, dif, 0);
}

static inline struct sock *__ninet_lookup_skb(struct inet_hashinfo *hashinfo,
					      struct sk_buff *skb, int doff,
					      const __be16 sport,
					      const __be16 dport,
					      int iif, bool *refcounted)
{
	struct sock *sk;

	*refcounted = true;
	sk = skb_steal_sock(skb, refcounted);
	if (sk)
		return sk;

	return __ninet_lookup(dev_net(skb->dev), hashinfo, skb,
			      doff, &(NIPCB(skb)->srcaddr), sport,
			      &(NIPCB(skb)->dstaddr), ntohs(dport),
			      iif, refcounted);
}

#define NINET_MATCH(__sk, __net, __saddr, __daddr, __ports, __dif)	\
	(((__sk)->sk_portpair == (__ports))			&&	\
	 ((__sk)->sk_family == AF_NINET)			&&	\
	 nip_addr_eq(&(__sk)->sk_nip_daddr, (__saddr))		&&	\
	 nip_addr_eq(&(__sk)->sk_nip_rcv_saddr, (__daddr))	&&	\
	 (!(__sk)->sk_bound_dev_if	||              \
	   ((__sk)->sk_bound_dev_if == (__dif)))	&&	\
	 net_eq(sock_net(__sk), (__net)))

int ninet_hash_connect(struct inet_timewait_death_row *death_row,
		       struct sock *sk);

u64 secure_newip_port_ephemeral(const __be32 *saddr, const __be32 *daddr,
			       __be16 dport);
__u32 secure_tcp_nip_sequence_number(const __be32 *saddr, const __be32 *daddr,
				    __be16 sport, __be16 dport);

u32 ninet_ehashfn(const struct net *net,
	      const struct nip_addr *laddr, const u16 lport,
	      const struct nip_addr *faddr, const __be16 fport);

#endif /* IS_ENABLED(CONFIG_NEWIP) */
#endif /* _NINET_HASHTABLES_H */
