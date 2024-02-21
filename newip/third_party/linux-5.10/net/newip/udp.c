// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv4/udp.c
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() calls
 *		Alan Cox	:	stopped close while in use off icmp
 *					messages. Not a fix but a botch that
 *					for udp at least is 'valid'.
 *		Alan Cox	:	Fixed icmp handling properly
 *		Alan Cox	:	Correct error for oversized datagrams
 *		Alan Cox	:	Tidied select() semantics.
 *		Alan Cox	:	udp_err() fixed properly, also now
 *					select and read wake correctly on errors
 *		Alan Cox	:	udp_send verify_area moved to avoid mem leak
 *		Alan Cox	:	UDP can count its memory
 *		Alan Cox	:	send to an unknown connection causes
 *					an ECONNREFUSED off the icmp, but
 *					does NOT close.
 *		Alan Cox	:	Switched to new sk_buff handlers. No more backlog!
 *		Alan Cox	:	Using generic datagram code. Even smaller and the PEEK
 *					bug no longer crashes it.
 *		Fred Van Kempen	:	Net2e support for sk->broadcast.
 *		Alan Cox	:	Uses skb_free_datagram
 *		Alan Cox	:	Added get/set sockopt support.
 *		Alan Cox	:	Broadcasting without option set returns EACCES.
 *		Alan Cox	:	No wakeup calls. Instead we now use the callbacks.
 *		Alan Cox	:	Use ip_tos and ip_ttl
 *		Alan Cox	:	SNMP Mibs
 *		Alan Cox	:	MSG_DONTROUTE, and 0.0.0.0 support.
 *		Matt Dillon	:	UDP length checks.
 *		Alan Cox	:	Smarter af_inet used properly.
 *		Alan Cox	:	Use new kernel side addressing.
 *		Alan Cox	:	Incorrect return on truncated datagram receive.
 *	Arnt Gulbrandsen	:	New udp_send and stuff
 *		Alan Cox	:	Cache last socket
 *		Alan Cox	:	Route cache
 *		Jon Peatfield	:	Minor efficiency fix to sendto().
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Nonblocking error fix.
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Mike McLagan	:	Routing by source
 *		David S. Miller	:	New socket lookup architecture.
 *					Last socket cache retained as it
 *					does have a high hit rate.
 *		Olaf Kirch	:	Don't linearise iovec on sendmsg.
 *		Andi Kleen	:	Some cleanups, cache destination entry
 *					for connect.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Melvin Smith	:	Check msg_name not msg_namelen in sendto(),
 *					return ENOTCONN for unconnected sockets (POSIX)
 *		Janos Farkas	:	don't deliver multi/broadcasts to a different
 *					bound-to-device socket
 *	Hirokazu Takahashi	:	HW checksumming for outgoing UDP
 *					datagrams.
 *	Hirokazu Takahashi	:	sendfile() on UDP works now.
 *		Arnaldo C. Melo :	convert /proc/net/udp to seq_file
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov:		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 *	James Chapman		:	Add L2TP encapsulation type.
 *
 * Based on net/ipv6/udp.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Fixes:
 *	Hideaki YOSHIFUJI	:	sin6_scope_id support
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *      Kazunori MIYAZAWA @USAGI:       change process style to use ip6_append_data
 *      YOSHIFUJI Hideaki @USAGI:	convert /proc/net/udp6 to seq_file.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * The User Datagram Protocol (NewIP UDP).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/nip.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/types.h>

#include <net/addrconf.h>
#include <net/busy_poll.h>
#include <net/nip.h>
#include <net/nip_udp.h>
#include <net/nip_fib.h>
#include <net/nip_addrconf.h>
#include <net/protocol.h>
#include <net/raw.h>
#include <net/sock_reuseport.h>
#include <net/udp.h>
#include "nip_hdr.h"
#include "nip_checksum.h"
#include "tcp_nip_parameter.h"

static u32 nip_udp_portaddr_hash(const struct net *net,
				 const struct nip_addr *niaddr,
				 u_short port)
{
	u32 hash;
	u32 mix = net_hash_mix(net);

	/* use nip_addr_hash() to obtain a hash result of nip_addr */
	hash = jhash_1word(nip_addr_hash(niaddr), mix);

	return hash ^ port;
}

/* Called during the bind & sendto procedure, bind ports */
int nip_udp_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr, hash2_partial;

	hash2_nulladdr = nip_udp_portaddr_hash(sock_net(sk), &nip_any_addr, snum);
	/* hash2_partial is the hash result of nip_addr only */
	hash2_partial = nip_udp_portaddr_hash(sock_net(sk), &sk->SK_NIP_RCV_SADDR, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, hash2_nulladdr);
}

static int nip_udp_compute_score(struct sock *sk, struct net *net,
				 const struct nip_addr *saddr, __be16 sport,
				 const struct nip_addr *daddr, unsigned short hnum,
				 int dif, int sdif)
{
	int score = 0;
	struct inet_sock *inet;

	if (!net_eq(sock_net(sk), net) ||
	    udp_sk(sk)->udp_port_hash != hnum ||
	    sk->sk_family != PF_NINET)
		return -1;

	/* Destination port of the peer device
	 * In the header sent by the peer end, it is the source port
	 */
	inet = inet_sk(sk);
	if (inet->inet_dport) {
		if (inet->inet_dport != sport)
			return -1;
		score++;
	}

	/* Source ADDRESS of the local device
	 * In the header sent by the peer device, it is the destination address
	 */
	if (!nip_addr_any(&sk->SK_NIP_RCV_SADDR)) {
		if (!nip_addr_eq(&sk->SK_NIP_RCV_SADDR, daddr))
			return -1;
		score++;
	}

	/* Address of the peer device
	 * In the packet header sent by the peer device, is the source ADDRESS
	 */
	if (!nip_addr_any(&sk->SK_NIP_DADDR)) {
		if (!nip_addr_eq(&sk->SK_NIP_DADDR, saddr))
			return -1;
		score++;
	}

	/* Check the dev index */
	if (sk->sk_bound_dev_if) {
		bool dev_match = dif == sk->sk_bound_dev_if || sdif == sk->sk_bound_dev_if;

		if (!dev_match)
			return -1;
		score++;
	}

	if (sk->sk_incoming_cpu == raw_smp_processor_id())
		score++;
	return score;
}

static struct sock *nip_udp_lib_lookup2(struct net *net,
					const struct nip_addr *saddr,
					u_short sport,
					const struct nip_addr *daddr,
					unsigned short hnum,
					int dif, int sdif,
					struct udp_hslot *hslot2,
					struct sk_buff *skb)
{
	struct sock *sk;
	struct sock *result = NULL;
	int badness = -1;

	udp_portaddr_for_each_entry_rcu(sk, &hslot2->head) {
		int score = nip_udp_compute_score(sk, net, saddr, sport, daddr, hnum, dif, sdif);

		if (score > badness) {
			result = sk;
			badness = score;
		}
	}
	return result;
}

/* rcu_read_lock() must be held */
struct sock *__nip_udp_lib_lookup(struct net *net,
				  const struct nip_addr *saddr, __be16 sport,
				  const struct nip_addr *daddr, __be16 dport,
				  int dif, int sdif, struct udp_table *udptable,
				  struct sk_buff *skb)
{
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2;
	struct udp_hslot *hslot2;
	struct sock *result;

	/* mask ensures that the hash index is valid without memory overruns */
	hash2 = nip_udp_portaddr_hash(net, daddr, hnum);
	slot2 = hash2 & udptable->mask;
	hslot2 = &udptable->hash2[slot2];

	/* Lookup connected or non-wildcard sockets */
	result = nip_udp_lib_lookup2(net, saddr, sport,
				     daddr, hnum, dif, sdif,
				     hslot2, skb);
	if (!IS_ERR_OR_NULL(result))
		goto done;

	/* Lookup wildcard sockets */
	/* mask ensures that the hash index is valid without memory overruns */
	hash2 = nip_udp_portaddr_hash(net, &nip_any_addr, hnum);
	slot2 = hash2 & udptable->mask;
	hslot2 = &udptable->hash2[slot2];

	result = nip_udp_lib_lookup2(net, saddr, sport,
				     &nip_any_addr, hnum, dif, sdif,
				     hslot2, skb);
done:
	if (IS_ERR(result))
		return NULL;
	return result;
}

static struct sock *__nip_udp_lib_lookup_skb(struct sk_buff *skb,
					     __be16 sport, __be16 dport,
					     struct udp_table *udptable)
{
	return __nip_udp_lib_lookup(dev_net(skb->dev),
				&nipcb(skb)->srcaddr, sport,
				&nipcb(skb)->dstaddr, dport, skb->skb_iif,
				0, udptable, skb);
}

void udp_table_del(struct sock *sk)
{
	udp_lib_unhash(sk);
}

int nip_udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		    int noblock, int flags, int *addr_len)
{
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeking, off, datalen;
	int err;

	off = sk_peek_offset(sk, flags);
	peeking = off; /* Fetch the SKB from the queue */
	skb = __skb_recv_udp(sk, flags, noblock, &off, &err);
	if (!skb)
		return err;
	ulen = skb->len;
	copied = len;
	if (copied > ulen - off)
		copied = ulen - off;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/* copy data */
	datalen = copy_to_iter(skb->data, copied, &msg->msg_iter);
	if (datalen < 0) {
		nip_dbg("copy to iter in failure, len=%d", datalen);
		err = -EFAULT;
		return err;
	}

	sock_recv_ts_and_drops(msg, sk, skb);
	/* Update information such as the timestamp received
	 * by the last datagram in the transport control block
	 */
	/* copy the address */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_nin *, sin, msg->msg_name);

		sin->sin_family = AF_NINET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr = nipcb(skb)->srcaddr;
		*addr_len = sizeof(*sin);
	}

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

	skb_consume_udp(sk, skb, peeking ? -err : err);
	return err;
}

static void nip_udp_err(struct sk_buff *skb,
			struct ninet_skb_parm *opt,
			u8 type,
			u8 code, int offset,
			__be32 info)
{
}

static int __nip_udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	sk_incoming_cpu_update(sk);

	rc = __udp_enqueue_schedule_skb(sk, skb);
	if (rc < 0) {
		kfree_skb(skb);
		return -1;
	}
	return 0;
}

bool nip_get_udp_input_checksum(struct sk_buff *skb)
{
	struct nip_pseudo_header nph = {0};
	struct udphdr *udphead = udp_hdr(skb);
	unsigned short check_len = ntohs(udphead->len);

	nph.nexthdr = nipcb(skb)->nexthdr;
	nph.saddr = nipcb(skb)->srcaddr;
	nph.daddr = nipcb(skb)->dstaddr;
	nph.check_len = udphead->len;

	return nip_check_sum_parse(skb_transport_header(skb), check_len, &nph)
	       == 0xffff ? true : false;
}

/* Udp packets are received at the network layer */
int nip_udp_input(struct sk_buff *skb)
{
	struct sock *sk;
	int rc = -EINVAL;
	struct udphdr *udphead;

	if (!pskb_may_pull(skb, sizeof(struct udphdr))) {
		nip_dbg("invalid skb length, drop the packet(skb->len=%u)", skb->len);
		kfree_skb(skb);
		goto end;
	}

	udphead = udp_hdr(skb);
	if (ntohs(udphead->len) < sizeof(struct udphdr) ||
	    ntohs(udphead->len) > skb->len) {
		nip_dbg("invalid udp packet length, drop the packet(udphead->len=%u)",
			ntohs(udphead->len));
		kfree_skb(skb);
		goto end;
	}

	if (!nip_get_udp_input_checksum(skb)) {
		nip_dbg("checksum failed, drop the packet");
		kfree_skb(skb);
		goto end;
	}

	sk = __nip_udp_lib_lookup_skb(skb, udphead->source,
				      udphead->dest, &udp_table);
	if (!sk) {
		nip_dbg("dport not match, drop the packet. sport=%u, dport=%u, data_len=%u",
			ntohs(udphead->source), ntohs(udphead->dest), ntohs(udphead->len));
		kfree_skb(skb);
		goto end;
	}

	skb_pull(skb, sizeof(struct udphdr));
	skb->len = ntohs(udphead->len) - sizeof(struct udphdr);

	skb_dst_drop(skb);
	/* enqueue */
	rc = __nip_udp_queue_rcv_skb(sk, skb);
end:
	return rc;
}

int nip_udp_output(struct sock *sk, struct msghdr *msg, size_t len)
{
	DECLARE_SOCKADDR(struct sockaddr_nin *, sin, msg->msg_name);
	struct flow_nip fln;
	u_short sport, dport;
	struct dst_entry *dst;
	int err;
	struct inet_sock *inet;

	if (!sin)
		/* Currently, udp socket Connect function is not implemented.
		 * The destination address and port must be directly provided by Sendto
		 */
		return -EDESTADDRREQ;

	if (sin->sin_family != AF_NINET) {
		nip_dbg("sin_family false");
		return -EAFNOSUPPORT;
	}
	if (nip_addr_invalid(&sin->sin_addr)) {
		nip_dbg("sin_addr false");
		return -EFAULT;
	}
	if (is_nip_local_addr(&sin->sin_addr)) {
		err = ninet_ioctl_cmd(sk->sk_socket, msg->msg_iter.iov);
		if (!err) {
			nip_dbg("ninet_ioctl_cmd succeed");
			return err;
		} else if (err != -NIP_IOCTL_FLAG_INVALID) {
			nip_dbg("ninet_ioctl_cmd failed");
			return err;
		}
	}

	inet = inet_sk(sk);
	/* Destination address, port (network order) must be specified when sendto */
	dport = sin->sin_port;
	fln.daddr = sin->sin_addr;
	sport = htons(inet->inet_num);

	/* Check the dev index */
	fln.FLOWIN_OIF = sk->sk_bound_dev_if;

	/* Query the route & Obtain the Saddr */
	dst = nip_sk_dst_lookup_flow(sk, &fln);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto out;
	}

	err = _nip_udp_output(sk, msg, len,
			      sizeof(struct udphdr), &fln.saddr,
			      sport, &fln.daddr,
			      dport, dst);

out:
	dst_release(dst);
	if (!err)
		return len;

	return err;
}

/* Close the connection using */
void nip_udp_destroy_sock(struct sock *sk)
{
	udp_table_del(sk);
	ninet_destroy_sock(sk);
}

/* socket option code for udp */
int nip_udp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		       unsigned int optlen)
{
	if (level == SOL_UDP || level == SOL_UDPLITE)
		return 0;
	return nip_setsockopt(sk, level, optname, optval, optlen);
}

int nip_udp_getsockopt(struct sock *sk, int level,
		       int optname, char __user *optval,
		       int __user *optlen)
{
	if (level == SOL_UDP || level == SOL_UDPLITE)
		return 0;
	return nip_getsockopt(sk, level, optname, optval, optlen);
}

int nip_udp_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	return -EINVAL;
}

int nip_udp_pre_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	return -EINVAL;
}

int nip_udp_sendpage(struct sock *sk, struct page *page, int offset,
		     size_t size, int flags)
{
	return -EINVAL;
}

void nip_udp_datagram_release_cb(struct sock *sk)
{
}

void udp_nip_rehash(struct sock *sk)
{
}

void nip_udp_early_demux(struct sk_buff *skb)
{
}

static const struct ninet_protocol nip_udp_protocol = {
	.handler	= nip_udp_input,
	.err_handler	= nip_udp_err,
	.early_demux	= nip_udp_early_demux,
	.flags		= 0,
};

/* Newip Udp related operations */
struct proto nip_udp_prot = {
	.name			= "nip_udp",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
	.pre_connect		= nip_udp_pre_connect,
	.connect		= nip_udp_datagram_connect,
	.disconnect		= udp_disconnect,
	.ioctl			= udp_ioctl,
	.init			= udp_init_sock,
	.destroy		= nip_udp_destroy_sock,
	.setsockopt		= nip_udp_setsockopt,
	.getsockopt		= nip_udp_getsockopt,
	.sendmsg		= nip_udp_output,
	.recvmsg		= nip_udp_recvmsg,
	.sendpage		= nip_udp_sendpage,
	.release_cb		= nip_udp_datagram_release_cb,
	.backlog_rcv		= __nip_udp_queue_rcv_skb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= udp_nip_rehash,
	.get_port		= nip_udp_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,
	.obj_size		= sizeof(struct nip_udp_sock),
	.h.udp_table		= &udp_table,
	.diag_destroy		= udp_abort,
};

/* Example Create newip socket information */
static struct inet_protosw nip_udp_protosw = {
	.type = SOCK_DGRAM,
	.protocol = IPPROTO_UDP,
	.prot = &nip_udp_prot,
	.ops = &ninet_dgram_ops,
	.flags = INET_PROTOSW_PERMANENT,
};

/* Af_NINET initializes the call */
int __init nip_udp_init(void)
{
	int ret;

	ret = ninet_add_protocol(&nip_udp_protocol, IPPROTO_UDP);
	if (ret)
		goto out;

	ret = ninet_register_protosw(&nip_udp_protosw);
	if (ret)
		goto out_nip_udp_protocol;
out:
	return ret;

out_nip_udp_protocol:
	ninet_del_protocol(&nip_udp_protocol, IPPROTO_UDP);
	goto out;
}

void nip_udp_exit(void)
{
	ninet_unregister_protosw(&nip_udp_protosw);
	ninet_del_protocol(&nip_udp_protocol, IPPROTO_UDP);
}
