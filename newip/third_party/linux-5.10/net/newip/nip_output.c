// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv6/ip6_output.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Changes:
 *	A.N.Kuznetsov	:	airthmetics in fragmentation.
 *				extension headers are implemented.
 *				route changes now work.
 *				ip6_forward does not confuse sniffers.
 *				etc.
 *
 *      H. von Brand    :       Added missing #include <linux/string.h>
 *	Imran Patel	:	frag id should be in NBO
 *      Kazunori MIYAZAWA @USAGI
 *			:       add ip6_append_data and related functions
 *				for datagram xmit
 *
 * NewIP output functions
 * Linux NewIP INET implementation
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/nip.h>
#include <linux/route.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/netfilter.h>

#include <net/sock.h>
#include <net/nndisc.h>
#include <net/protocol.h>
#include <net/checksum.h>
#include <net/nip.h>
#include <net/nip_udp.h>
#include <net/nip_route.h>
#include <net/tcp_nip.h>

#include "nip_hdr.h"
#include "nip_checksum.h"
#include "tcp_nip_parameter.h"

#define NIP_BIT_TO_BYTE 1024
void update_memory_rate(const char *upper_fun)
{
	struct sysinfo mem_info;
	unsigned long total;
	unsigned long free;
	unsigned long used;
	unsigned int uint_kb;

	si_meminfo(&mem_info);
	uint_kb = mem_info.mem_unit / NIP_BIT_TO_BYTE;
	total = (unsigned long)mem_info.totalram * uint_kb;
	free = (unsigned long)mem_info.freeram * uint_kb;
	used = total - free;
	nip_dbg("%s call cur-func mem total: %ld KB, mem used: %ld KB", upper_fun, total, used);
}

int nip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct nip_addr *nexthop;
	struct neighbour *neigh;
	int ret = 0;
	struct net_device *dev = skb_dst(skb)->dev;

	skb->protocol = htons(ETH_P_NEWIP);
	skb->dev = dev;

	/* prepare to build ethernet header */
	nexthop = nip_nexthop((struct nip_rt_info *)dst, &NIPCB(skb)->dstaddr);

	rcu_read_lock_bh();

	neigh = __nip_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&nnd_tbl, nexthop, dev, false);
	if (!IS_ERR(neigh)) {
		int res = neigh_output(neigh, skb, false);

		rcu_read_unlock_bh();
		return res;
	}
	nip_dbg("find neigh and create neigh failed");

	rcu_read_unlock_bh();
	kfree_skb(skb);
	return ret;
}

int nip_forward(struct sk_buff *skb)
{
	return nip_output(NULL, NULL, skb);
}

static int nip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int err;

	err = dst_output(net, sk, skb);
	return err;
}

int nip_send_skb(struct sk_buff *skb)
{
	struct net *net;
	int err = 0;

	net = skb->sk ? sock_net(skb->sk) : dev_net(skb_dst(skb)->dev);
	err = nip_local_out(net, skb->sk, skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		nip_dbg("failed to out skb, err = %d", err);
	}

	return err;
}

unsigned short nip_get_output_checksum(struct sk_buff *skb,
				       struct nip_hdr_encap *head)
{
	struct nip_pseudo_header nph = {0};
	u8 *udp_hdr = skb_transport_header(skb);
	unsigned short check_len = head->trans_hdr_len + head->usr_data_len;

	nph.nexthdr = IPPROTO_UDP;
	nph.saddr = NIPCB(skb)->srcaddr;
	nph.daddr = NIPCB(skb)->dstaddr;
	nph.check_len = htons(check_len);
	return nip_check_sum_build(udp_hdr, check_len, &nph);
}

static struct sk_buff *_nip_alloc_skb(struct sock *sk,
				      struct nip_hdr_encap *head,
				      struct nip_pkt_seg_info *seg_info,
				      struct dst_entry *dst)
{
	int len;
	int nip_hdr_len = get_nip_hdr_len(NIP_HDR_UDP, &head->saddr, &head->daddr);
	struct sk_buff *skb;

	nip_hdr_len = nip_hdr_len == 0 ? NIP_HDR_MAX : nip_hdr_len;
	len = NIP_ETH_HDR_LEN + nip_hdr_len + head->trans_hdr_len + seg_info->mid_usr_pkt_len;
	skb = alloc_skb(len, 0);
	if (!skb) {
		nip_dbg("no space for skb");
		return NULL;
	}

	skb->protocol = htons(ETH_P_NEWIP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;
	skb->sk = sk;

	dst_hold(dst);
	nip_dbg("malloc_len=%d, dst->__refcnt=%u", len, atomic_read(&dst->__refcnt));
	skb_dst_set(skb, dst);
	memset(NIPCB(skb), 0, sizeof(struct ninet_skb_parm));

	return skb;
}

static int _nip_udp_single_output(struct sock *sk,
				  struct nip_hdr_encap *head,
				  struct nip_pkt_seg_info *seg_info,
				  struct dst_entry *dst)
{
	int len;
	int ret;
	struct msghdr *from = (struct msghdr *)head->usr_data;
	struct sk_buff *skb = _nip_alloc_skb(sk, head, seg_info, dst);
	unsigned short check = 0;

	if (IS_ERR_OR_NULL(skb)) {
		nip_dbg("skb alloc fail");
		return -ENOMEM;
	}

	/* Reserved Position of the Ethernet header (to be filled after the
	 * Ethernet header is delivered to the link layer)
	 */
	skb_reserve(skb, NIP_ETH_HDR_LEN);

	/* Fill in the Network-layer Header (newIP) */
	skb_reset_network_header(skb);
	head->hdr_buf = skb->data;
	nip_hdr_udp_encap(head);
	skb_reserve(skb, head->hdr_buf_pos);
	NIPCB(skb)->dstaddr = head->daddr;
	NIPCB(skb)->srcaddr = head->saddr;
	NIPCB(skb)->nexthdr = IPPROTO_UDP;

	/* Fill in the Transport Layer Header (UDP) */
	skb_reset_transport_header(skb);
	nip_build_udp_hdr(head->sport, head->dport,
			  htons(head->trans_hdr_len + head->usr_data_len),
			  skb->data, htons(0));
	skb_reserve(skb, head->trans_hdr_len);
	len = copy_from_iter(skb->data, head->usr_data_len, &from->msg_iter);
	if (len < 0) {
		/* The DST has been set to the SKB. When the SKB is released,
		 * the DST is automatically released
		 */
		nip_dbg("copy from iter fail (datalen=%u)", head->usr_data_len);
		kfree_skb(skb);
		return -EFBIG;
	}

	/* insert check sum */
	check = nip_get_output_checksum(skb, head);
	nip_build_udp_hdr(head->sport, head->dport,
			  htons(head->trans_hdr_len + head->usr_data_len),
			  skb->data - head->trans_hdr_len, htons(check));

	/* Refresh the data/tail of the SKB after the packet copy is complete */
	skb_put(skb, head->usr_data_len);
	skb->data = skb_network_header(skb);
	skb->len = head->hdr_buf_pos + head->trans_hdr_len +
		   head->usr_data_len;

	/* Add the actual size of the current SKB to the SOCK send cache count
	 * and set destructor to __sock_wfree to reduce the SOCK send cache size
	 * when the SKB is released.
	 */
	skb->destructor = __sock_wfree;
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);
	skb->priority = sk->sk_priority;

	ret = nip_send_skb(skb);
	nip_dbg("output finish (ret=%d, datalen=%u)", ret, head->usr_data_len);
	update_memory_rate(__func__);
	return ret;
}

int _nip_udp_output(struct sock *sk, void *from, int datalen,
		    int transhdrlen, const struct nip_addr *saddr,
		    ushort sport, const struct nip_addr *daddr,
		    ushort dport, struct dst_entry *dst)
{
	int i;
	u32 ret = 0;
	u32 mtu = dst_mtu(dst);
	struct nip_pkt_seg_info seg_info = {0};
	struct nip_hdr_encap head = {0};
	int nip_hdr_len = get_nip_hdr_len(NIP_HDR_UDP, saddr, daddr);

	head.saddr = *saddr;
	head.daddr = *daddr;
	head.sport = sport;
	head.dport = dport;
	head.usr_data = from;
	head.ttl = NIP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_UDP;
	head.trans_hdr_len = transhdrlen;

	nip_hdr_len = nip_hdr_len == 0 ? NIP_HDR_MAX : nip_hdr_len;
	nip_calc_pkt_frag_num(mtu, nip_hdr_len, datalen, &seg_info);

	/* Send intermediate data segments */
	for (i = 0; i < seg_info.mid_pkt_num; i++) {
		head.usr_data_len = seg_info.mid_usr_pkt_len;
		ret = _nip_udp_single_output(sk, &head, &seg_info, dst);
		if (ret)
			goto end;
	}

	/* Send the last data segment */
	if (seg_info.last_pkt_num) {
		head.usr_data_len = seg_info.last_usr_pkt_len;
		ret = _nip_udp_single_output(sk, &head, &seg_info, dst);
	}

end:
	return ret;
}

static int nip_sk_dst_check(struct dst_entry *dst,
			    struct flow_nip *fln)
{
	int err = 0;

	if (!dst)
		goto out;

	if (fln->flowin_oif && fln->flowin_oif != dst->dev->ifindex)
		err = -EPERM;

out:
	return err;
}

/* 1. Based on FLN, the routing table is searched to obtain the corresponding DST
 * 2. The newIP address of the source end is obtained based on the routing table
 * search result and stored in the fln->saddr
 */
static int nip_dst_lookup_tail(struct net *net, const struct sock *sk,
			       struct dst_entry **dst, struct flow_nip *fln)
{
	int err;
	struct nip_rt_info *rt;

	if (!(*dst))
		*dst = nip_route_output(net, sk, fln);

	err = (*dst)->error;
	if (err) {
		rt = NULL;
		nip_dbg("route output search error");
		goto out_err_release;
	}

	err = nip_sk_dst_check(*dst, fln);
	if (err)
		goto out_err_release;

	rt = (struct nip_rt_info *)*dst;
	if (*dst == &net->newip.nip_broadcast_entry->dst) {
		fln->saddr = fln->daddr;
		err = 0;
	} else {
		err = nip_route_get_saddr(net, rt, &fln->daddr, &fln->saddr);
	}

	if (err)
		goto out_err_release;

	return 0;

out_err_release:
	dst_release(*dst);
	*dst = NULL;

	return err;
}

struct dst_entry *nip_dst_lookup_flow(struct net *net, const struct sock *sk,
				      struct flow_nip *fln,
				      const struct nip_addr *final_dst)
{
	struct dst_entry *dst = NULL;
	int err;

	err = nip_dst_lookup_tail(net, sk, &dst, fln);
	if (err)
		return ERR_PTR(err);
	if (final_dst)
		fln->daddr = *final_dst;

	return dst;
}

struct dst_entry *nip_sk_dst_lookup_flow(struct sock *sk, struct flow_nip *fln)
{
	struct dst_entry *dst = NULL;
	int err;

	err = nip_dst_lookup_tail(sock_net(sk), sk, &dst, fln);
	if (err)
		return ERR_PTR(err);

	return dst;
}

int tcp_nip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	int err = -EHOSTUNREACH;
	struct net *net = sock_net(sk);
	struct nip_addr *saddr, *daddr;
	struct dst_entry *dst;
	struct flow_nip fln;
	struct nip_hdr_encap head = {0};
	unsigned char hdr_buf[NIP_HDR_MAX]; /* Cache the newIP header */

	rcu_read_lock();
	skb->protocol = htons(ETH_P_NEWIP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;
	saddr = &sk->sk_nip_rcv_saddr;
	daddr = &sk->sk_nip_daddr;

	head.saddr = *saddr;
	head.daddr = *daddr;
	head.ttl = NIP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_TCP;
	head.hdr_buf = hdr_buf;
	nip_hdr_comm_encap(&head);
	head.total_len = head.hdr_buf_pos + skb->len;
	nip_update_total_len(&head, htons(head.total_len));

	fln.daddr = sk->sk_nip_daddr;
	dst = __sk_dst_check(sk, 0);
	if (!dst) {
		nip_dbg("no dst cache for sk, search newip rt");
		dst = nip_route_output(net, sk, &fln);
		if (!dst) {
			nip_dbg("cannot find dst");
			goto out;
		}
		if (dst->error)
			goto out_err_release;
		sk_dst_set(sk, dst);
	}
	skb_dst_set_noref(skb, dst);

	/* build nwk header */
	skb_push(skb, head.hdr_buf_pos);
	memcpy(skb->data, head.hdr_buf, head.hdr_buf_pos);

	skb_reset_network_header(skb);
	NIPCB(skb)->srcaddr = *saddr;
	NIPCB(skb)->dstaddr = *daddr;
	NIPCB(skb)->nexthdr = head.nexthdr;

	skb->priority = sk->sk_priority;
	head.total_len = skb->len;
	err = nip_send_skb(skb);
	if (err)
		nip_dbg("failed to send skb, skb->len=%u", head.total_len);
	else
		nip_dbg("send skb ok, skb->len=%u", head.total_len);

out:
	rcu_read_unlock();
	return err;

out_err_release:
	dst_release(dst);
	dst = NULL;
	sk->sk_err_soft = -err;
	sk->sk_route_caps = 0;
	kfree_skb(skb);
	return err;
}

void tcp_nip_actual_send_reset(struct sock *sk, struct sk_buff *skb, u32 seq,
			       u32 ack_seq, u32 win, int rst, u32 priority)
{
	const struct tcphdr *th = tcp_hdr(skb);
	struct tcphdr *t1;
	struct sk_buff *buff;
	struct flow_nip fln;
	struct net *net;
	struct nip_addr *saddr, *daddr;
	unsigned int tot_len = sizeof(struct tcphdr);
	struct nip_hdr_encap head = {0};
	unsigned char hdr_buf[NIP_HDR_MAX];
	struct dst_entry *dst;
	int err;

	net = sk ? sock_net(sk) : dev_net(skb_dst(skb)->dev);

	/* alloc skb */
	buff = alloc_skb(MAX_TCP_HEADER, priority);
	if (!buff)
		/* If you add log here, there will be an alarm:
		 * WARNING: Possible unnecessary 'out of memory' message
		 */
		return;

	skb_reserve(buff, MAX_TCP_HEADER);

	buff->sk = sk; // sk could be NULL
	saddr = &(NIPCB(skb)->dstaddr);
	daddr = &(NIPCB(skb)->srcaddr);

	/* Fill in tcp header */
	t1 = skb_push(buff, sizeof(struct tcphdr));
	skb_reset_transport_header(buff);
	memset(t1, 0, sizeof(*t1));
	t1->dest = th->source;
	t1->source = th->dest;
	t1->doff = tot_len / TCP_NUM_4;
	t1->seq = htonl(seq);
	t1->ack_seq = htonl(ack_seq);
	t1->ack = !rst || !th->ack;
	t1->rst = rst;
	t1->window = htons(win);
	t1->check = htons(nip_get_output_checksum_tcp(buff, *saddr, *daddr));
	nip_dbg("host dport=%u, net dport=0x%x, host sport=%u, net sport=0x%x",
		ntohs(t1->dest), t1->dest, ntohs(t1->source), t1->source);
	nip_dbg("host seq=%u, net seq=0x%x, host ack_seq=%u, net ack_seq=0x%x",
		seq, t1->seq, ack_seq, t1->ack_seq);

	buff->protocol = htons(ETH_P_NEWIP);
	buff->ip_summed = CHECKSUM_NONE;
	buff->csum = 0;

	/* Fill in nip header */
	head.saddr = *saddr;
	head.daddr = *daddr;
	head.ttl = NIP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_TCP;
	head.hdr_buf = hdr_buf;
	nip_hdr_comm_encap(&head);
	head.total_len = head.hdr_buf_pos + buff->len;
	nip_update_total_len(&head, htons(head.total_len));

	/* Check routine */
	fln.daddr = *daddr;
	dst = nip_route_output(net, sk, &fln); // here, sk not used.
	if (!dst) {
		nip_dbg("cannot find dst");
		goto out;
	}
	skb_dst_set_noref(buff, dst);

	/* Build newip header */
	skb_push(buff, head.hdr_buf_pos);
	memcpy(buff->data, head.hdr_buf, head.hdr_buf_pos);

	skb_reset_network_header(buff);
	NIPCB(buff)->srcaddr = *saddr;
	NIPCB(buff)->dstaddr = *daddr;
	NIPCB(buff)->nexthdr = head.nexthdr;

	buff->priority = priority;
	head.total_len = buff->len;
	err = nip_send_skb(buff);
	if (err)
		nip_dbg("failed to send skb, skb->len=%u", head.total_len);
	else
		nip_dbg("send skb ok, skb->len=%u", head.total_len);

out:
	return;
}
