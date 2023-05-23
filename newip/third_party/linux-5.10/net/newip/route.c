// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv4/route.c
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Linus Torvalds, <Linus.Torvalds@helsinki.fi>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *		Alan Cox	:	Verify area fixes.
 *		Alan Cox	:	cli() protects routing changes
 *		Rui Oliveira	:	ICMP routing table updates
 *		(rco@di.uminho.pt)	Routing table insertion and update
 *		Linus Torvalds	:	Rewrote bits to be sensible
 *		Alan Cox	:	Added BSD route gw semantics
 *		Alan Cox	:	Super /proc >4K
 *		Alan Cox	:	MTU in route table
 *		Alan Cox	:	MSS actually. Also added the window
 *					clamper.
 *		Sam Lantinga	:	Fixed route matching in rt_del()
 *		Alan Cox	:	Routing cache support.
 *		Alan Cox	:	Removed compatibility cruft.
 *		Alan Cox	:	RTF_REJECT support.
 *		Alan Cox	:	TCP irtt support.
 *		Jonathan Naylor	:	Added Metric support.
 *	Miquel van Smoorenburg	:	BSD API fixes.
 *	Miquel van Smoorenburg	:	Metrics.
 *		Alan Cox	:	Use __u32 properly
 *		Alan Cox	:	Aligned routing errors more closely with BSD
 *					our system is still very different.
 *		Alan Cox	:	Faster /proc handling
 *	Alexey Kuznetsov	:	Massive rework to support tree based routing,
 *					routing caches and better behaviour.
 *
 *		Olaf Erb	:	irtt wasn't being copied right.
 *		Bjorn Ekwall	:	Kerneld route support.
 *		Alan Cox	:	Multicast fixed (I hope)
 *		Pavel Krauz	:	Limited broadcast fixed
 *		Mike McLagan	:	Routing by source
 *	Alexey Kuznetsov	:	End of old history. Split to fib.c and
 *					route.c and rewritten from scratch.
 *		Andi Kleen	:	Load-limit warning messages.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *	Vitaly E. Lavrov	:	Race condition in ip_route_input_slow.
 *	Tobias Ringstrom	:	Uninitialized res.type in ip_route_output_slow.
 *	Vladimir V. Ivanov	:	IP rule info (flowid) is really useful.
 *		Marc Boucher	:	routing by fwmark
 *	Robert Olsson		:	Added rt_cache statistics
 *	Arnaldo C. Melo		:	Convert proc stuff to seq_file
 *	Eric Dumazet		:	hashed spinlocks and rt_check_expire() fixes.
 *	Ilia Sotnikov		:	Ignore TOS on PMTUD and Redirect
 *	Ilia Sotnikov		:	Removed TOS from hash calculations
 *
 * Based on net/ipv6/route.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Changes:
 *
 *	YOSHIFUJI Hideaki @USAGI
 *		reworked default router selection.
 *		- respect outgoing interface
 *		- select from (probably) reachable routers (i.e.
 *		routers in REACHABLE, STALE, DELAY or PROBE states).
 *		- always select the same router if it is (probably)
 *		reachable.  otherwise, round-robin the list.
 *	Ville Nuorvala
 *		Fixed routing subtrees.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * ROUTE - implementation of the NewIP router.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/sockios.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/capability.h>
#include <linux/proc_fs.h>

#include <net/sock.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/protocol.h>
#include <net/dst.h>
#include <net/lwtunnel.h>
#include <linux/uaccess.h>   /* copy_from_user() */
#include <linux/rtnetlink.h> /* rtnl_lock() */
#include <linux/inetdevice.h>

#include <net/nip_route.h>
#include <net/nip_fib.h>
#include <net/nip_addrconf.h>
#include <net/nndisc.h>
#include <net/nip.h>

#include <linux/newip_route.h>
#include "nip_hdr.h"
#include "tcp_nip_parameter.h"

static int nip_pkt_discard(struct sk_buff *skb);
static int nip_pkt_discard_out(struct net *net, struct sock *sk,
			       struct sk_buff *skb);
static unsigned int	 nip_mtu(const struct dst_entry *dst);

static const struct nip_rt_info nip_null_entry_template = {
	.dst = {
		.__refcnt = ATOMIC_INIT(1),
		.__use = 1,
		.obsolete = DST_OBSOLETE_FORCE_CHK,
		.error = -ENETUNREACH,
		.input = nip_pkt_discard,
		.output = nip_pkt_discard_out,
		 },
	.rt_ref = ATOMIC_INIT(1),
};

static const struct nip_rt_info nip_broadcast_entry_template = {
	.dst = {
		.__refcnt = ATOMIC_INIT(1),
		.__use = 1,
		.obsolete = DST_OBSOLETE_FORCE_CHK,
		.input = nip_input,
		.output = nip_output,
		 },
	.rt_ref = ATOMIC_INIT(1),
};

struct nip_addr *nip_nexthop(struct nip_rt_info *rt, struct nip_addr *daddr)
{
	if (rt->rt_flags & RTF_GATEWAY)
		return &rt->gateway;
	else
		return daddr;
}

static void rtmsg_to_fibni_config(struct net *net, struct nip_rtmsg *rtmsg,
				  struct nip_fib_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));

	cfg->fc_table = NIP_RT_TABLE_MAIN;
	cfg->fc_ifindex = rtmsg->rtmsg_ifindex;
	cfg->fc_metric = rtmsg->rtmsg_metric;
	cfg->fc_expires = rtmsg->rtmsg_info;

	cfg->fc_flags = rtmsg->rtmsg_flags;

	cfg->fc_nlinfo.nl_net = net;

	cfg->fc_dst = rtmsg->rtmsg_dst;
	cfg->fc_src = rtmsg->rtmsg_src;
	cfg->fc_gateway = rtmsg->rtmsg_gateway;
}

static void nip_rt_info_init(struct nip_rt_info *rt)
{
	struct dst_entry *dst = &rt->dst;

	memset(dst + 1, 0, sizeof(*rt) - sizeof(*dst));
	rt->from = NULL;
}

static struct nip_rt_info *__nip_dst_alloc(struct net *net,
					   struct net_device *dev, int flags)
{
	struct nip_rt_info *rt =
	    dst_alloc(&net->newip.nip_dst_ops, dev, 1, DST_OBSOLETE_FORCE_CHK,
		      flags);

	if (rt)
		nip_rt_info_init(rt);

	return rt;
}

struct nip_rt_info *nip_dst_alloc(struct net *net, struct net_device *dev,
				  int flags)
{
	struct nip_rt_info *rt = __nip_dst_alloc(net, dev, flags);

	if (rt) {
		rt->rt_pcpu =
		    alloc_percpu_gfp(struct nip_rt_info *, GFP_ATOMIC);
		if (rt->rt_pcpu) {
			int cpu;

			for_each_possible_cpu(cpu) {
				struct nip_rt_info **p;

				p = per_cpu_ptr(rt->rt_pcpu, cpu);
				/* no one shares rt */
				*p = NULL;
			}
		} else {
			dst_destroy((struct dst_entry *)rt);
			return NULL;
		}
	}

	return rt;
}

static void nip_rt_dst_from_metrics_check(struct nip_rt_info *rt)
{
	if (rt->from &&
	    dst_metrics_ptr(&rt->dst) != dst_metrics_ptr(rt->from))
		dst_init_metrics(&rt->dst, dst_metrics_ptr(rt->from), true);
}

static struct nip_rt_info *nip_rt_get_pcpu_route(struct nip_rt_info *rt)
{
	struct nip_rt_info *pcpu_rt, **p;

	p = this_cpu_ptr(rt->rt_pcpu);
	pcpu_rt = *p;

	if (pcpu_rt) {
		dst_hold(&pcpu_rt->dst);
		nip_rt_dst_from_metrics_check(pcpu_rt);
	}
	return pcpu_rt;
}

static void nip_rt_set_from(struct nip_rt_info *rt, struct nip_rt_info *from)
{
	WARN_ON(from->from);

	rt->rt_flags &= ~RTF_EXPIRES;
	dst_hold(&from->dst);
	rt->from = &from->dst;
	dst_init_metrics(&rt->dst, dst_metrics_ptr(&from->dst), true);
}

static void nip_rt_copy_init(struct nip_rt_info *rt, struct nip_rt_info *ort)
{
	rt->dst.input = ort->dst.input;
	rt->dst.output = ort->dst.output;
	rt->rt_dst = ort->rt_dst;
	rt->dst.error = ort->dst.error;
	rt->rt_idev = ort->rt_idev;
	if (rt->rt_idev)
		nin_dev_hold(rt->rt_idev);

	rt->dst.lastuse = jiffies;
	rt->gateway = ort->gateway;
	rt->rt_flags = ort->rt_flags;
	nip_rt_set_from(rt, ort);
	rt->rt_metric = ort->rt_metric;
	rt->rt_table = ort->rt_table;
	rt->dst.lwtstate = lwtstate_get(ort->dst.lwtstate);
}

static struct nip_rt_info *nip_rt_pcpu_alloc(struct nip_rt_info *rt)
{
	struct nip_rt_info *pcpu_rt;

	pcpu_rt = __nip_dst_alloc(dev_net(rt->dst.dev),
				  rt->dst.dev, rt->dst.flags);
	if (!pcpu_rt)
		return NULL;
	nip_rt_copy_init(pcpu_rt, rt);
	pcpu_rt->rt_protocol = rt->rt_protocol;
	pcpu_rt->rt_flags |= RTF_PCPU;
	return pcpu_rt;
}

static struct nip_rt_info *nip_rt_make_pcpu_route(struct nip_rt_info *rt)
{
	struct nip_rt_info *pcpu_rt, *prev;

	pcpu_rt = nip_rt_pcpu_alloc(rt);
	if (!pcpu_rt) {
		struct net *net = dev_net(rt->dst.dev);

		dst_hold(&net->newip.nip_null_entry->dst);
		return net->newip.nip_null_entry;
	}

	rcu_read_lock_bh();
	if (rt->rt_pcpu) {
		struct nip_rt_info **p = this_cpu_ptr(rt->rt_pcpu);

		prev = cmpxchg(p, NULL, pcpu_rt);
		if (prev) {
			/* If someone did it before us, return prev instead */
			dst_destroy(&pcpu_rt->dst);
			pcpu_rt = prev;
		}
	} else {
		dst_destroy(&pcpu_rt->dst);
		pcpu_rt = rt;
	}
	dst_hold(&pcpu_rt->dst);
	nip_rt_dst_from_metrics_check(pcpu_rt);
	rcu_read_unlock_bh();
	return pcpu_rt;
}

static struct nip_rt_info *nip_pol_route_input(struct net *net,
					       struct nip_fib_table *table,
					       struct flow_nip *fln, int flags)
{
	return nip_pol_route(net, table, fln->flowin_iif, fln, flags);
}

struct dst_entry *nip_route_input_lookup(struct net *net,
					 struct net_device *dev,
					 struct flow_nip *fln, int flags, int *tbl_type)
{
	return nip_fib_rule_lookup(net, fln, flags, tbl_type, nip_pol_route_input);
}

int nip_route_input(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	int flags = 0;
	struct flow_nip fln = {
		.flowin_iif = skb->skb_iif,
		.daddr = NIPCB(skb)->dstaddr,
		.saddr = NIPCB(skb)->srcaddr,
	};
	struct dst_entry *out_dst;
	int tbl_type = 0;

	if (nip_addr_eq(&fln.daddr, &nip_broadcast_addr_arp)) {
		nip_dbg("recv broadcast packet");
		dst_hold(&net->newip.nip_broadcast_entry->dst);
		skb_dst_set(skb,
			    (struct dst_entry *)net->newip.nip_broadcast_entry);
		return 0;
	}

	out_dst = nip_route_input_lookup(net, skb->dev, &fln, flags, &tbl_type);
	skb_dst_set(skb, out_dst);

	if (tbl_type == RT_TABLE_MAIN) {
		struct ninet_dev *nin_dev = rcu_dereference(skb->dev->nip_ptr);
		struct ninet_dev *nout_dev = rcu_dereference(out_dst->dev->nip_ptr);

		/* When global variable ipv4 all/send_redirects or
		 * corresponding network/send_redirects is 1,
		 * IN_DEV_TX_REDIRECTS() conditions are valid.
		 * send_redirects default is 1.
		 */
		if (nin_dev == nout_dev &&
		    IN_DEV_TX_REDIRECTS(rcu_dereference(out_dst->dev->ip_ptr))) {
			nip_dbg("The inlet and outlet are the same");
			return 1;
		}
	}
	return 0;
}

static struct nip_rt_info *nip_pol_route_output(struct net *net,
						struct nip_fib_table *table,
						struct flow_nip *fln, int flags)
{
	return nip_pol_route(net, table, fln->flowin_oif, fln, flags);
}

struct dst_entry *nip_route_output_flags(struct net *net, const struct sock *sk,
					 struct flow_nip *fln, int flags)
{
	struct dst_entry *dst;
	struct nip_rt_info *rt;
	int tbl_type = 0;

	dst = nip_fib_rule_lookup(net, fln, flags, &tbl_type, nip_pol_route_output);
	rt = (struct nip_rt_info *)dst;

	if (!(rt->rt_flags & RTF_LOCAL))
		return dst;

	rcu_read_lock();
	if (rt->rt_idev) {
		read_lock_bh(&rt->rt_idev->lock);
		/* search saddr in idev->addr */
		if (!list_empty(&rt->rt_idev->addr_list)) {
			struct ninet_ifaddr *ifp;

			list_for_each_entry(ifp, &rt->rt_idev->addr_list, if_list) {
				fln->saddr = ifp->addr;
				break;
			}
		}
		read_unlock_bh(&rt->rt_idev->lock);
	}
	rcu_read_unlock();

	dst_release(dst);
	dst_hold(&net->newip.nip_broadcast_entry->dst);
	return &net->newip.nip_broadcast_entry->dst;
}

struct nip_rt_info *nip_pol_route(struct net *net, struct nip_fib_table *table,
				  int oif, struct flow_nip *fln, int flags)
{
	struct nip_fib_node *fn;
	struct nip_rt_info *rt, *pcpu_rt;

	rcu_read_lock_bh();
	fn = nip_fib_locate(table->nip_tb_head, &fln->daddr);
	if (!fn) {
		rcu_read_unlock_bh();
		nip_dbg("search fail");
		rt = net->newip.nip_null_entry;
		dst_hold_and_use(&rt->dst, jiffies);
		return rt;
	}
	rt = fn->nip_route_info;

	/* Get a percpu copy */
	rt->dst.lastuse = jiffies;
	rt->dst.__use++;
	pcpu_rt = nip_rt_get_pcpu_route(rt);
	nip_dbg("cpu id=%d", smp_processor_id());
	if (pcpu_rt) {
		rcu_read_unlock_bh();
		nip_dbg("pcpu found");
	} else {
		dst_hold(&rt->dst);
		rcu_read_unlock_bh();
		pcpu_rt = nip_rt_make_pcpu_route(rt);
		dst_release(&rt->dst);
	}

	nip_dbg("rt dst.__refcnt=%d, pcpu dst.__refcnt=%d",
		atomic_read(&rt->dst.__refcnt),
		atomic_read(&pcpu_rt->dst.__refcnt));
	return pcpu_rt;
}

bool nip_bind_addr_check(struct net *net,
			 struct nip_addr *addr)
{
	struct nip_fib_node *fn;
	struct nip_fib_table *fib_tbl = net->newip.nip_fib_local_tbl;

	if (nip_addr_invalid(addr)) {
		nip_dbg("binding-addr invalid, bitlen=%u", addr->bitlen);
		return false;
	}

	if (nip_addr_eq(addr, &nip_any_addr)) {
		nip_dbg("binding-addr is any addr");
		return true;
	}

	rcu_read_lock_bh();
	fn = nip_fib_locate(fib_tbl->nip_tb_head, addr);
	rcu_read_unlock_bh();
	if (!fn) {
		nip_dbg("binding-addr is not local addr");
		return false;
	}

	nip_dbg("binding-addr is local addr");
	return true;
}

static struct nip_rt_info *nip_route_info_create(struct nip_fib_config *cfg)
{
	struct net *net = cfg->fc_nlinfo.nl_net;
	struct nip_rt_info *rt = NULL;
	struct net_device *dev = NULL;
	struct ninet_dev *idev = NULL;
	struct nip_fib_table *table;
	int err = -ENODEV;

	/* find net_device */
	dev = dev_get_by_index(net, cfg->fc_ifindex);
	if (!dev) {
		nip_dbg("fail to get dev by ifindex(%u)", cfg->fc_ifindex);
		goto out;
	}

	/* find ninet_dev，which has the newip address list */
	idev = nin_dev_get(dev);
	if (!idev) {
		nip_dbg("fail to get ninet dev (ifindex=%u)", cfg->fc_ifindex);
		goto out;
	}
	/* Do not add a route when the network port is not running
	 * to avoid incorrect route selection
	 */
	if (!netif_running(idev->dev)) {
		nip_dbg("network interface is not running");
		goto out;
	}
	if (cfg->fc_metric == 0)
		cfg->fc_metric = NIP_RT_PRIO_USER;

	err = -ENOBUFS;
	table = nip_fib_get_table(net, cfg->fc_table);
	if (!table) {
		nip_dbg("fail to get fib table (fc_table=%u)", cfg->fc_table);
		goto out;
	}

	rt = nip_dst_alloc(net, NULL, (cfg->fc_flags & RTF_ADDRCONF) ? 0 : DST_NOCOUNT);
	if (!rt) {
		nip_dbg("fail to alloc dst mem");
		err = -ENOMEM;
		goto out;
	}

	nip_rt_clean_expires(rt);

	if (cfg->fc_protocol == RTPROT_UNSPEC)
		cfg->fc_protocol = RTPROT_BOOT;
	rt->rt_protocol = cfg->fc_protocol;

	if (cfg->fc_flags & RTF_LOCAL) {
		rt->dst.input = nip_input;
		nip_dbg("rt->dst.input=nip_input, ifindex=%u", cfg->fc_ifindex);
	} else {
		rt->dst.input = nip_forward;
		nip_dbg("rt->dst.input=nip_forward, ifindex=%u", cfg->fc_ifindex);
	}

	rt->dst.output = nip_output;
	rt->rt_dst = cfg->fc_dst;
	rt->rt_src = cfg->fc_src;
	rt->rt_metric = cfg->fc_metric;

	if (cfg->fc_flags & RTF_GATEWAY)
		rt->gateway = cfg->fc_gateway;
	else
		rt->gateway = nip_any_addr;

	rt->rt_flags = cfg->fc_flags;
	rt->dst.dev = dev;
	rt->rt_idev = idev;
	rt->rt_table = table;

	return rt;
out:
	if (dev)
		dev_put(dev);
	if (idev)
		nin_dev_put(idev);
	return ERR_PTR(err);
}

/* __nip_ins_rt is called with FREE table->nip_tb_lock.
 * It takes new route entry, the addition fails by any reason the
 * route is released.
 */
static int __nip_ins_rt(struct nip_rt_info *rt)
{
	int err;
	struct nip_fib_table *table;

	table = rt->rt_table;

	spin_lock_bh(&table->nip_tb_lock);
	err = nip_fib_add(table, rt);
	spin_unlock_bh(&table->nip_tb_lock);

	return err;
}

int nip_ins_rt(struct nip_rt_info *rt)
{
	/* Hold dst to account for the reference from the nip fib hash */
	dst_hold(&rt->dst);
	return __nip_ins_rt(rt);
}

int nip_route_add(struct nip_fib_config *cfg)
{
	struct nip_rt_info *rt;
	int err;

	rt = nip_route_info_create(cfg);
	if (IS_ERR(rt)) {
		nip_dbg("fail to creat route info");
		err = PTR_ERR(rt);
		rt = NULL;
		goto out;
	}

	err = __nip_ins_rt(rt);
out:
	return err;
}

static int __nip_del_rt(struct nip_rt_info *rt, struct nl_info *info)
{
	int err;
	struct nip_fib_table *table;
	struct net *net = dev_net(rt->dst.dev);

	if (rt == net->newip.nip_null_entry) {
		err = -ENOENT;
		goto out;
	}

	table = rt->rt_table;
	spin_lock_bh(&table->nip_tb_lock);
	err = nip_fib_del(rt, info);
	spin_unlock_bh(&table->nip_tb_lock);

out:
	nip_rt_put(rt);
	return err;
}

int nip_del_rt(struct nip_rt_info *rt)
{
	struct nl_info info = {
		.nl_net = dev_net(rt->dst.dev),
	};
	return __nip_del_rt(rt, &info);
}

static int nip_route_del(struct nip_fib_config *cfg)
{
	struct net *net = cfg->fc_nlinfo.nl_net;
	struct nip_fib_table *table;
	struct nip_fib_node *fn;
	struct nip_rt_info *rt;
	int err = -ESRCH;

	table = nip_fib_get_table(net, cfg->fc_table);
	if (!table)
		return err;

	rcu_read_lock_bh();
	fn = nip_fib_locate(table->nip_tb_head, &cfg->fc_dst);
	if (fn) {
		rt = fn->nip_route_info;
		dst_hold(&rt->dst);
		rcu_read_unlock_bh();

		return __nip_del_rt(rt, &cfg->fc_nlinfo);
	}
	rcu_read_unlock_bh();

	return err;
}

int nip_route_ioctl(struct net *net, unsigned int cmd, struct nip_rtmsg *rtmsg)
{
	struct nip_fib_config cfg;
	int err;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
		nip_dbg("not admin can`t cfg");
		return -EPERM;
	}

	rtmsg_to_fibni_config(net, rtmsg, &cfg);
	if (nip_addr_invalid(&cfg.fc_dst)) {
		nip_dbg("nip daddr invalid, bitlen=%u", cfg.fc_dst.bitlen);
		return -EFAULT;
	}

	if (cfg.fc_flags & RTF_GATEWAY) {
		if (nip_addr_invalid(&cfg.fc_gateway)) {
			nip_dbg("nip gateway daddr invalid, bitlen=%u",
				cfg.fc_gateway.bitlen);
			return -EFAULT;
		}
	}

	rtnl_lock();
	switch (cmd) {
	case SIOCADDRT: /* Add a route */
		err = nip_route_add(&cfg);
		break;
	case SIOCDELRT: /* Delete a route */
		err = nip_route_del(&cfg);
		break;
	default:
		err = -EINVAL;
	}
	rtnl_unlock();

	return err;
}

static void nip_dst_destroy(struct dst_entry *dst)
{
	struct nip_rt_info *rt = (struct nip_rt_info *)dst;
	struct dst_entry *from = rt->from;
	struct ninet_dev *idev;

	dst_destroy_metrics_generic(dst);
	free_percpu(rt->rt_pcpu);

	idev = rt->rt_idev;
	if (idev) {
		rt->rt_idev = NULL;
		nip_dbg("idev->refcnt=%u", refcount_read(&idev->refcnt));
		nin_dev_put(idev);
	}

	if (from)
		nip_dbg("from->__refcnt=%d", atomic_read(&from->__refcnt));
	rt->from = NULL;
	dst_release(from);
}

static inline const void *nip_choose_neigh_daddr(struct nip_rt_info *rt,
						 struct sk_buff *skb,
						 const void *daddr)
{
	struct nip_addr *p = &rt->gateway;

	if (rt->rt_flags & RTF_GATEWAY)
		return (const void *)p;
	else if (skb)
		return &NIPCB(skb)->dstaddr;
	return daddr;
}

static struct neighbour *nip_neigh_lookup(const struct dst_entry *dst,
					  struct sk_buff *skb,
					  const void *daddr)
{
	struct nip_rt_info *rt = (struct nip_rt_info *)dst;
	struct neighbour *n;

	daddr = nip_choose_neigh_daddr(rt, skb, daddr);
	n = __nip_neigh_lookup(dst->dev, daddr);
	if (n)
		return n;
	return neigh_create(&nnd_tbl, daddr, dst->dev);
}

static struct dst_entry *nip_dst_check(struct dst_entry *dst, u32 cookie)
{
	if (dst->obsolete != DST_OBSOLETE_FORCE_CHK)
		return NULL;
	return dst;
}

/* Used to calculate the MSS value required by TCP
 * Because there is no MSS in the TCP of NewIP,
 * the value is calculated based on the MTU of the network port
 */
static unsigned int nip_default_advmss(const struct dst_entry *dst)
{
	unsigned int mtu = dst_mtu(dst);

	mtu -= NIP_HDR_MAX + sizeof(struct tcphdr);

	return mtu;
}

static unsigned int nip_mtu(const struct dst_entry *dst)
{
	unsigned int mtu;
	struct ninet_dev *idev;

	mtu = NIP_MIN_MTU;

	rcu_read_lock();
	idev = __nin_dev_get(dst->dev);
	if (idev)
		mtu = idev->cnf.mtu;
	rcu_read_unlock();

	return mtu;
}

static void nip_dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			   int how)
{
	struct nip_rt_info *rt = (struct nip_rt_info *)dst;
	struct ninet_dev *idev = rt->rt_idev;
	struct net_device *loopback_dev =
		dev_net(dev)->loopback_dev;

	if (idev && idev->dev != loopback_dev) {
		struct ninet_dev *loopback_idev = nin_dev_get(loopback_dev);

		if (loopback_idev) {
			rt->rt_idev = loopback_idev;
			nin_dev_put(idev);
		}
	}
}

static struct dst_ops nip_dst_ops_template = {
	.family			= AF_NINET,
	.destroy		= nip_dst_destroy,
	.ifdown			= nip_dst_ifdown,
	.neigh_lookup		= nip_neigh_lookup,
	.check			= nip_dst_check,
	.default_advmss		= nip_default_advmss,
	.mtu			= nip_mtu,
};

static int nip_pkt_discard(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static int nip_pkt_discard_out(struct net *net, struct sock *sk,
			       struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

struct nip_rt_info *nip_addrconf_dst_alloc(struct ninet_dev *idev,
					   const struct nip_addr *addr)
{
	u32 tb_id;
	struct net *net = dev_net(idev->dev);
	struct net_device *dev = idev->dev;
	struct nip_rt_info *rt;

	rt = nip_dst_alloc(net, dev, DST_NOCOUNT);
	if (!rt)
		return ERR_PTR(-ENOMEM);

	nin_dev_hold(idev);

	rt->dst.flags |= DST_HOST;
	rt->dst.input = nip_input;
	rt->dst.output = nip_output;
	rt->rt_idev = idev;

	rt->rt_protocol = RTPROT_KERNEL;
	rt->rt_flags = RTF_UP | RTF_NONEXTHOP;
	rt->rt_flags |= RTF_LOCAL;

	rt->gateway = *addr;
	rt->rt_dst = *addr;
	tb_id = NIP_RT_TABLE_LOCAL;
	rt->rt_table = nip_fib_get_table(net, tb_id);

	return rt;
}

struct arg_dev_net {
	struct net_device *dev;
	struct net *net;
};

/* Determine whether an RT should be deleted along with ifDown
 * called with nip_tb_lock held for table with rt
 */
static int nip_fib_ifdown(struct nip_rt_info *rt, void *arg)
{
	const struct arg_dev_net *adn = arg;
	const struct net_device *dev = adn->dev;
	bool not_same_dev = (rt->dst.dev == dev || !dev);
	bool not_null_entry = (rt != adn->net->newip.nip_null_entry);
	bool not_broadcast_entry = (rt != adn->net->newip.nip_broadcast_entry);
	bool dev_unregister = (dev && netdev_unregistering(dev));
	bool ignore_route_ifdown = (!rt->rt_idev->cnf.ignore_routes_with_linkdown);

	if (not_same_dev && not_null_entry && not_broadcast_entry &&
	    (dev_unregister || ignore_route_ifdown))
		return -1;

	nip_dbg("don`t del route with %s down, ifindex=%u, not_same_dev=%u, not_null_entry=%u",
		dev->name, dev->ifindex, not_same_dev, not_null_entry);
	nip_dbg("not_broadcast_entry=%u, dev_unregister=%u, ignore_route_ifdown=%u",
		not_broadcast_entry, dev_unregister, ignore_route_ifdown);
	return 0;
}

void nip_rt_ifdown(struct net *net, struct net_device *dev)
{
	struct arg_dev_net adn = {
		.dev = dev,
		.net = net,
	};

	nip_fib_clean_all(net, nip_fib_ifdown, &adn);
}

static int __net_init nip_route_net_init(struct net *net)
{
	int ret = -ENOMEM;

	memcpy(&net->newip.nip_dst_ops, &nip_dst_ops_template,
	       sizeof(net->newip.nip_dst_ops));

	if (dst_entries_init(&net->newip.nip_dst_ops) < 0)
		goto out;

	net->newip.nip_null_entry = kmemdup(&nip_null_entry_template,
					    sizeof(*net->newip.nip_null_entry),
					    GFP_KERNEL);
	if (!net->newip.nip_null_entry)
		goto out_nip_dst_entries;
	net->newip.nip_null_entry->dst.ops = &net->newip.nip_dst_ops;
	dst_init_metrics(&net->newip.nip_null_entry->dst, dst_default_metrics.metrics, true);

	net->newip.nip_broadcast_entry =
		kmemdup(&nip_broadcast_entry_template,
			sizeof(*net->newip.nip_broadcast_entry),
						 GFP_KERNEL);
	if (!net->newip.nip_broadcast_entry)
		goto out_nip_null_entry;
	net->newip.nip_broadcast_entry->dst.ops = &net->newip.nip_dst_ops;
	dst_init_metrics(&net->newip.nip_broadcast_entry->dst, dst_default_metrics.metrics, true);
	ret = 0;
out:
	return ret;

out_nip_null_entry:
	kfree(net->newip.nip_null_entry);
out_nip_dst_entries:
	dst_entries_destroy(&net->newip.nip_dst_ops);
	goto out;
}

static void __net_exit nip_route_net_exit(struct net *net)
{
	kfree(net->newip.nip_broadcast_entry);
	kfree(net->newip.nip_null_entry);
	dst_entries_destroy(&net->newip.nip_dst_ops);
}

static struct pernet_operations nip_route_net_ops = {
	.init = nip_route_net_init,
	.exit = nip_route_net_exit,
};

static int nip_route_dev_notify(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);

	if (!(dev->flags & IFF_LOOPBACK))
		return NOTIFY_OK;

	if (event == NETDEV_REGISTER) {
		net->newip.nip_null_entry->dst.dev = dev;
		net->newip.nip_null_entry->rt_idev = nin_dev_get(dev);

		net->newip.nip_broadcast_entry->dst.dev = dev;
		net->newip.nip_broadcast_entry->rt_idev = nin_dev_get(dev);
	} else if (event == NETDEV_UNREGISTER &&
		   dev->reg_state != NETREG_UNREGISTERED) {
		nin_dev_put_clear(&net->newip.nip_null_entry->rt_idev);
		nin_dev_put_clear(&net->newip.nip_broadcast_entry->rt_idev);
	}

	return NOTIFY_OK;
}

static void seq_printf_nipaddr_to_proc(struct seq_file *seq,
				       struct nip_addr *addr)
{
	int i = 0;

	for (i = 0; i < addr->bitlen / NIP_ADDR_BIT_LEN_8; i++)
		seq_printf(seq, "%02x", addr->nip_addr_field8[i]);

	seq_puts(seq, "\t");
}

static void nip_route_show_table(struct seq_file *seq,
				 struct nip_fib_table *table)
{
	struct nip_fib_node *fn;
	int i;

	rcu_read_lock_bh();
	for (i = 0; i < NIN_ROUTE_HSIZE; i++) {
		hlist_for_each_entry_rcu(fn, &table->nip_tb_head[i],
					 fib_hlist) {
			struct nip_rt_info *rt = fn->nip_route_info;

			seq_printf_nipaddr_to_proc(seq, &rt->rt_dst);
			seq_printf_nipaddr_to_proc(seq, &rt->gateway);
			seq_printf(seq, "%4u %4s\n", rt->rt_flags,
				   rt->dst.dev ? rt->dst.dev->name : "");
		}
	}
	rcu_read_unlock_bh();
}

static int nip_route_proc_show(struct seq_file *seq, void *v)
{
	struct net *net = seq->private;

	nip_route_show_table(seq, net->newip.nip_fib_main_tbl);
	nip_route_show_table(seq, net->newip.nip_fib_local_tbl);

	return 0;
}

static int __net_init nip_route_net_init_late(struct net *net)
{
	proc_create_net_single("nip_route", 0444, net->proc_net,
			       nip_route_proc_show, NULL);
	return 0;
}

static void __net_exit nip_route_net_exit_late(struct net *net)
{
	remove_proc_entry("nip_route", net->proc_net);
}

static struct pernet_operations nip_route_net_late_ops = {
	.init = nip_route_net_init_late,
	.exit = nip_route_net_exit_late,
};

static struct notifier_block nip_route_dev_notifier = {
	.notifier_call = nip_route_dev_notify,
	.priority = ADDRCONF_NOTIFY_PRIORITY - 10,
};

int __init nip_route_init(void)
{
	int ret;

	ret = -ENOMEM;

	nip_dst_ops_template.kmem_cachep =
	    kmem_cache_create("nip_dst_cache", sizeof(struct nip_rt_info), 0,
			      SLAB_HWCACHE_ALIGN, NULL);
	if (!nip_dst_ops_template.kmem_cachep)
		goto out;

	ret = register_pernet_subsys(&nip_route_net_ops);
	if (ret)
		goto out_kmem_cache;

	ret = nip_fib_init();
	if (ret)
		goto out_register_subsys;

	ret = register_pernet_subsys(&nip_route_net_late_ops);
	if (ret)
		goto out_nip_fib_init;

	ret = register_netdevice_notifier(&nip_route_dev_notifier);
	if (ret)
		goto out_register_late_subsys;

out:
	return ret;

out_register_late_subsys:
	unregister_pernet_subsys(&nip_route_net_late_ops);
out_nip_fib_init:
	nip_fib_gc_cleanup();
out_register_subsys:
	unregister_pernet_subsys(&nip_route_net_ops);
out_kmem_cache:
	kmem_cache_destroy(nip_dst_ops_template.kmem_cachep);
	goto out;
}

void nip_route_cleanup(void)
{
	unregister_pernet_subsys(&nip_route_net_late_ops);
	nip_fib_gc_cleanup();
	unregister_pernet_subsys(&nip_route_net_ops);
	kmem_cache_destroy(nip_dst_ops_template.kmem_cachep);
}

