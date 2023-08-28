// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv6/icmp.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Changes:
 *
 *	Andi Kleen		:	exception handling
 *	Andi Kleen			add rate limits. never reply to a icmp.
 *					add more length checks and other fixes.
 *	yoshfuji		:	ensure to sent parameter problem for
 *					fragments.
 *	YOSHIFUJI Hideaki @USAGI:	added sysctl for icmp rate limit.
 *	Randy Dunlap and
 *	YOSHIFUJI Hideaki @USAGI:	Per-interface statistics support
 *	Kazunori MIYAZAWA @USAGI:       change output process to use ip6_append_data
 *
 * Internet Control Message Protocol (NewIP ICMP)
 * Linux NewIP INET implementation
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/sock.h>
#include <net/nip.h>
#include <net/protocol.h>
#include <net/nip_route.h>
#include <net/nip_addrconf.h>
#include <net/nndisc.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/nip_icmp.h>

#include "nip_hdr.h"
#include "tcp_nip_parameter.h"

int nip_icmp_rcv(struct sk_buff *skb)
{
	int ret = 0;
	struct nip_icmp_hdr *hdr;
	u8 type;

	if (!pskb_may_pull(skb, sizeof(struct nip_icmp_hdr))) {
		nip_dbg("invalid ICMP packet");
		return -EINVAL;
	}

	hdr = nip_icmp_header(skb);
	type = hdr->nip_icmp_type;
	nip_dbg("rcv newip icmp packet. type=%u", type);
	switch (type) {
	case NIP_ARP_NS:
	case NIP_ARP_NA:
		ret = nndisc_rcv(skb);
		break;
	default:
		nip_dbg("nip icmp packet type error");
	}
	return ret;
}

static const struct ninet_protocol nip_icmp_protocol = {
	.handler = nip_icmp_rcv,
	.flags = 0,
};

int __init nip_icmp_init(void)
{
	int ret;

	ret = ninet_add_protocol(&nip_icmp_protocol, IPPROTO_NIP_ICMP);
	return ret;
}
