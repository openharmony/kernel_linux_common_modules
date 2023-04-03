// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Internet Control Message Protocol (NewIP ICMP)
 * Linux NewIP INET implementation
 *
 * Based on net/ipv6/icmp.c
 * Based on net/ipv4/af_inet.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

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
#include <net/sock.h>
#include <net/nip.h>
#include <net/protocol.h>
#include <net/nip_route.h>
#include <net/nip_addrconf.h>
#include <net/nndisc.h>

#include "nip_hdr.h"
#include "tcp_nip_parameter.h"

int nip_icmp_rcv(struct sk_buff *skb)
{
	int ret = 0;
	struct nip_icmp_hdr *hdr = nip_icmp_header(skb);
	u8 type = hdr->nip_icmp_type;

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
