/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Definitions for the NewIP ICMP protocol.
 *
 * Based on include/linux/icmp.h
 */
#ifndef _LINUX_NIP_ICMP_H
#define _LINUX_NIP_ICMP_H

#include <uapi/linux/nip_icmp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

static inline struct nip_icmp_hdr *nip_icmp_header(const struct sk_buff *skb)
{
	return (struct nip_icmp_hdr *)skb_transport_header(skb);
}

int nip_icmp_init(void);

#endif
