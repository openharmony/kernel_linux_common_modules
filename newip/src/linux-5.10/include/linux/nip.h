/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Based on include/linux/ipv6.h
 * Based on include/net/sock.h
 */
#ifndef _NIP_H
#define _NIP_H

#include <uapi/linux/nip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>

#define ETH_P_NEWIP  0xEADD  /* NIP */

/* struct sock_common __sk_common */
#define sk_nip_daddr     __sk_common.nip_daddr
#define sk_nip_rcv_saddr __sk_common.nip_rcv_saddr

/* struct request_sock req */
#define ir_nip_rmt_addr req.__req_common.nip_daddr
#define ir_nip_loc_addr req.__req_common.nip_rcv_saddr

struct nip_devconf {
	__s32 forwarding;
	__s32 mtu;
	__s32 ignore_routes_with_linkdown;

	__s32 disable_nip;
	__s32 nndisc_notify;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;

	struct ctl_table_header *sysctl_header;
};

/* This structure contains results of exthdrs parsing
 * The common CB structure: struct sk_buff->char cb[48]
 * TCP CB structure       : struct tcp_skb_cb
 * struct tcp_skb_cb->header is union, include IPv4/IPv6/NewIP xx_skb_parm, max size is 24
 * sizeof(struct ninet_skb_parm)=19
 * sizeof(struct inet_skb_parm)=24
 * sizeof(struct inet6_skb_parm)=20
 * sizeof(struct tcp_skb_cb->exclude skb_parm)=24 |__ total size is 48, struct sk_buff->char cb[48]
 * sizeof(struct tcp_skb_cb->include skb_parm)=24 |
 */
#pragma pack(1)
struct ninet_skb_parm {
	struct nip_addr dstaddr;
	struct nip_addr srcaddr;
	u8 nexthdr;
};
#pragma pack()

struct tcp_nip_common {
	u32 ack_retrans_num;
	u32 ack_retrans_seq;
	u32 nip_ssthresh;
	u32 nip_ssthresh_reset;
	bool nip_keepalive_enable;
	u32 idle_ka_probes_out;
	u32 nip_keepalive_out;
	u32 last_rcv_nxt;
	u32 dup_ack_cnt;
	u32 keepalive_time_bak;
	u32 keepalive_probes_bak;
	u32 keepalive_intvl_bak;
};

struct tcp_nip_request_sock {
	struct tcp_request_sock tcp_nip_rsk_tcp;
	struct tcp_nip_common common;
};

struct nip_udp_sock {
	struct udp_sock udp;
};

struct tcp_nip_sock {
	struct tcp_sock tcp;
	struct tcp_nip_common common;
};

#endif /* _NIP_H */
