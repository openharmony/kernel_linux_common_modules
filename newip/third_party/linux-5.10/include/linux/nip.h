/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on include/linux/ipv6.h
 * No Authors, no Copyright
 *
 * Based on include/net/sock.h
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *		Steve Whitehouse:	Default routines for sock_ops
 *		Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *					protinfo be just a void pointer, as the
 *					protocol specific parts were moved to
 *					respective headers and ipv4/v6, etc now
 *					use private slabcaches for its socks
 *		Pedro Hortas	:	New flags field for socket options
 */
#ifndef _NIP_H
#define _NIP_H

#include <uapi/linux/nip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>

#define ETH_P_NEWIP  0xEADD  /* NIP */

/* struct sock_common __sk_common */
#define SK_NIP_DADDR     __sk_common.nip_daddr
#define SK_NIP_RCV_SADDR __sk_common.nip_rcv_saddr

/* struct request_sock req */
#define IR_NIP_RMT_ADDR req.__req_common.nip_daddr
#define IR_NIP_LOC_ADDR req.__req_common.nip_rcv_saddr

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
	u32 nip_srtt;
	u32 nip_bw;
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
