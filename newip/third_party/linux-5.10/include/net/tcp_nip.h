/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Based on include/net/tcp.h
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Based on include/linux/tcp.h
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Definitions for the NewIP TCP module.
 */
#ifndef _TCP_NIP_H
#define _TCP_NIP_H

#define FASTRETRANS_DEBUG 1

#include <linux/list.h>
#include <linux/tcp.h>
#include <linux/bug.h>
#include <linux/slab.h>
#include <linux/cache.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/kref.h>
#include <linux/ktime.h>

#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <net/inet_hashtables.h>
#include <net/checksum.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/tcp_states.h>
#include <net/inet_ecn.h>
#include <net/dst.h>

#include <net/tcp.h>
#include <net/nip.h>
#include <net/ninet_connection_sock.h>
#include <linux/seq_file.h>
#include <linux/memcontrol.h>

extern struct proto tcp_nip_prot;

#define TCP_HDR_LEN_OFFSET 6
#define TCP_HDR_LEN_POS_PAYLOAD 12
#define TCP_NIP_4BYTE_PAYLOAD 2

#define TCP_OPT_MSS_PAYLOAD 24
#define TCP_OLEN_MSS_PAYLOAD 16

#define TCP_NUM_2 2
#define TCP_NUM_4 4

#define TCP_ARRAY_INDEX_2 2

#define TCP_NIP_KEEPALIVE_CYCLE_MS_DIVISOR 20
#define TCP_NIP_CSK_KEEPALIVE_CYCLE 10

#define TCP_NIP_WINDOW_MAX 65535U

#define TCP_NIP_WRITE_TIMER_DEFERRED  (TCP_MTU_REDUCED_DEFERRED + 1)
#define TCP_NIP_DELACK_TIMER_DEFERRED (TCP_NIP_WRITE_TIMER_DEFERRED + 1)

/* init */
int tcp_nip_init(void);
void tcp_nip_exit(void);

void tcp_nip_done(struct sock *sk);
int tcp_direct_connect(struct sock *sk, void __user *arg);
void tcp_nip_rcv_established(
	struct sock *sk,
	struct sk_buff *skb,
	const struct tcphdr *th,
	unsigned int len);

void __tcp_nip_push_pending_frames(
	struct sock *sk,
	unsigned int cur_mss,
	int nonagle);

u32 __nip_tcp_select_window(struct sock *sk);
unsigned short nip_get_output_checksum_tcp(struct sk_buff *skb, struct nip_addr src_addr,
					   struct nip_addr dst_addr);
void tcp_nip_rearm_rto(struct sock *sk);

int tcp_nip_rcv_state_process(struct sock *sk, struct sk_buff *skb);

/* tcp_nip_output */
int tcp_nip_transmit_skb(
	struct sock *sk,
	struct sk_buff *skb,
	int clone_it,
	gfp_t gfp_mask);
int __tcp_nip_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs);
int tcp_nip_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs);
void tcp_nip_send_fin(struct sock *sk);
void tcp_nip_send_active_reset(struct sock *sk, gfp_t priority);
void tcp_nip_send_probe0(struct sock *sk);
int tcp_nip_write_wakeup(struct sock *sk, int mib);

/* tcp_nip_timer */
void tcp_nip_init_xmit_timers(struct sock *sk);
void tcp_nip_clear_xmit_timers(struct sock *sk);
void tcp_nip_delack_timer_handler(struct sock *sk);
void tcp_nip_write_timer_handler(struct sock *sk);

static inline struct sk_buff *tcp_nip_send_head(const struct sock *sk)
{
	return sk->sk_send_head;
}

static inline void tcp_nip_add_write_queue_tail(
	struct sock *sk,
	struct sk_buff *skb)
{
	__skb_queue_tail(&sk->sk_write_queue, skb);

	if (sk->sk_send_head == NULL)
		sk->sk_send_head = skb;
}

static inline void tcp_nip_write_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		tcp_skb_tsorted_anchor_cleanup(skb);
		sk_wmem_free_skb(sk, skb);
	}

	tcp_clear_all_retrans_hints(tcp_sk(sk));
	sk->sk_send_head = NULL;
	tcp_sk(sk)->packets_out = 0;
	inet_csk(sk)->icsk_backoff = 0;
}

static inline bool tcp_nip_write_queue_empty(struct sock *sk)
{
	return skb_queue_empty(&sk->sk_write_queue);
}

static inline struct tcp_nip_sock *tcp_nip_sk(const struct sock *sk)
{
	return (struct tcp_nip_sock *)sk;
}

static inline struct tcp_nip_request_sock *tcp_nip_rsk(const struct request_sock *req)
{
	return (struct tcp_nip_request_sock *)req;
}

/* connect */
int __tcp_nip_connect(struct sock *sk);
int _tcp_nip_conn_request(struct request_sock_ops *rsk_ops,
			  const struct tcp_request_sock_ops *af_ops,
			  struct sock *sk, struct sk_buff *skb);
struct sk_buff *tcp_nip_make_synack(
	const struct sock *sk,
	struct dst_entry *dst,
	struct request_sock *req,
	struct tcp_fastopen_cookie *foc,
	enum tcp_synack_type synack_type);
int nip_send_synack(struct request_sock *req, struct sk_buff *skb);
struct sock *tcp_nip_check_req(struct sock *sk, struct sk_buff *skb,
			   struct request_sock *req);
int tcp_nip_child_process(struct sock *parent, struct sock *child,
		      struct sk_buff *skb);
int tcp_nip_rtx_synack(const struct sock *sk, struct request_sock *req);

/* client send ack */
void tcp_nip_send_ack(struct sock *sk);
struct sock *tcp_nip_create_openreq_child(const struct sock *sk,
				      struct request_sock *req,
				      struct sk_buff *skb);
void tcp_nip_initialize_rcv_mss(struct sock *sk);

/* release */
void tcp_nip_release_cb(struct sock *sk);

void tcp_nip_keepalive_enable(struct sock *sk);
void tcp_nip_keepalive_disable(struct sock *sk);

#endif  /* _NIP_TCP_H */
