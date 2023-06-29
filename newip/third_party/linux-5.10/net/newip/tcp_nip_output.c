// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on net/ipv4/tcp_output.c
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 * Based on net/ipv4/tcp_minisocks.c
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Implementation of the Transmission Control Protocol(TCP).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/nip.h>
#include <net/tcp_nip.h>
#include <net/tcp.h>
#include <net/ninet_connection_sock.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <net/nip_udp.h>
#include "nip_hdr.h"
#include "nip_checksum.h"
#include "tcp_nip_parameter.h"

#define OPTION_SACK_ADVERTISE   BIT(0)
#define OPTION_TS               BIT(1)
#define OPTION_MD5              BIT(2)
#define OPTION_WSCALE           BIT(3)
#define OPTION_FAST_OPEN_COOKIE BIT(8)
#define TCP_NIP_SND_NUM_MAX     (~0U)

/* Store the options contained in TCP when sending TCP packets */
struct tcp_nip_out_options {
	u16 options;        /* bit field of OPTION_* */
	u16 mss;            /* If it is zero, the MSS option is disabled */

	u8 ws;              /* window scale, 0 to disable */
	__u32 tsval, tsecr; /* need to include OPTION_TS */
};

static bool tcp_nip_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			       int push_one, gfp_t gfp);

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_nip_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;
	int nip_hdr_len = get_nip_hdr_len(NIP_HDR_COMM, &sk->SK_NIP_RCV_SADDR, &sk->SK_NIP_DADDR);

	/* Calculate base mss without TCP options: It is MMS_S - sizeof(tcphdr) of rfc1122 */
	nip_hdr_len = nip_hdr_len == 0 ? NIP_HDR_MAX : nip_hdr_len;
	mss_now = pmtu - nip_hdr_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	mss_now = max(mss_now, sock_net(sk)->ipv4.sysctl_tcp_min_snd_mss);
	return mss_now;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int tcp_nip_mtu_to_mss(struct sock *sk, int pmtu)
{
	/* Subtract TCP options size, not including SACKs */
	return __tcp_nip_mtu_to_mss(sk, pmtu) -
	       (tcp_sk(sk)->tcp_header_len - sizeof(struct tcphdr));
}

static inline void tcp_advance_send_head(struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_skb_is_last(sk, skb))
		sk->sk_send_head = NULL;
	else
		sk->sk_send_head = skb_queue_next(&sk->sk_write_queue, skb);
}

static void tcp_nip_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	tcp_advance_send_head(sk, skb);
	WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(skb)->end_seq);
	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets || icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)
		tcp_nip_rearm_rto(sk);

	tcp_nip_check_space(sk);
}

/* check probe0 timer */
static void tcp_nip_check_probe_timer(struct sock *sk)
{
	if (!tcp_sk(sk)->packets_out && !inet_csk(sk)->icsk_pending) {
		unsigned long when = tcp_probe0_base(sk);

		nip_dbg("start probe0 timer, when=%lu, RTO MAX=%u", when, TCP_RTO_MAX);
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0, when, TCP_RTO_MAX);
	} else if (inet_csk(sk)->icsk_pending != ICSK_TIME_PROBE0) {
		nip_dbg("can`t start probe0 timer, packets_out=%u, icsk_pending=%u",
			tcp_sk(sk)->packets_out, inet_csk(sk)->icsk_pending);
	}
}

void __tcp_nip_push_pending_frames(struct sock *sk, unsigned int cur_mss,
				   int nonagle)
{
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_nip_write_xmit(sk, cur_mss, nonagle, 0, sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_nip_check_probe_timer(sk);
}

u32 __nip_tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_nip_common *ntp = &tcp_nip_sk(sk)->common;
	int mss = tcp_nip_current_mss(sk); /* TCP_BASE_MSS */
	int allowed_space = tcp_full_space(sk);
	int full_space = min_t(int, tp->window_clamp, allowed_space); /* Total receive cache */
	int free_space = tcp_space(sk); /* 3/4 remaining receive cache */
	int window;

	if (unlikely(mss > full_space)) {
		mss = full_space;
		if (mss <= 0)
			return 0;
	}

	/* receive buffer is half full */
	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		free_space = round_down(free_space, 1 << tp->rx_opt.rcv_wscale);
		if (free_space < (allowed_space >> TCP_NUM_4) || free_space < mss) {
			nip_dbg("rcv_wnd is 0, [allowed|full|free]space=[%u, %u, %u], mss=%u",
				allowed_space, full_space, free_space, mss);
			return 0;
		}
	}

	if (get_nip_tcp_rcv_win_enable()) {
		if (get_ssthresh_enable())
			free_space = free_space > ntp->nip_ssthresh ?
				     ntp->nip_ssthresh : free_space;
		else
			free_space = free_space > tp->rcv_ssthresh ? tp->rcv_ssthresh : free_space;
	} else {
		free_space = free_space > get_ssthresh_high() ? get_ssthresh_high() : free_space;
	}

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 * tp->rx_opt.rcv_wscale is always true
	 */
	window = free_space;

	/* Advertise enough space so that it won't get scaled away.
	 * Import case: prevent zero window announcement if
	 * 1<<rcv_wscale > mss.
	 */
	window = ALIGN(window, (1 << tp->rx_opt.rcv_wscale));
	nip_dbg("wscale(%u) win change [%u to %u], [allowed|free]space=[%u, %u], mss=%u",
		tp->rx_opt.rcv_wscale, free_space, window, allowed_space, free_space, mss);
	return window;
}

/* The basic algorithm of window size selection:
 * 1. Calculate the remaining size of the receiving window cur_win.
 * 2. Calculate the new receive window size NEW_win, which is 3/4 of the remaining receive
 *    cache and cannot exceed RCV_SSTHresh.
 * 3. Select the receiving window size with the larger median value of cur_win and new_win.
 */
static u16 nip_tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 old_win = tp->rcv_wnd;
	/* The remaining size of the front receive window */
	u32 cur_win = tcp_receive_window(tp);
	/* Calculate the size of the new receive window based on the remaining receive cache */
	u32 new_win = __nip_tcp_select_window(sk);
	u32 new_win_bak;

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		if (new_win == 0)
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWANTZEROWINDOWADV);
		new_win_bak = new_win;
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
		nip_dbg("when new_win(%u) < cur_win(%u), win change [%u to %u]",
			new_win_bak, cur_win, new_win_bak, new_win);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale && sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 Scaling Applied.
	 * Scaling the receive window so that it can represent up to 30 bits
	 */
	new_win_bak = new_win;
	new_win >>= tp->rx_opt.rcv_wscale;
	nip_dbg("wscale(%u) win change [%u to %u]", tp->rx_opt.rcv_wscale, new_win_bak, new_win);
	if (new_win == 0) {
		tp->pred_flags = 0;
		if (old_win)
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTOZEROWINDOWADV);
	} else if (old_win == 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFROMZEROWINDOWADV);
	}

	return new_win;
}

/* Function
 *    Initialize transport layer parameters.
 * Parameter
 *    sk: transmission control block.
 */
static void tcp_nip_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale = 0;

	/* Header structure length + timestamp length */
	tp->tcp_header_len = sizeof(struct tcphdr);
	if (sock_net(sk)->ipv4.sysctl_tcp_timestamps)
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;

	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;

	tcp_mtup_init(sk);
	tp->rx_opt.mss_clamp = tcp_nip_sync_mss(sk, dst_mtu(dst));

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(sk);

	/* Initialization window */
	tcp_select_initial_window(sk, tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ?
				  tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  0,
				  &rcv_wscale,
				  0);

	tp->rx_opt.rcv_wscale = get_wscale_enable() ? get_wscale() : rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tp->snd_wl1 = 0;
	tcp_write_queue_purge(sk);

	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->snd_nxt = tp->write_seq;

	tp->rcv_nxt = 0;
	tp->rcv_wup = tp->rcv_nxt;
	tp->copied_seq = tp->rcv_nxt;
	inet_csk(sk)->icsk_rto = get_nip_rto() == 0 ? TCP_TIMEOUT_INIT : (HZ / get_nip_rto());
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

static void tcp_nip_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	tcp_skb_pcount_set(skb, 1);

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

#define OPTION_TS     BIT(1)
#define OPTION_WSCALE BIT(3)

static void tcp_nip_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	__skb_header_release(skb);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	WRITE_ONCE(tp->write_seq, tcb->end_seq);
	tp->packets_out += tcp_skb_pcount(skb);
}

static __u16 tcp_nip_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;
	u32 mtu;

	if (dst) {
		int nip_hdr_len;
		int nip_mss;
		unsigned int metric = dst_metric_advmss(dst);

		if (metric < (unsigned int)mss) {
			mss = metric;
			tp->advmss = mss;
		}

		mtu = dst_mtu(dst);
		nip_hdr_len = get_nip_hdr_len(NIP_HDR_COMM, &sk->SK_NIP_RCV_SADDR,
					      &sk->SK_NIP_DADDR);
		nip_hdr_len = nip_hdr_len == 0 ? NIP_HDR_MAX : nip_hdr_len;
		nip_mss = mtu - nip_hdr_len - sizeof(struct tcphdr);
		if (nip_mss > mss) {
			mss = nip_mss;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned int tcp_nip_syn_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_nip_out_options *opts)
{
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

	opts->mss = tcp_nip_advertise_mss(sk);
	nip_dbg("advertise mss %d", opts->mss);
	remaining -= TCPOLEN_MSS_ALIGNED;

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned int tcp_nip_established_options(struct sock *sk, struct sk_buff *skb,
						struct tcp_nip_out_options *opts)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int size = 0;

	opts->options = 0;

	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
	return size;
}

/* Function
 *    Put the parameters from the TCP option into SKB.
 *    Write previously computed TCP options to the packet.
 * Parameter
 *    ptr: pointer to TCP options in SKB.
 *    tp: transmission control block.
 *    opts: structure to be sent to temporarily load TCP options.
 */
static void tcp_nip_options_write(__be32 *ptr, struct tcp_sock *tp,
				  struct tcp_nip_out_options *opts)
{
	if (unlikely(opts->mss))
		*ptr++ = htonl((TCPOPT_MSS << TCP_OPT_MSS_PAYLOAD) |
			       (TCPOLEN_MSS << TCP_OLEN_MSS_PAYLOAD) |
			       opts->mss);
}

static inline void tcp_nip_event_ack_sent(struct sock *sk, unsigned int pkts,
					  u32 rcv_nxt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(rcv_nxt != tp->rcv_nxt))
		return;
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

unsigned short nip_get_output_checksum_tcp(struct sk_buff *skb, struct nip_addr src_addr,
					   struct nip_addr dst_addr)
{
	struct nip_pseudo_header nph = {0};
	u8 *tcp_hdr = skb_transport_header(skb);

	nph.nexthdr = IPPROTO_TCP;
	nph.saddr = src_addr;
	nph.daddr = dst_addr;

	nph.check_len = htons(skb->len);
	return nip_check_sum_build(tcp_hdr, skb->len, &nph);
}

static int __tcp_nip_transmit_skb(struct sock *sk, struct sk_buff *skb,
				  int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb;
	struct tcp_nip_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcphdr *th;
	int err = 0;
	__be16 len;
	unsigned short check = 0;
	bool ack;

	if (skb->tstamp == 0)
		skb->tstamp = tcp_jiffies32;

	if (clone_it) {
		TCP_SKB_CB(skb)->tx.in_flight = TCP_SKB_CB(skb)->end_seq
			- tp->snd_una;
		oskb = skb;

		tcp_skb_tsorted_save(oskb) {
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			else
				skb = skb_clone(oskb, gfp_mask);
		} tcp_skb_tsorted_restore(oskb);

		if (unlikely(!skb))
			return -ENOBUFS;
	}

	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	if (unlikely(tcb->tcp_flags & TCPHDR_SYN))
		tcp_options_size = tcp_nip_syn_options(sk, skb, &opts);
	else
		tcp_options_size = tcp_nip_established_options(sk, skb, &opts);
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1);
	/* The data pointer moves up */
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	/* Disassociate the control block */
	skb_orphan(skb);

	/* Establishes associations with control blocks */
	skb->sk = sk;
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;
	skb_set_hash_from_sk(skb, sk);
	/* Increase allocated memory */
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);

	/* Build TCP header and checksum it. */
	th          = (struct tcphdr *)skb->data;
	th->source  = inet->inet_sport;
	th->dest    = inet->inet_dport;
	th->seq     = htonl(tcb->seq);
	th->ack_seq = htonl(rcv_nxt);
	/* TCP's header offset is measured in 4 bytes, so moving two to the right
	 * means dividing by 4. In addition, according to the position of the offset
	 * field in the packet, the offset field is at the beginning of a short type,
	 * accounting for 4 bits. Therefore, the offset field should be shifted 12 bits
	 * to the left
	 */
	len = htons(((tcp_header_size >> TCP_NIP_4BYTE_PAYLOAD) << TCP_HDR_LEN_POS_PAYLOAD) |
		    tcb->tcp_flags);
	*(((__be16 *)th) + TCP_HDR_LEN_OFFSET) = len;

	th->check = 0;
	/* Newip Urg_ptr is disabled. Urg_ptr is used to carry the number of discarded packets */
	th->urg_ptr = htons(tp->snd_up);

	/* Write TCP option */
	tcp_nip_options_write((__be32 *)(th + 1), tp, &opts);

	/* Window Settings */
	if (likely(!(tcb->tcp_flags & TCPHDR_SYN)))
		th->window = htons(nip_tcp_select_window(sk));
	else
		th->window = htons(min(tp->rcv_wnd, TCP_NIP_WINDOW_MAX));

	ack = tcb->tcp_flags & TCPHDR_ACK;
	nip_dbg("sport=%u, dport=%u, win=%u, rcvbuf=%d, sk_rmem_alloc=%d, ack=%u, skb->len=%u",
		ntohs(inet->inet_sport), ntohs(inet->inet_dport), ntohs(th->window),
		sk->sk_rcvbuf, atomic_read(&sk->sk_rmem_alloc), ack, skb->len);

	/* Fill in checksum */
	check = nip_get_output_checksum_tcp(skb, sk->SK_NIP_RCV_SADDR, sk->SK_NIP_DADDR);
	th->check = htons(check);

	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		tcp_nip_event_ack_sent(sk, tcp_skb_pcount(skb), rcv_nxt);

	 /* There's data to send */
	if (skb->len != tcp_header_size)
		tp->data_segs_out += tcp_skb_pcount(skb);

	memset(skb->cb, 0, sizeof(struct ninet_skb_parm));
	err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);
	return err;
}

/* Function
 *    TCP's transport layer sends code that builds and initializes the TCP header
 *    Construct the SK_buff call transport layer to network layer interface
 * Parameter
 *    sk: Transmission control block.
 *    skb: Structure stores all information about network datagrams
 */
int tcp_nip_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			 gfp_t gfp_mask)
{
	return __tcp_nip_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}

static void tcp_nip_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	tcp_nip_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Function
 *    A function used by the client transport layer to connect requests.
 * Parameter
 *    sk: transmission control block.
 */
int __tcp_nip_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_nip_connect_init(sk);
	buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;

	/* Initializes the SYN flag bit */
	tcp_nip_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
	tcp_mstamp_refresh(tp);
	tp->retrans_stamp = tcp_time_stamp(tp);
	tcp_nip_init_xmit_timers(sk);

	tcp_nip_connect_queue_skb(sk, buff);

	/* Send off SYN */
	err =  tcp_nip_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;

	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, inet_csk(sk)->icsk_rto, TCP_RTO_MAX);

	return 0;
}

unsigned int tcp_nip_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	mss_now = tcp_nip_mtu_to_mss(sk, pmtu);
	nip_dbg("sync mtu_to_mss %d", mss_now);
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);
	nip_dbg("sync bound to half wnd %d", mss_now);

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_nip_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;

	nip_dbg("sync final mss %d", mss_now);

	return mss_now;
}

unsigned int tcp_nip_current_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned int header_len;
	struct tcp_nip_out_options opts;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);

		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_nip_sync_mss(sk, mtu);
	}

	header_len = tcp_nip_established_options(sk, NULL, &opts) + sizeof(struct tcphdr);
	if (header_len != tp->tcp_header_len) {
		int delta = (int)header_len - tp->tcp_header_len;

		mss_now -= delta;
	}

	return mss_now;
}

/* Function:
 *    Set up TCP options for SYN-ACKs.
 *    Initializes the TCP option for the SYN-ACK segment. Returns the SIZE of the TCP header.
 * Parameter
 *    req: Request connection control block.
 *    mss: maximum segment length.
 *    skb: Transfer control block buffer.
 *    opts: stores the options contained in TCP packets when they are sent.
 *    foc: Fast Open option.
 *    synack_type: type of SYN+ACK segment.
 */
static unsigned int tcp_nip_synack_options(struct request_sock *req,
					   unsigned int mss, struct sk_buff *skb,
					   struct tcp_nip_out_options *opts,
					   const struct tcp_md5sig_key *md5,
					   struct tcp_fastopen_cookie *foc,
					   enum tcp_synack_type synack_type)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb);
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	return MAX_TCP_OPTION_SPACE - remaining;
}

static int get_nip_mss(const struct sock *sk, struct dst_entry *dst, struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_sock *tp = tcp_sk(sk);
	u16 user_mss;
	int mss;
	int nip_hdr_len;
	int nip_mss;
	u32 mtu;

	mss = dst_metric_advmss(dst);
	user_mss = READ_ONCE(tp->rx_opt.user_mss);
	if (user_mss && user_mss < mss)
		mss = user_mss;

	mtu = dst_mtu(dst);
	nip_hdr_len = get_nip_hdr_len(NIP_HDR_COMM, &ireq->IR_NIP_LOC_ADDR, &ireq->IR_NIP_RMT_ADDR);
	nip_hdr_len = nip_hdr_len == 0 ? NIP_HDR_MAX : nip_hdr_len;
	nip_mss = mtu - nip_hdr_len - sizeof(struct tcphdr);

	if (nip_mss > mss) {
		mss = nip_mss;
		tp->advmss = mss;
	}

	return mss;
}

/* Function
 *    The SYN + ACK segment is constructed based on the current transport control block,
 *    routing information, and request information.
 * Parameter
 *    sk: transmission control block.
 *    dst: routing.
 *    req: Request connection control block.
 *    foc: Fast Open option.
 *    synack_type: type of SYN+ACK segment.
 */
struct sk_buff *tcp_nip_make_synack(const struct sock *sk, struct dst_entry *dst,
				    struct request_sock *req,
				    struct tcp_fastopen_cookie *foc,
				enum tcp_synack_type synack_type)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_md5sig_key *md5 = NULL;
	struct tcp_nip_out_options opts;
	struct sk_buff *skb;
	int tcp_header_size;
	struct tcphdr *th;
	int mss;
	unsigned short check = 0;

	skb = alloc_skb(MAX_TCP_HEADER, 0);
	if (unlikely(!skb)) {
		dst_release(dst);
		return NULL;
	}

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	switch (synack_type) {
	case TCP_SYNACK_NORMAL:
		/* Release the original SKB and treat itself as the SKB of the current SK */
		skb_set_owner_w(skb, req_to_sk(req));
		break;
	default:
		break;
	}
	skb_dst_set(skb, dst);
	/* set skb priority from sk */
	skb->priority = sk->sk_priority;

	mss = get_nip_mss(sk, dst, req);

	/* Clear the options and set the associated timestamp */
	memset(&opts, 0, sizeof(opts));
	skb->skb_mstamp_ns = tcp_clock_us();

	/* Get the TCP header size, then set the size and reset the transport layer header */
	skb_set_hash(skb, tcp_rsk(req)->txhash, PKT_HASH_TYPE_L4);
	tcp_header_size = tcp_nip_synack_options(req, mss, skb, &opts, md5,
						 foc, synack_type) + sizeof(*th);
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	/* Clear the TCP header and set the fields of the TCP header */
	th = (struct tcphdr *)skb->data;
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
	th->source = htons(ireq->ir_num);
	th->dest = ireq->ir_rmt_port;
	skb->ip_summed = CHECKSUM_PARTIAL;
	th->seq = htonl(tcp_rsk(req)->snt_isn);
	th->ack_seq = htonl(tcp_rsk(req)->rcv_nxt);
	th->check = 0;

	th->window = htons(min(req->rsk_rcv_wnd, 65535U));

	tcp_nip_options_write((__be32 *)(th + 1), NULL, &opts);
	/* TCP data offset, divided by 4 because doff is a 32-bit word
	 * That is, words four bytes long are counted in units
	 */
	th->doff = (tcp_header_size >> 2);
	__TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

	/* Fill in checksum */
	check = nip_get_output_checksum_tcp(skb,  ireq->IR_NIP_LOC_ADDR,  ireq->IR_NIP_RMT_ADDR);
	th->check = htons(check);

	/* Do not fool tcpdump (if any), clean our debris */
	skb->tstamp = 0;
	return skb;
}

/* Function
 *    Send SKB packets with SYN+ACK segments to the network layer.
 * Parameter
 *    req: Request connection control block.
 *    skb: Transfer control block buffer.
 */
int __nip_send_synack(struct request_sock *req, struct sk_buff *skb)
{
	struct inet_request_sock *ireq = inet_rsk(req); /* 连接请求块 */
	int err;
	int csummode = CHECKSUM_NONE;
	struct nip_addr *saddr, *daddr;
	struct nip_hdr_encap head = {0};
	unsigned char hdr_buf[NIP_HDR_MAX]; /* Cache the newIP header */

	skb->protocol = htons(ETH_P_NEWIP);
	skb->ip_summed = csummode;
	skb->csum = 0;
	saddr = &ireq->IR_NIP_LOC_ADDR;
	daddr = &ireq->IR_NIP_RMT_ADDR;

	head.saddr = *saddr;
	head.daddr = *daddr;
	head.ttl = NIP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_TCP;
	head.hdr_buf = hdr_buf;
	nip_hdr_comm_encap(&head);
	head.total_len = head.hdr_buf_pos + skb->len;
	nip_update_total_len(&head, htons(head.total_len));

	skb_push(skb, head.hdr_buf_pos);
	memcpy(skb->data, head.hdr_buf, head.hdr_buf_pos);
	skb_reset_network_header(skb);
	nipcb(skb)->srcaddr = *saddr;
	nipcb(skb)->dstaddr = *daddr;
	nipcb(skb)->nexthdr = head.nexthdr;

	head.total_len = skb->len;
	err = nip_send_skb(skb);
	if (err)
		nip_dbg("failed to send skb, skb->len=%u", head.total_len);
	else
		nip_dbg("send skb ok, skb->len=%u", head.total_len);

	return err;
}

int nip_send_synack(struct request_sock *req, struct sk_buff *skb)
{
	return __nip_send_synack(req, skb);
}

/* Function:
 *    Creates a subtransport block to complete the establishment of the three-way handshake
 * Parameter：
 *    parent: indicates the parent transmission control block
 *    child: indicates the child transmission control block
 *    skb: Transfer control block buffer
 */
int tcp_nip_child_process(struct sock *parent, struct sock *child,
			  struct sk_buff *skb)
{
	int ret = 0;
	int state = child->sk_state;
	/* Child is not occupied by the user process */
	if (!sock_owned_by_user(child)) {
		ret = tcp_nip_rcv_state_process(child, skb);
		/* At this point the state of the child has been migrated,
		 * waking up the process on the listening socket,
		 * which may be blocked due to Accept
		 */
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent);
	} else {
		__sk_add_backlog(child, skb);
	}
	bh_unlock_sock(child);
	sock_put(child);
	return ret;
}

static inline __u32 tcp_nip_acceptable_seq(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Function:
 *    The client sends an ACK
 * Parameter：
 *    sk: transmission control block
 *    rcv_nxt: serial number to be accepted
 */
void __tcp_nip_send_ack(struct sock *sk, u32 rcv_nxt)
{
	struct sk_buff *buff;

	if (sk->sk_state == TCP_CLOSE)
		return;

	buff = alloc_skb(MAX_TCP_HEADER,
			 sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));

	/* Reserve space for the header. */
	skb_reserve(buff, MAX_TCP_HEADER);
	/* Initialize SKB without data */
	tcp_nip_init_nondata_skb(buff, tcp_nip_acceptable_seq(sk), TCPHDR_ACK);

	/* Mark pure ack，skb->truesize set to 2 */
	skb_set_tcp_pure_ack(buff);

	/* Record the timestamp and send the SKB. */
	__tcp_nip_transmit_skb(sk, buff, 0, (__force gfp_t)0, rcv_nxt);
}

void tcp_nip_send_ack(struct sock *sk)
{
	__tcp_nip_send_ack(sk, tcp_sk(sk)->rcv_nxt);
}

void tcp_nip_send_fin(struct sock *sk)
{
	struct sk_buff *skb;
	struct sk_buff *tskb = tcp_write_queue_tail(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_mss;

	nip_dbg("send fin");
	/* Set the fin position of the last packet to 1 */
	if (tskb && tcp_nip_send_head(sk)) {
coalesce:
		TCP_SKB_CB(tskb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(tskb)->end_seq++;
		tp->write_seq++;
	} else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, sk->sk_allocation);
		if (unlikely(!skb)) {
			if (tskb)
				goto coalesce;
			return;
		}
		skb_reserve(skb, MAX_TCP_HEADER);

		tcp_nip_init_nondata_skb(skb, tp->write_seq,
					 TCPHDR_ACK | TCPHDR_FIN);
		tcp_nip_queue_skb(sk, skb);
	}

	cur_mss = tcp_nip_current_mss(sk); // TCP_BASE_MSS
	__tcp_nip_push_pending_frames(sk, cur_mss, TCP_NAGLE_OFF);
}

void tcp_nip_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	nip_dbg("send rst");
	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb)
		/* If you add log here, there will be an alarm:
		 * WARNING: Possible unnecessary 'out of memory' message
		 */
		return;

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_nip_init_nondata_skb(skb, tcp_nip_acceptable_seq(sk),
				 TCPHDR_ACK | TCPHDR_RST);
	/* Send it off. */
	tcp_nip_transmit_skb(sk, skb, 0, priority);
}

static bool tcp_nip_snd_wnd_test(const struct tcp_sock *tp,
				 const struct sk_buff *skb,
				 unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

static void tcp_nip_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	if (skb->len <= mss_now || skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		tcp_skb_pcount_set(skb, 1);
		TCP_SKB_CB(skb)->tcp_gso_size = 0;
	} else {
		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
		TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	}
}

static int tcp_nip_init_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_nip_set_skb_tso_segs(skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}

static bool tcp_nip_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			       int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_nip_common *ntp = &tcp_nip_sk(sk)->common;
	struct sk_buff *skb;
	u32 snd_num;
	u32 last_nip_ssthresh = ntp->nip_ssthresh;
	static const char * const str[] = {"can`t send pkt because no window",
					   "have window to send pkt"};

	if (!mss_now) {
		nip_dbg("invalid parameter, mss_now=%u", mss_now);
		return false;
	}
	snd_num = get_nip_tcp_snd_win_enable() ? (ntp->nip_ssthresh / mss_now) :
			  TCP_NIP_SND_NUM_MAX;

	tcp_nip_keepalive_enable(sk);
	ntp->idle_ka_probes_out = 0;

	tcp_mstamp_refresh(tp);

	if (tp->rcv_tstamp) {
		u32 tstamp = tcp_jiffies32 - tp->rcv_tstamp;

		if (tstamp >= get_ack_to_nxt_snd_tstamp()) {
			ntp->nip_ssthresh = get_ssthresh_low_min();
			snd_num = ntp->nip_ssthresh / mss_now;
			ssthresh_dbg("new snd tstamp %u >= %u, ssthresh %u to %u, snd_num=%u",
				     tstamp, get_ack_to_nxt_snd_tstamp(),
				     last_nip_ssthresh, ntp->nip_ssthresh, snd_num);
		}
	}

	while ((skb = tcp_nip_send_head(sk)) && (snd_num--)) {
		bool snd_wnd_ready;

		tcp_nip_init_tso_segs(skb, mss_now);
		snd_wnd_ready = tcp_nip_snd_wnd_test(tp, skb, mss_now);
		nip_dbg("%s, skb->len=%u", (snd_wnd_ready ? str[1] : str[0]), skb->len);
		if (unlikely(!snd_wnd_ready))
			break;

		if (unlikely(tcp_nip_transmit_skb(sk, skb, 1, gfp)))
			break;

		tcp_nip_event_new_data_sent(sk, skb);

		if (push_one)
			break;
	}
	return !tp->packets_out && tcp_nip_send_head(sk);
}

int tcp_nip_rtx_synack(const struct sock *sk, struct request_sock *req)
{
	const struct tcp_request_sock_ops *af_ops = tcp_rsk(req)->af_specific;
	int res;
	struct dst_entry *dst;

	dst = af_ops->route_req(sk, NULL, req);
	tcp_rsk(req)->txhash = net_tx_rndhash();

	res = af_ops->send_synack(sk, dst, NULL, req, NULL, TCP_SYNACK_NORMAL, NULL);

	return res;
}

static void tcp_nip_adjust_pcount(struct sock *sk, const struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;
}

int __tcp_nip_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cur_mss;
	int len, err;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (unlikely(before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))) {
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	cur_mss = tcp_nip_current_mss(sk);

	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	len = cur_mss * segs;
	if (skb->len > len) {
		if (tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE, skb, len, cur_mss, GFP_ATOMIC))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int diff = tcp_skb_pcount(skb);

		tcp_nip_set_skb_tso_segs(skb, cur_mss);
		diff -= tcp_skb_pcount(skb);
		if (diff)
			tcp_nip_adjust_pcount(sk, skb, diff);
	}

	err = tcp_nip_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	if (likely(!err)) {
		segs = tcp_skb_pcount(skb);

		tp->total_retrans += segs;
	}
	return err;
}

int tcp_nip_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err = __tcp_nip_retransmit_skb(sk, skb, segs);

	if (err == 0) {
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = tcp_skb_timestamp(skb);
	} else if (err != -EBUSY) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL);
	}

	return err;
}

#define TCP_NIP_DEFERRED_ALL ((1UL << TCP_TSQ_DEFERRED)  | \
			  (1UL << TCP_NIP_WRITE_TIMER_DEFERRED)      | \
			  (1UL << TCP_NIP_DELACK_TIMER_DEFERRED)     | \
			  (1UL << TCP_MTU_REDUCED_DEFERRED))

void tcp_nip_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & TCP_NIP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_NIP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	sock_release_ownership(sk);
	if (flags & (1UL << TCP_NIP_WRITE_TIMER_DEFERRED)) {
		tcp_nip_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << TCP_NIP_DELACK_TIMER_DEFERRED)) {
		tcp_nip_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << TCP_MTU_REDUCED_DEFERRED)) {
		inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
		__sock_put(sk);
	}
}

enum nip_probe_type {
	NIP_PROBE0 = 0,
	NIP_KEEPALIVE = 1,
	NIP_UNKNOWN = 2,
	NIP_PROBE_MAX,
};

static int tcp_nip_xmit_probe_skb(struct sock *sk, int urgent, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int ret;
	int probe_type;
	const char *str[NIP_PROBE_MAX] = {"probe0", "keepalive", "unknown"};

	if (mib == LINUX_MIB_TCPWINPROBE)
		probe_type = NIP_PROBE0;
	else if (mib == LINUX_MIB_TCPKEEPALIVE)
		probe_type = NIP_KEEPALIVE;
	else
		probe_type = NIP_UNKNOWN;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER,
			sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (!skb)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);

	tcp_nip_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);

	NET_INC_STATS(sock_net(sk), mib);
	ret = tcp_nip_transmit_skb(sk, skb, 0, (__force gfp_t)0);
	nip_dbg("send %s probe packet, ret=%d", str[probe_type], ret);
	return ret;
}

int tcp_nip_write_wakeup(struct sock *sk, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE) {
		nip_dbg("no probe0 when tcp close");
		return -1;
	}

	skb = tcp_nip_send_head(sk);
	/* If the serial number of the next packet is in the sending window */
	if (skb && before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_nip_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;
		/* If the current window size is not enough to send a complete packet */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq) {
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			err = tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
					   skb, seg_size, mss, GFP_ATOMIC);
			if (err) {
				nip_dbg("tcp_fragment return err=%d", err);
				return -1;
			}
		}
		err = tcp_nip_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_nip_event_new_data_sent(sk, skb);
		nip_dbg("transmit skb %s", (!err ? "ok" : "fail"));
		return err;
	} else {
		return tcp_nip_xmit_probe_skb(sk, 0, mib);
	}
}

/* The 0 window probe packet is sent */
void tcp_nip_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	unsigned long when;
	/* An ACK packet with snd_UNa-1 and length 0 is sent as a zero-window detection packet */
	int err = tcp_nip_write_wakeup(sk, LINUX_MIB_TCPWINPROBE);

	/* If there are packets to be sent on the network and no packets to be
	 * sent in the send queue, the packet is returned directly
	 */
	if (tp->packets_out || !tcp_nip_send_head(sk)) {
		/* Cancel probe timer, if it is not required. */
		nip_dbg("packets_out(%u) not 0 or send_head is NULL, cancel probe0 timer",
			tp->packets_out);
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	/* Err: 0 succeeded, -1 failed */
	icsk->icsk_probes_out++; /* Number of probes +1 */
	if (err <= 0) {
		if (icsk->icsk_backoff < READ_ONCE(net->ipv4.sysctl_tcp_retries2))
			icsk->icsk_backoff++;
		when = tcp_probe0_when(sk, TCP_RTO_MAX);
		nip_dbg("probe0 %s, probes_out=%u, probe0_base=%lu, icsk_backoff=%u, when=%lu",
			(!err ? "send ok" : "send fail"), icsk->icsk_probes_out,
			tcp_probe0_base(sk), icsk->icsk_backoff, when);
	} else {
		/* Makes the zero window probe timer time out faster */
		when = TCP_RESOURCE_PROBE_INTERVAL;
		nip_dbg("probe0 not sent due to local congestion, make timer out faster");
	}

	nip_dbg("restart probe0 timer, when=%lu, icsk_backoff=%u, probe_max=%u",
		when, icsk->icsk_backoff, TCP_RTO_MAX);
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0, when, TCP_RTO_MAX);
}
