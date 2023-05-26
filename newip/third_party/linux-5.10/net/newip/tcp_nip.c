// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv4/tcp.c
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
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	:	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 * Based on net/ipv4/tcp_ipv4.c
 *		See tcp.c for author information
 *
 * Changes:
 *		David S. Miller	:	New socket lookup architecture.
 *					This code is dedicated to John Dyson.
 *		David S. Miller :	Change semantics of established hash,
 *					half is devoted to TIME_WAIT sockets
 *					and the rest go in the other half.
 *		Andi Kleen :		Add support for syncookies and fixed
 *					some bugs: ip options weren't passed to
 *					the TCP layer, missed a check for an
 *					ACK bit.
 *		Andi Kleen :		Implemented fast path mtu discovery.
 *						Fixed many serious bugs in the
 *					request_sock handling and moved
 *					most of it into the af independent code.
 *					Added tail drop and some other bugfixes.
 *					Added new listen semantics.
 *		Mike McLagan	:	Routing by source
 *	Juan Jose Ciarlante:		ip_dynaddr bits
 *		Andi Kleen:		various fixes.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year
 *					coma.
 *	Andi Kleen		:	Fix new listen.
 *	Andi Kleen		:	Fix accept error reporting.
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *
 * Based on net/ipv6/tcp_ipv6.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Fixes:
 *	Hideaki YOSHIFUJI	:	sin6_scope_id support
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	YOSHIFUJI Hideaki @USAGI:	convert /proc/net/tcp6 to seq_file.
 *
 * Based on net/core/stream.c
 *     Authors:        Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *                     (from old tcp.c code)
 *                     Alan Cox <alan@lxorguk.ukuu.org.uk> (Borrowed comments 8-))
 *
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
 * Based on net/ipv4/tcp_input.c
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
 * Changes:
 *		Pedro Roque	:	Fast Retransmit/Recovery.
 *					Two receive queues.
 *					Retransmit queue handled by TCP.
 *					Better retransmit timer handling.
 *					New congestion avoidance.
 *					Header prediction.
 *					Variable renaming.
 *
 *		Eric		:	Fast Retransmit.
 *		Randy Scott	:	MSS option defines.
 *		Eric Schenk	:	Fixes to slow start algorithm.
 *		Eric Schenk	:	Yet another double ACK bug.
 *		Eric Schenk	:	Delayed ACK bug fixes.
 *		Eric Schenk	:	Floyd style fast retrans war avoidance.
 *		David S. Miller	:	Don't allow zero congestion window.
 *		Eric Schenk	:	Fix retransmitter so that it sends
 *					next packet on ack of previous packet.
 *		Andi Kleen	:	Moved open_request checking here
 *					and process RSTs for open_requests.
 *		Andi Kleen	:	Better prune_queue, and other fixes.
 *		Andrey Savochkin:	Fix RTT measurements in the presence of
 *					timestamps.
 *		Andrey Savochkin:	Check sequence numbers correctly when
 *					removing SACKs due to in sequence incoming
 *					data segments.
 *		Andi Kleen:		Make sure we never ack data there is not
 *					enough room for. Also make this condition
 *					a fatal error if it might still happen.
 *		Andi Kleen:		Add tcp_measure_rcv_mss to make
 *					connections with MSS<min(MTU,ann. MSS)
 *					work without delayed acks.
 *		Andi Kleen:		Process packets with PSH set in the
 *					fast path.
 *		J Hadi Salim:		ECN support
 *		Andrei Gurtov,
 *		Pasi Sarolahti,
 *		Panu Kuhlberg:		Experimental audit of TCP (re)transmission
 *					engine. Lots of bugs are found.
 *		Pasi Sarolahti:		F-RTO for dealing with spurious RTOs
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Implementation of the Transmission Control Protocol(TCP).
 *
 * TCP over NewIP
 *
 * Description of States:
 *
 *    TCP_SYN_SENT      sent a connection request, waiting for ack
 *
 *    TCP_SYN_RECV      received a connection request, sent ack,
 *                      waiting for final ack in three-way handshake.
 *
 *    TCP_ESTABLISHED   connection established
 *
 *    TCP_FIN_WAIT1     our side has shutdown, waiting to complete
 *                      transmission of remaining buffered data
 *
 *    TCP_FIN_WAIT2     all buffered data sent, waiting for remote
 *                      to shutdown
 *
 *    TCP_CLOSING       both sides have shutdown but we still have
 *                      data we have to finish sending
 *
 *    TCP_TIME_WAIT     timeout to catch resent junk before entering
 *                      closed, can only be entered from FIN_WAIT2
 *                      or CLOSING.  Required because the other end
 *                      may not have gotten our last ACK causing it
 *                      to retransmit the data packet (which we ignore)
 *
 *    TCP_CLOSE_WAIT    remote side has shutdown and is waiting for
 *                      us to finish writing our data and to shutdown
 *                      (we have to close() to move on to LAST_ACK)
 *
 *    TCP_LAST_ACK      out side has shutdown after remote has
 *                      shutdown.  There may still be data in our
 *                      buffer that we have to finish sending
 *
 *    TCP_CLOSE         socket is finished
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/times.h>
#include <linux/random.h>
#include <linux/seq_file.h>

#include <net/tcp.h>
#include <net/ninet_hashtables.h>
#include <net/ninet_connection_sock.h>
#include <net/protocol.h>
#include <net/dsfield.h>
#include <net/timewait_sock.h>
#include <net/inet_common.h>
#include <net/secure_seq.h>
#include <net/nip.h>
#include <net/tcp_nip.h>
#include <net/nip_addrconf.h>
#include <net/nip_route.h>
#include <linux/nip.h>
#include "nip_checksum.h"
#include "tcp_nip_parameter.h"

#define TCP_HEADER_LENGTH(th) ((th)->doff << 2)
#define TCP_ACK_NUM_MULTIPLIER      20
#define TCP_WINDOW_RAISE_THRESHOLD  2
#define TCP_BACKLOG_HEADROOM        (64 * 1024)
#define BYTES_PER_TCP_HEADER        4

static const struct inet_connection_sock_af_ops newip_specific;

static void tcp_nip_push(struct sock *sk, int flags, int mss_now,
			 int nonagle, int size_goal)
{
	__tcp_nip_push_pending_frames(sk, mss_now, nonagle);
}

static const unsigned char new_state[16] = {
  /* current state:        new state:      action: */
[0]	= TCP_CLOSE,
[TCP_ESTABLISHED]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
[TCP_SYN_SENT]	= TCP_CLOSE,
[TCP_SYN_RECV]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
[TCP_FIN_WAIT1]	= TCP_FIN_WAIT1,
[TCP_FIN_WAIT2]	= TCP_FIN_WAIT2,
[TCP_TIME_WAIT]	= TCP_CLOSE,
[TCP_CLOSE]		= TCP_CLOSE,
[TCP_CLOSE_WAIT]	= TCP_LAST_ACK  | TCP_ACTION_FIN,
[TCP_LAST_ACK]	= TCP_LAST_ACK,
[TCP_LISTEN]		= TCP_CLOSE,
[TCP_CLOSING]		= TCP_CLOSING,
[TCP_NEW_SYN_RECV]	= TCP_CLOSE, /* should not happen ! */
};

bool nip_get_tcp_input_checksum(struct sk_buff *skb)
{
	struct nip_pseudo_header nph = {0};

	nph.nexthdr = NIPCB(skb)->nexthdr;
	nph.saddr = NIPCB(skb)->srcaddr;
	nph.daddr = NIPCB(skb)->dstaddr;

	nph.check_len = htons(skb->len);
	return nip_check_sum_parse(skb_transport_header(skb),
				   skb->len, &nph)
				   == 0xffff ? true : false;
}

static int tcp_nip_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];
	int ns = next & TCP_STATE_MASK;

	tcp_set_state(sk, ns);

	return next & TCP_ACTION_FIN;
}

void sk_nip_stream_kill_queues(struct sock *sk)
{
	/* First the read buffer. */
	__skb_queue_purge(&sk->sk_receive_queue);

	/* Next, the error queue. */
	__skb_queue_purge(&sk->sk_error_queue);

	/* Next, the write queue. */
	WARN_ON(!skb_queue_empty(&sk->sk_write_queue));

	WARN_ON(sk->sk_wmem_queued);
}

void tcp_nip_shutdown(struct sock *sk, int how)
{
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
		if (tcp_nip_close_state(sk))
			tcp_nip_send_fin(sk);
	}
}

void tcp_nip_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;
	u32 sk_ack_backlog;

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	nip_dbg("sk_state:%d", sk->sk_state);

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		sk_ack_backlog = READ_ONCE(sk->sk_ack_backlog);
		inet_csk_listen_stop(sk);
		nip_dbg("sk_state CLOSE, sk_ack_backlog=%u to %u, sk_max_ack_backlog=%u",
			sk_ack_backlog, READ_ONCE(sk->sk_ack_backlog),
			READ_ONCE(sk->sk_max_ack_backlog));
		goto adjudge_to_death;
	}

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;

		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			len--;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (data_was_unread) {
		tcp_set_state(sk, TCP_CLOSE);
		tcp_nip_send_active_reset(sk, sk->sk_allocation);
	} else if (tcp_nip_close_state(sk)) {
		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 */
		nip_dbg("ready to send fin, sk_state=%d", sk->sk_state);
		tcp_nip_send_fin(sk);
	}

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);

	local_bh_disable();
	bh_lock_sock(sk);
	WARN_ON(sock_owned_by_user(sk));

	this_cpu_dec(*sk->sk_prot->orphan_count);

	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* These states need RST on ABORT according to RFC793 */
static inline bool tcp_nip_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
			TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

/* Function
 *    Initialize some of the parameters in request_sock
 * Parameter
 *    req: Request connection control block
 *    sk_listener: Transmission control block
 *    skb: Transfer control block buffer
 */
static void tcp_nip_init_req(struct request_sock *req,
			     const struct sock *sk_listener,
			     struct sk_buff *skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	ireq->ir_nip_rmt_addr = NIPCB(skb)->srcaddr;
	ireq->ir_nip_loc_addr = NIPCB(skb)->dstaddr;
}

/* Function
 *    Initialize The initialization number SEQ. Calculate the initial serial number of
 *    the server based on part of the source address source port, part of the destination
 *    address, and destination port
 * Parameter
 *    skb: Transfer control block buffer
 */
static __u32 tcp_nip_init_sequence(const struct sk_buff *skb)
{
	return secure_tcp_nip_sequence_number(NIPCB(skb)->dstaddr.nip_addr_field32,
					    NIPCB(skb)->srcaddr.nip_addr_field32,
					    tcp_hdr(skb)->dest,
					    tcp_hdr(skb)->source);
}

static struct dst_entry *tcp_nip_route_req(const struct sock *sk,
					   struct flowi *fl,
					   const struct request_sock *req)
{
	struct dst_entry *dst;
	struct inet_request_sock *ireq = inet_rsk(req);
	struct flow_nip fln;

	fln.daddr = ireq->ir_nip_rmt_addr;
	dst = nip_route_output(sock_net(sk), sk, &fln);
	return dst;
}

/* Function
 *    Functions used by the client transport layer to connect requests
 *    This parameter is used to set the source address, destination address and interface
 * Parameter
 *    sk: Transmission control block
 *    uaddr：The destination address
 *    addr_len：Destination address Length
 */
static int tcp_nip_connect(struct sock *sk, struct sockaddr *uaddr,
			   int addr_len)
{
	struct sockaddr_nin *usin = (struct sockaddr_nin *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__be16 orig_dport;
	struct nip_addr *daddr;
	struct dst_entry *dst;
	int err;
	struct ip_options_rcu *inet_opt;
	struct inet_timewait_death_row *tcp_death_row;
	struct flow_nip fln;

	fln.daddr = usin->sin_addr;

	if (addr_len < sizeof(struct sockaddr_nin))
		return -EINVAL;

	if (usin->sin_family != AF_NINET)
		return -EAFNOSUPPORT;

	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     lockdep_sock_is_held(sk));
	/* Destination ADDRESS and port */
	daddr = &usin->sin_addr;
	orig_dport = usin->sin_port;

	/* Find the route and obtain the source address */
	nip_dbg("sk->sk_bound_dev_if is %d", sk->sk_bound_dev_if);
	fln.flowin_oif = sk->sk_bound_dev_if;
	dst = nip_dst_lookup_flow(sock_net(sk), sk, &fln, NULL);
	if (IS_ERR(dst)) {
		nip_dbg("cannot find dst");
		err = PTR_ERR(dst);
		goto failure;
	}

	/* find the actual source addr for sk->sk_nip_rcv_saddr */
	if (nip_addr_eq(&sk->sk_nip_rcv_saddr, &nip_any_addr))
		sk->sk_nip_rcv_saddr = fln.saddr;
	fln.saddr = sk->sk_nip_rcv_saddr;

	if (nip_addr_invalid(&fln.daddr)) {
		nip_dbg("nip daddr invalid, bitlen=%u", fln.daddr.bitlen);
		err = -EFAULT;
		goto failure;
	}

	if (nip_addr_invalid(&fln.saddr)) {
		nip_dbg("nip saddr invalid, bitlen=%u", fln.saddr.bitlen);
		err = -EFAULT;
		goto failure;
	}

	/* The destination address and port are set to the transport control block */
	inet->inet_dport = usin->sin_port;
	sk->sk_nip_daddr = usin->sin_addr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet_opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	tcp_set_state(sk, TCP_SYN_SENT);
	sk_set_txhash(sk);
	sk_dst_set(sk, dst);

	/* Dynamically bind local ports */
	tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;
	err = ninet_hash_connect(tcp_death_row, sk);
	if (err)
		goto late_failure;

	/* Class if the transport control block has already been linked */
	if (tp->rx_opt.ts_recent_stamp) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		if (likely(!tp->repair))
			tp->write_seq	   = 0;
	}

	if (!tp->write_seq)
		tp->write_seq =
		secure_tcp_nip_sequence_number(sk->sk_nip_rcv_saddr.nip_addr_field32,
					       sk->sk_nip_daddr.nip_addr_field32,
					       inet->inet_sport,
					       usin->sin_port);

	inet->inet_id = prandom_u32();

	/* Call tcp_connect to send the SYN field */
	err = __tcp_nip_connect(sk);
	if (err)
		goto late_failure;

	return 0;

/* failure after tcp_set_state(sk, TCP_SYN_SENT) */
late_failure:
	tcp_set_state(sk, TCP_CLOSE);
failure:
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}

static void tcp_nip_send_reset(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = tcp_hdr(skb);
	u32 seq = 0;
	u32 ack_seq = 0;
	u32 priority = gfp_any();

	/* Never send a reset in response to a reset. */
	if (th->rst)
		return;

	nip_dbg("send rst");
	if (th->ack)
		seq = ntohl(th->ack_seq);
	else
		ack_seq = ntohl(th->seq) + th->syn + th->fin + skb->len -
			  TCP_HEADER_LENGTH(th);

	tcp_nip_actual_send_reset(sk, skb, seq, ack_seq, 0, 1, priority);
}

/* Function
 *    function used by the server to send SYN+ACK segments
 * Parameter
 *    sk: Transmission control block
 *    dst: routing。
 *    flowi: Flow control block
 *    req: Request connection control block
 *    foc: Fast open options
 *    synack_type: Type of the SYN+ACK segment
 */
static int tcp_nip_send_synack(const struct sock *sk, struct dst_entry *dst,
			       struct flowi *fl,
			       struct request_sock *req,
			       struct tcp_fastopen_cookie *foc,
			       enum tcp_synack_type synack_type,
			       struct sk_buff *syn_skb)
{
	struct sk_buff *skb;
	int err = -ENOMEM;

	skb = tcp_nip_make_synack(sk, dst, req, foc, synack_type);
	if (skb) {
		nip_dbg("TCP server create SYN+ACK skb successfully");
		rcu_read_lock();
		err = nip_send_synack(req, skb);
		rcu_read_unlock();
	}

	return err;
}

static void tcp_nip_reqsk_destructor(struct request_sock *req)
{
	;
}

struct request_sock_ops tcp_nip_request_sock_ops __read_mostly = {
	.family		=	AF_NINET,
	.obj_size	=	sizeof(struct tcp_nip_request_sock),
	.rtx_syn_ack	=	tcp_nip_rtx_synack,
	.send_ack	=	NULL,
	.destructor	=	tcp_nip_reqsk_destructor,
	.send_reset	=	NULL,
	.syn_ack_timeout =	NULL,
};

static const struct tcp_request_sock_ops tcp_request_sock_newip_ops = {
	.mss_clamp	=	TCP_BASE_MSS,
#ifdef CONFIG_TCP_MD5SIG
	.req_md5_lookup	=	NULL,
	.calc_md5_hash	=	NULL,
#endif
	.init_req	=	tcp_nip_init_req,
#ifdef CONFIG_SYN_COOKIES
	.cookie_init_seq =	NULL,
#endif
	.route_req	=	tcp_nip_route_req,
	.init_seq	=	tcp_nip_init_sequence,
	.send_synack	=	tcp_nip_send_synack,
};

/* Function
 *    The route cache saves the transport control block from the SKB
 * Parameter
 *    sk: Transmission control block
 *    skb: Transfer control block buffer
 *    req: Request connection control block
 *    dst: routing
 *    req_unhash: Request connection control block
 */
void ninet_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	if (dst && dst_hold_safe(dst)) {
		sk->sk_rx_dst = dst;
		inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
	}
}

/* Function
 *    A function used by the server to process client connection requests
 * Parameter
 *    sk: Transmission control block
 *    skb: Transfer control block buffer
 */
static int tcp_nip_conn_request(struct sock *sk, struct sk_buff *skb)
{
	return _tcp_nip_conn_request(&tcp_nip_request_sock_ops,
				     &tcp_request_sock_newip_ops, sk, skb);
}

/* Function
 *    Create child control blocks
 * Parameter
 *    sk: Transmission control block
 *    skb: Transfer control block buffer
 *    req: Request connection control block
 *    dst: routing
 *    req_unhash: Request connection control block
 */
static struct sock *tcp_nip_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req)
{
	struct tcp_nip_request_sock *niptreq = tcp_nip_rsk(req);
	struct inet_request_sock *ireq = inet_rsk(req);
	bool found_dup_sk = false;
	struct tcp_nip_sock *newtcpnipsk;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
	struct flow_nip fln;

	if (sk_acceptq_is_full(sk))
		goto out_overflow;

	fln.daddr = ireq->ir_nip_rmt_addr;
	if (!dst) {
		dst = nip_route_output(sock_net(sk), sk, &fln);
		if (!dst)
			goto out;
	}

	newsk = tcp_nip_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto out_nonewsk;

	/* Save the received route cache */
	ninet_sk_rx_dst_set(newsk, skb);

	newtcpnipsk = (struct tcp_nip_sock *)newsk;
	newtcpnipsk->common = niptreq->common;

	newtp = tcp_sk(newsk);
	newinet = inet_sk(newsk);

	newsk->sk_nip_daddr = ireq->ir_nip_rmt_addr;
	newsk->sk_nip_rcv_saddr = ireq->ir_nip_loc_addr;

	newinet->inet_opt = NULL;

	inet_csk(newsk)->icsk_ext_hdr_len = 0;

	newtp->retrans_stamp = jiffies;

	/* Negotiate MSS */
	newtp->mss_cache = TCP_BASE_MSS;
	newtp->out_of_order_queue = RB_ROOT;
	newtp->advmss = dst_metric_advmss(dst);
	if (tcp_sk(sk)->rx_opt.user_mss &&
	    tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = tcp_sk(sk)->rx_opt.user_mss;

	tcp_nip_initialize_rcv_mss(newsk);
	if (__inet_inherit_port(sk, newsk) < 0)
		goto put_and_exit;
	/* Deleting the old sock from the ehash table and adding the new sock to the
	 * ehash table succeeds *own_req equals true
	 */
	*own_req = inet_ehash_nolisten(newsk, req_to_sk(req_unhash),
				       &found_dup_sk);

	/* newip newsk doesn't save this dst. release it. */
	dst_release(dst);
	return newsk;

out_overflow:
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out_nonewsk:
out:
	/* newip newsk doesn't save this dst. release it. */
	dst_release(dst);
	tcp_listendrop(sk);
	return NULL;
put_and_exit:
	newinet->inet_opt = NULL;
	inet_csk_prepare_forced_close(newsk);
	tcp_nip_done(newsk);
	goto out;
}

static const struct inet_connection_sock_af_ops newip_specific = {
	.queue_xmit	   = tcp_nip_queue_xmit,
	.send_check	   = NULL,
	.rebuild_header	   = NULL,
	.sk_rx_dst_set	   = ninet_sk_rx_dst_set,
	.conn_request	   = tcp_nip_conn_request,
	.syn_recv_sock	   = tcp_nip_syn_recv_sock,
	.net_header_len	   = 0,
	.net_frag_header_len = 0,
	.setsockopt	   = nip_setsockopt,
	.getsockopt	   = nip_getsockopt,
	.addr2sockaddr	   = NULL,
	.sockaddr_len	   = sizeof(struct sockaddr_nin),

	.mtu_reduced	   = NULL,
};

#if IS_ENABLED(CONFIG_NEWIP_FAST_KEEPALIVE)
#define MAX_NIP_TCP_KEEPIDLE	32767
#define MAX_NIP_TCP_KEEPINTVL	32767
#define MAX_NIP_TCP_KEEPCNT	255
static int tcp_nip_keepalive_para_update(struct sock *sk,
					 u32 keepalive_time,
					 u32 keepalive_intvl,
					 u8 keepalive_probes)
{
	int val;
	struct tcp_sock *tp = tcp_sk(sk);

	/* set keep idle (TCP_KEEPIDLE) */
	val = keepalive_time;
	if (val < 1 || val > MAX_NIP_TCP_KEEPIDLE) {
		nip_dbg("keepalive_time(%u) invalid", val);
		return -EINVAL;
	}

	tp->keepalive_time = val;
	if (sock_flag(sk, SOCK_KEEPOPEN) &&
	    !((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		u32 elapsed = keepalive_time_elapsed(tp);

		if (tp->keepalive_time > elapsed)
			elapsed = tp->keepalive_time - elapsed;
		else
			elapsed = 0;
		inet_csk_reset_keepalive_timer(sk, elapsed);
	}

	/* set keep intvl (TCP_KEEPINTVL) */
	val = keepalive_intvl;
	if (val < 1 || val > MAX_NIP_TCP_KEEPINTVL) {
		nip_dbg("keepalive_intvl(%u) invalid", val);
		return -EINVAL;
	}
	tp->keepalive_intvl = val;

	/* set keep cnt (TCP_KEEPCNT) */
	val = keepalive_probes;
	if (val < 1 || val > MAX_NIP_TCP_KEEPCNT) {
		nip_dbg("keepalive_probes(%u) invalid", val);
		return -EINVAL;
	}
	tp->keepalive_probes = val;

	/* enable keepalive (SO_KEEPALIVE) */
	if (sk->sk_prot->keepalive) {
		sk->sk_prot->keepalive(sk, 1);
		sock_valbool_flag(sk, SOCK_KEEPOPEN, 1);
	} else {
		nip_dbg("keepalive func is null");
	}

	return 0;
}
#endif

#define NIP_PKT_TOTAL_LEN_BOUNDARY 100000  // 100K
#define NIP_KEEPALIVE_PROBES 255
void tcp_nip_keepalive_enable(struct sock *sk)
{
#if IS_ENABLED(CONFIG_NEWIP_FAST_KEEPALIVE)
	int ret;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_nip_common *ntp = &tcp_nip_sk(sk)->common;
	struct sk_buff *skb = tcp_nip_send_head(sk);

	if (!skb)
		return;

	if (ntp->nip_keepalive_enable) {
		/* If keepalive set by setsockopt, backup para and change para to nip para */
		if (tp->keepalive_time > HZ) {
			ntp->keepalive_time_bak = tp->keepalive_time;
			ntp->keepalive_probes_bak = tp->keepalive_probes;
			ntp->keepalive_intvl_bak = tp->keepalive_intvl;

			nip_dbg("HZ=%u, change time/probes/intvl [%u, %u, %u] to [%u, %u, %u]",
				HZ, tp->keepalive_time, tp->keepalive_probes,
				tp->keepalive_intvl, get_nip_keepalive_time(),
				NIP_KEEPALIVE_PROBES, get_nip_keepalive_intvl());

			tp->keepalive_time = get_nip_keepalive_time();
			tp->keepalive_probes = NIP_KEEPALIVE_PROBES;
			tp->keepalive_intvl = get_nip_keepalive_intvl();
			inet_csk_reset_keepalive_timer(sk, tp->keepalive_time);
		}
		return;
	}

	/* If keepalive set by setsockopt, backup para */
	if (sock_flag(sk, SOCK_KEEPOPEN)) {
		ntp->keepalive_time_bak = tp->keepalive_time;
		ntp->keepalive_probes_bak = tp->keepalive_probes;
		ntp->keepalive_intvl_bak = tp->keepalive_intvl;
		nip_dbg("HZ=%u, backup normal time/probes/intvl [%u, %u, %u]",
			HZ, tp->keepalive_time, tp->keepalive_probes, tp->keepalive_intvl);
	}

	/* change para to nip para */
	ret = tcp_nip_keepalive_para_update(sk, get_nip_keepalive_time(),
					    get_nip_keepalive_intvl(),
					    NIP_KEEPALIVE_PROBES);
	if (ret != 0) {
		nip_dbg("fail, HZ=%u, time/probes/intvl [%u, %u, %u]",
			HZ, tp->keepalive_time, tp->keepalive_probes, tp->keepalive_intvl);
		return;
	}

	nip_dbg("ok, HZ=%u, time/probes/intvl [%u, %u, %u]",
		HZ, tp->keepalive_time, tp->keepalive_probes, tp->keepalive_intvl);
	ntp->nip_keepalive_enable = true;
#endif
}

void tcp_nip_keepalive_disable(struct sock *sk)
{
#if IS_ENABLED(CONFIG_NEWIP_FAST_KEEPALIVE)
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_nip_common *ntp = &tcp_nip_sk(sk)->common;

	if (!ntp->nip_keepalive_enable)
		return;

	if (!sock_flag(sk, SOCK_KEEPOPEN)) {
		ntp->nip_keepalive_enable = false;
		nip_dbg("ok, HZ=%u, normal ka has disable", HZ);
		return;
	}

	if (ntp->idle_ka_probes_out < get_nip_idle_ka_probes_out())
		return;

	/* newip keepalive change to normal keepalive */
	if (ntp->keepalive_time_bak) {
		nip_dbg("HZ=%u, change normal time/probes/intvl [%u, %u, %u] to [%u, %u, %u]",
			HZ, tp->keepalive_time, tp->keepalive_probes,
			tp->keepalive_intvl, ntp->keepalive_time_bak, ntp->keepalive_probes_bak,
			ntp->keepalive_intvl_bak);
		tp->keepalive_time = ntp->keepalive_time_bak;
		tp->keepalive_probes = ntp->keepalive_probes_bak;
		tp->keepalive_intvl = ntp->keepalive_intvl_bak;
		inet_csk_reset_keepalive_timer(sk, tp->keepalive_time);
		return;
	}

	ntp->keepalive_time_bak = 0;
	ntp->keepalive_probes_bak = 0;
	ntp->keepalive_intvl_bak = 0;

	/* enable keepalive (SO_KEEPALIVE) */
	if (sk->sk_prot->keepalive)
		sk->sk_prot->keepalive(sk, 0);
	sock_valbool_flag(sk, SOCK_KEEPOPEN, 0);

	nip_dbg("ok, HZ=%u, idle_ka_probes_out=%u", HZ, get_nip_idle_ka_probes_out());
	ntp->nip_keepalive_enable = false;
#endif
}

static void _tcp_sock_priv_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_nip_common *ntp = &tcp_nip_sk(sk)->common;

	memset(ntp, 0, sizeof(*ntp));
	ntp->nip_ssthresh = get_nip_ssthresh_default();
	tp->sacked_out = 0;
	tp->rcv_tstamp = 0;
	tp->selective_acks[0].start_seq = 0;
	tp->selective_acks[0].end_seq = 0;
	tp->keepalive_time = 0;
	tp->keepalive_probes = 0;
	tp->keepalive_intvl = 0;
}

static void tcp_sock_priv_init(struct sock *sk)
{
	_tcp_sock_priv_init(sk);
}

/* Function
 *    Example Initialize sock information in TCP
 * Parameter
 *    sk: Sock to be initialized
 * Note: Currently, this function does not initialize timer, pre-queue, and congestion control,
 * and does not allow fast retransmission. No function is set to adjust MSS
 */
static int tcp_nip_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_sock_priv_init(sk);

	tp->out_of_order_queue = RB_ROOT;
	tcp_nip_init_xmit_timers(sk);
	INIT_LIST_HEAD(&tp->tsq_node);

	icsk->icsk_rto = get_nip_rto() == 0 ? TCP_TIMEOUT_INIT : (HZ / get_nip_rto());
	icsk->icsk_rto_min = TCP_RTO_MIN;
	icsk->icsk_delack_max = TCP_DELACK_MAX;
	tp->mdev_us = jiffies_to_usecs(TCP_TIMEOUT_INIT);
	minmax_reset(&tp->rtt_min, tcp_jiffies32, ~0U);

	tp->snd_cwnd = TCP_INIT_CWND;
	tp->app_limited = ~0U;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	tp->reordering = sock_net(sk)->ipv4.sysctl_tcp_reordering;
	tp->tsoffset = 0;
	sk->sk_state = TCP_CLOSE;
	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_sync_mss = tcp_nip_sync_mss;

	WRITE_ONCE(sk->sk_sndbuf, get_nip_sndbuf()); // sock_net(sk)->ipv4.sysctl_tcp_wmem[1]
	WRITE_ONCE(sk->sk_rcvbuf, get_nip_rcvbuf()); // sock_net(sk)->ipv4.sysctl_tcp_rmem[1]

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	local_bh_enable();

	icsk->icsk_af_ops = &newip_specific;

	return 0;
}

static void skb_nip_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tp->write_seq;
	tcb->end_seq = tp->write_seq;
	tcb->tcp_flags = TCPHDR_ACK;
	tcb->sacked  = 0;

	tcp_nip_add_write_queue_tail(sk, skb);

	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

static unsigned int tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
				       int large_allowed)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 new_size_goal, size_goal;

	if (!large_allowed || !mss_now)
		return mss_now;

	/* Note : tcp_tso_autosize() will eventually split this later */
	new_size_goal = sk->sk_gso_max_size - 1 - MAX_TCP_HEADER;
	new_size_goal = tcp_bound_to_half_wnd(tp, new_size_goal);

	/* We try hard to avoid divides here */
	size_goal = tp->gso_segs * mss_now;
	if (unlikely(new_size_goal < size_goal ||
		     new_size_goal >= size_goal + mss_now)) {
		tp->gso_segs = min_t(u16, new_size_goal / mss_now,
				     sk->sk_gso_max_segs);
		size_goal = tp->gso_segs * mss_now;
	}

	return max(size_goal, mss_now);
}

int tcp_nip_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	mss_now = tcp_nip_current_mss(sk);
	*size_goal = tcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));
	return mss_now;
}

int tcp_nip_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int flags;
	int err;
	int copied = 0;
	int mss_now = 0;
	int size_goal;
	bool process_backlog = false;
	long timeo;

	lock_sock(sk);

	flags = msg->msg_flags;

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	copied = 0;

restart:
	mss_now = tcp_nip_send_mss(sk, &size_goal, flags);

	nip_dbg("mss_now=%d", mss_now);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (msg_data_left(msg)) {
		int copy = 0;
		int max = mss_now;

		bool first_skb;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;

		if (process_backlog && sk_flush_backlog(sk)) {
			process_backlog = false;
			goto restart;
		}
		first_skb = skb_queue_empty(&sk->sk_write_queue);
		skb = sk_stream_alloc_skb(sk, mss_now, sk->sk_allocation, first_skb);
		if (!skb)
			goto wait_for_memory;

		skb->tstamp = 0;
		process_backlog = true;

		skb_nip_entail(sk, skb);
		copy = mss_now;
		max = mss_now;

		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);

		if (skb_availroom(skb) > 0) {
			/* We have some space in skb head. Superb! */
			copy = min_t(int, copy, skb_availroom(skb));
			err = skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
			if (err)
				goto do_fault;
		} else {
			nip_dbg("msg too big, tcp cannot devide packet now");
			goto out;
		}

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		tcp_skb_pcount_set(skb, 0);
		copied += copy;
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		}

		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_nip_push(sk, flags & ~MSG_MORE, mss_now,
				     TCP_NAGLE_PUSH, size_goal);

		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		mss_now = tcp_nip_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied)
		tcp_nip_push(sk, flags, mss_now, tp->nonagle, size_goal);
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		tcp_unlink_write_queue(skb, sk);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;

	err = sk_stream_error(sk, flags, err);
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && err == -EAGAIN))
		sk->sk_write_space(sk);
	release_sock(sk);
	return err;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void tcp_nip_cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool time_to_ack = false;

	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	WARN(skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq),
	     "cleanup rbuf bug: copied %X seq %X rcvnxt %X",
	     tp->copied_seq, TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);

	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);

		if (tp->rcv_nxt - tp->rcv_wup > (get_ack_num() *
			TCP_ACK_NUM_MULTIPLIER * icsk->icsk_ack.rcv_mss) ||
		    /* If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !inet_csk_in_pingpong_mode(sk))) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = true;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp);

		/* Optimize, __nip_tcp_select_window() is not cheap. */
		if (TCP_WINDOW_RAISE_THRESHOLD * rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __nip_tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= TCP_WINDOW_RAISE_THRESHOLD * rcv_window_now)
				time_to_ack = true;
		}
	}
	if (time_to_ack)
		tcp_nip_send_ack(sk);
}

int tcp_nip_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		    int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 *seq;
	unsigned long used;
	int err = 0;
	int target;
	long timeo;
	size_t len_tmp = len;
	struct sk_buff *skb, *last;

	lock_sock(sk);

	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	seq = &tp->copied_seq;

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len_tmp);

	do {
		u32 offset;
		/* Next get a buffer. */
		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			last = skb;
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, TCP_SKB_CB(skb)->seq),
				 "TCP recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X",
				 *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt,
				 flags))
				break;
			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
				pr_err_once("found a SYN, please report");
				offset--;
			}
			if (offset < skb->len)
				goto found_ok_skb;
			if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
				goto found_fin_ok;
			/* If the first SKB in the current SK_receive_queue is not the SKB to
			 * be replicated, then MSG_PEEK should be set in flags
			 */
			WARN(!(flags & MSG_PEEK),
			     "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X",
			     *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt, flags);
		}

		/* If the program is executed at this point, the SK_receive_queue is finished */
		/* If there is no data in the backlog, stop reading at target */
		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		tcp_nip_cleanup_rbuf(sk, copied);

		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else {
			nip_dbg("no enough data receive queue, wait");
			sk_wait_data(sk, &timeo, last);
		}
		continue;
found_ok_skb:
		used = skb->len - offset;
		if (len_tmp < used)
			used = len_tmp;
		nip_dbg("copy data into msg, len=%ld", used);
		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			if (err) {
				nip_dbg("copy data failed");
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}
		*seq += used;
		len_tmp -= used;
		copied += used;

		if (used + offset < skb->len)
			continue;

		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			goto found_fin_ok;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb);
		continue;

found_fin_ok:
		/* Process the FIN. */
		++*seq;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb);
		break;
	} while (len_tmp > 0);

	/* Clean up data we have read: This will do ACK frames. */
	tcp_nip_cleanup_rbuf(sk, copied);

	release_sock(sk);
	return copied;

out:
	release_sock(sk);
	return err;
}

static void skb_nip_rbtree_purge(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	skb_rbtree_purge(&tp->out_of_order_queue);
}

void tcp_nip_destroy_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_nip_clear_xmit_timers(sk);

	tcp_nip_write_queue_purge(sk);

	skb_nip_rbtree_purge(sk);

	if (inet_csk(sk)->icsk_bind_hash)
		inet_put_port(sk);

	tcp_saved_syn_free(tp);
	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	local_bh_enable();
}

/* Function
 *    The sock handler for THE LISTEN and ESTABLISHED states is called by tcp_nip_rCV
 * Parameter
 *    skb: Packets received from the network layer
 *    sk: A SOCK instance needs to be processed
 */
static int tcp_nip_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	nip_dbg("received newip tcp skb, sk_state=%d", sk->sk_state);

	if (sk->sk_state == TCP_ESTABLISHED) {
		struct dst_entry *dst = sk->sk_rx_dst;

		if (dst) {
			/* Triggered when processing newly received skb after deleting routes */
			if (inet_sk(sk)->rx_dst_ifindex != skb->skb_iif ||
			    !dst->ops->check(dst, 0)) {
				dst_release(dst);
				sk->sk_rx_dst = NULL;
			}
		}
		tcp_nip_rcv_established(sk, skb, tcp_hdr(skb), skb->len);
		return 0;
	}

	/* The connection is established in cookie mode to defend against SYN-flood attacks */
	if (sk->sk_state == TCP_LISTEN)
		nip_dbg("found TCP_LISTEN SOCK");

	if (tcp_nip_rcv_state_process(sk, skb))
		goto discard;
	return 0;

discard:
	kfree_skb(skb);
	return 0;
}

/* Function:
 *    Fill the TCP header field in SKB into the TCP private control block,
 *    because the TCP header field in SKB is the network byte order,
 *    in order to facilitate later call, need to convert the host byte order
 *    and store in the TCP control block.
 * Parameter：
 *    skb：Packets delivered by the network layer
 *    th：TCP header field in a packet
 */
static void tcp_nip_fill_cb(struct sk_buff *skb, const struct tcphdr *th)
{
	barrier();

	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * TCP_NUM_4);

	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->tcp_flags = tcp_flag_byte(th);
	TCP_SKB_CB(skb)->tcp_tw_isn = 0;
	TCP_SKB_CB(skb)->sacked = 0;
}

static bool tcp_nip_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	u32 limit = READ_ONCE(sk->sk_rcvbuf) + READ_ONCE(sk->sk_sndbuf);

	/* Only socket owner can try to collapse/prune rx queues
	 * to reduce memory overhead, so add a little headroom here.
	 * Few sockets backlog are possibly concurrently non empty.
	 */
	limit += TCP_BACKLOG_HEADROOM;

	/* In case all data was pulled from skb frags (in __pskb_pull_tail()),
	 * we can fix skb->truesize to its real value to avoid future drops.
	 * This is valid because skb is not yet charged to the socket.
	 * It has been noticed pure SACK packets were sometimes dropped
	 * (if cooked by drivers without copybreak feature).
	 */
	skb_condense(skb);

	if (unlikely(sk_add_backlog(sk, skb, limit))) {
		bh_unlock_sock(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
		nip_dbg("insert backlog fail");
		return true;
	}
	return false;
}

/* Function
 *    TCP is the gateway from the network layer to the transport layer
 *    and receives data packets from the network layer
 * Parameter
 *    skb：Packets delivered by the network layer
 */
static int tcp_nip_rcv(struct sk_buff *skb)
{
	const struct tcphdr *th;
	bool refcounted;
	struct sock *sk;
	int ret;
	int dif = skb->skb_iif;

	if (skb->pkt_type != PACKET_HOST) {
		nip_dbg("unknown pkt-type(%u), drop skb", skb->pkt_type);
		goto discard_it;
	}

	if (!nip_get_tcp_input_checksum(skb)) {
		nip_dbg("checksum fail, drop skb");
		goto discard_it;
	}

	th = (const struct tcphdr *)skb->data;

	if (unlikely(th->doff < sizeof(struct tcphdr) / TCP_NUM_4)) {
		nip_dbg("non-four byte alignment, drop skb");
		goto discard_it;
	}

	sk = __ninet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th),
				th->source, th->dest, dif, &refcounted);
	if (!sk) {
		nip_dbg("can`t find related sock for skb, will disconnect");
		goto no_tcp_socket;
	}

	if (sk->sk_state == TCP_TIME_WAIT) {
		/* Handles the SK portion of the interrupt state */
		nip_dbg("sk_state is TCP_TIME_WAIT, drop skb");
		goto discard_it;
	}
	if (sk->sk_state == TCP_NEW_SYN_RECV) {
		struct request_sock *req = inet_reqsk(sk);
		struct sock *nsk;

		nip_dbg("TCP server into third shake hands, sk->sk_state:%d", sk->sk_state);
		sk = req->rsk_listener;

		sock_hold(sk);
		refcounted = true;
		nsk = NULL;
		/* You need to create a new SOCK and enter TCP_SYN_RECV,
		 * which is then set to Established
		 */
		if (!tcp_filter(sk, skb)) {
			th = (const struct tcphdr *)skb->data;
			tcp_nip_fill_cb(skb, th);
			nsk = tcp_nip_check_req(sk, skb, req);
		}
		if (!nsk || nsk == sk) {
			nip_dbg("skb info error and create newsk failure, drop skb");
			reqsk_put(req);
			goto discard_and_relse;
		}
		if (tcp_nip_child_process(sk, nsk, skb)) {
			nip_dbg("child process fail, drop skb");
			goto discard_and_relse;
		} else {
			sock_put(sk);
			return 0;
		}
	}

	tcp_nip_fill_cb(skb, th);

	if (tcp_filter(sk, skb)) {
		nip_dbg("tcp filter fail, drop skb");
		goto discard_and_relse;
	}
	th = (const struct tcphdr *)skb->data;
	skb->dev = NULL;

	if (sk->sk_state == TCP_LISTEN) {
		nip_dbg("TCP server into first shake hands! sk->sk_state:%d", sk->sk_state);
		ret  = tcp_nip_do_rcv(sk, skb);
		goto put_and_return;
	}
	bh_lock_sock_nested(sk);

	ret = 0;
	if (!sock_owned_by_user(sk)) {
		ret = tcp_nip_do_rcv(sk, skb);
	} else {
		nip_dbg("sock locked by user, put packet into backlog");
		if (tcp_nip_add_backlog(sk, skb)) {
			nip_dbg("add backlog fail, drop skb");
			goto discard_and_relse;
		}
	}

	bh_unlock_sock(sk);

put_and_return:
	if (refcounted)
		sock_put(sk);
	return ret ? -1 : 0;

no_tcp_socket:
	tcp_nip_send_reset(NULL, skb);
	goto discard_it;
discard_it:
	kfree_skb(skb);
	return 0;

discard_and_relse:
	sk_drops_add(sk, skb);
	if (refcounted)
		sock_put(sk);
	goto discard_it;
}

static void tcp_nip_early_demux(struct sk_buff *skb)
{
	const struct tcphdr *th;
	struct sock *sk;

	if (skb->pkt_type != PACKET_HOST)
		return;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct tcphdr)))
		return;

	th = tcp_hdr(skb);
	if (th->doff < sizeof(struct tcphdr) / BYTES_PER_TCP_HEADER)
		return;

	sk = __ninet_lookup_established(dev_net(skb->dev), &tcp_hashinfo,
					&NIPCB(skb)->srcaddr, th->source,
					&NIPCB(skb)->dstaddr, ntohs(th->dest), skb->skb_iif);
	if (sk) {
		skb->sk = sk;
		skb->destructor = sock_edemux;
		if (sk_fullsock(sk)) {
			struct dst_entry *dst = READ_ONCE(sk->sk_rx_dst);

			if (dst)
				dst = dst_check(dst, 0);
			if (dst && inet_sk(sk)->rx_dst_ifindex == skb->skb_iif) {
				nip_dbg("find sock in ehash, set dst for skb");
				skb_dst_set_noref(skb, dst);
			}
		}
	}
}

void tcp_nip_done(struct sock *sk)
{
	struct request_sock *req = tcp_sk(sk)->fastopen_rsk;

	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV)
		TCP_INC_STATS(sock_net(sk), TCP_MIB_ATTEMPTFAILS);

	tcp_set_state(sk, TCP_CLOSE);
	inet_csk_clear_xmit_timers(sk);
	if (req)
		reqsk_fastopen_remove(sk, req, false);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);
	} else {
		WARN_ON(sk->sk_state != TCP_CLOSE);
		WARN_ON(!sock_flag(sk, SOCK_DEAD));

		/* It cannot be in hash table! */
		WARN_ON(!sk_unhashed(sk));

		/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
		WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);
		sk->sk_prot->destroy(sk);

		sk_nip_stream_kill_queues(sk);

		local_bh_disable();
		this_cpu_dec(*sk->sk_prot->orphan_count);
		local_bh_enable();
		sock_put(sk);
		nip_dbg("close sock done");
	}
}

/* Function
 *    Disconnect the connection to the peer end, non-blocking
 *    Release read/write queue, send RST (not sent yet), clear timer
 * Parameter
 *    sk: Transmission control block
 */
int tcp_nip_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;
	u32 sk_ack_backlog;

	nip_dbg("old_state=%u", old_state);
	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	if (old_state == TCP_LISTEN) {
		sk_ack_backlog = READ_ONCE(sk->sk_ack_backlog);
		inet_csk_listen_stop(sk);
		nip_dbg("sk_state CLOSE, sk_ack_backlog=%u to %u, sk_max_ack_backlog=%u",
			sk_ack_backlog, READ_ONCE(sk->sk_ack_backlog),
			READ_ONCE(sk->sk_max_ack_backlog));
	} else if (tcp_nip_need_reset(old_state) || (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		tcp_nip_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT) {
		sk->sk_err = ECONNRESET;
	}

	tcp_nip_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	tcp_write_queue_purge(sk);

	_tcp_sock_priv_init(sk);

	inet->inet_dport = 0;
	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt_us = 0;
	tp->write_seq += tp->max_window + TCP_NUM_2;
	if (tp->write_seq == 0)
		tp->write_seq = 1;
	tp->snd_cwnd = TCP_NUM_2;
	icsk->icsk_backoff = 0;
	icsk->icsk_probes_out = 0;
	icsk->icsk_probes_tstamp = 0;
	icsk->icsk_rto = get_nip_rto() == 0 ? TCP_TIMEOUT_INIT : (HZ / get_nip_rto());
	icsk->icsk_rto_min = TCP_RTO_MIN;
	icsk->icsk_delack_max = TCP_DELACK_MAX;
	tp->packets_out = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->window_clamp = 0;
	tp->delivered = 0;
	tcp_clear_retrans(tp);
	tp->total_retrans = 0;
	inet_csk_delack_init(sk);

	icsk->icsk_ack.rcv_mss = TCP_MIN_MSS;
	sk->sk_send_head = NULL;
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);
	dst_release(sk->sk_rx_dst);
	sk->sk_rx_dst = NULL;
	tp->segs_in = 0;
	tp->segs_out = 0;
	tp->bytes_acked = 0;
	tp->bytes_received = 0;
	tp->data_segs_in = 0;
	tp->data_segs_out = 0;

	WARN_ON(inet->inet_num && !icsk->icsk_bind_hash);

	if (sk->sk_frag.page) {
		put_page(sk->sk_frag.page);
		sk->sk_frag.page = NULL;
		sk->sk_frag.offset = 0;
	}

	sk->sk_error_report(sk);
	return err;
}

struct sock *ninet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *newsk;
	u32 sk_ack_backlog_last = READ_ONCE(sk->sk_ack_backlog);
	u32 sk_max_ack_backlog = READ_ONCE(sk->sk_max_ack_backlog);

	newsk = inet_csk_accept(sk, flags, err, kern);
	nip_dbg("accept %s, sk_ack_backlog_last=%u, sk_max_ack_backlog=%u",
		(newsk ? "ok" : "fail"), sk_ack_backlog_last, sk_max_ack_backlog);

	return newsk;
}

struct proto tcp_nip_prot = {
	.name			= "NIP_TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_nip_close,
	.connect		= tcp_nip_connect,
	.disconnect		= tcp_nip_disconnect,
	.accept			= ninet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= tcp_nip_init_sock,
	.destroy		= tcp_nip_destroy_sock,
	.shutdown		= tcp_nip_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.keepalive		= tcp_set_keepalive,
	.recvmsg		= tcp_nip_recvmsg,
	.sendmsg		= tcp_nip_sendmsg,
	.sendpage		= NULL,
	.backlog_rcv		= tcp_nip_do_rcv,
	.release_cb		= tcp_nip_release_cb,
	.hash			= ninet_hash,
	.unhash			= ninet_unhash,
	.get_port		= inet_csk_get_port,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_rmem),
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp_nip_sock),
	.rsk_prot		= &tcp_nip_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
	.no_autobind		= true,
};

static const struct ninet_protocol tcp_nip_protocol   = {
	.early_demux	=	tcp_nip_early_demux,
	.handler	=	tcp_nip_rcv,
	.flags		=	0,
};

static struct inet_protosw tcp_nip_protosw = {
	.type		=	SOCK_STREAM,
	.protocol	=	IPPROTO_TCP,
	.prot		=	&tcp_nip_prot,
	.ops		=	&ninet_stream_ops,
	.flags		=	INET_PROTOSW_PERMANENT |
				INET_PROTOSW_ICSK,
};

int __init tcp_nip_init(void)
{
	int ret;

	ret = ninet_add_protocol(&tcp_nip_protocol, IPPROTO_TCP);
	if (ret)
		goto out;

	/* register ninet protocol */
	ret = ninet_register_protosw(&tcp_nip_protosw);
	if (ret)
		goto out_nip_tcp_protocol;

out:
	return ret;

out_nip_tcp_protocol:
	ninet_del_protocol(&tcp_nip_protocol, IPPROTO_TCP);
	goto out;
}

/* When adding the __exit tag to a function, it is important to
 * ensure that the function is only called during the exit phase
 * to avoid unnecessary warnings and errors.
 */
void tcp_nip_exit(void)
{
	ninet_unregister_protosw(&tcp_nip_protosw);
	ninet_del_protocol(&tcp_nip_protocol, IPPROTO_TCP);
}
