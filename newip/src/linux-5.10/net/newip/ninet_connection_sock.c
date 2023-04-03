// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Support for NewIP INET connection oriented protocols.
 *
 * Based on net/ipv4/inet_connection_sock.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/nip.h>
#include <linux/jhash.h>

#include <net/tcp.h>
#include <net/nip_addrconf.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/nip_route.h>
#include <net/sock.h>
#include <net/ninet_connection_sock.h>
#include <net/tcp_nip.h>
#include "tcp_nip_parameter.h"

/* Function
 *	Timeout handler for request processing, used to retransmit SYN+ACK
 * Parameter
 *	t: Request control block
 */
static void ninet_reqsk_timer_handler(struct timer_list *t)
{
	struct request_sock *req = from_timer(req, t, rsk_timer);
	struct sock *sk_listener = req->rsk_listener;
	struct net *net = sock_net(sk_listener);
	struct inet_connection_sock *icsk = inet_csk(sk_listener);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	int max_retries, thresh;

	/* Defines the maximum number of retransmissions. Thresh defaults to 5 */
	max_retries = icsk->icsk_syn_retries ? : net->ipv4.sysctl_tcp_synack_retries;
	thresh = max_retries;

	/* Check timeout times. SYN+ACK retransmission times +1 */
	if (req->num_timeout <= thresh) {
		unsigned long timeo;

		req->rsk_ops->rtx_syn_ack(sk_listener, req);
		req->num_retrans++;
		/* If the number of times out is still 0, the number is increased by 1
		 * to determine whether it is the first time out
		 */
		if (req->num_timeout++ == 0)
			atomic_dec(&queue->young);
		timeo = min(TCP_TIMEOUT_INIT, TCP_RTO_MAX);
		mod_timer(&req->rsk_timer, jiffies + timeo);
		return;
	}

	inet_csk_reqsk_queue_drop_and_put(sk_listener, req);
}

/* Function
 *	Add request_SOCK to the connection queue and ehash table,
 *	and set the SYNACK timeout retransmission timer
 * Parameter
 *	sk: Transmission control block
 *	req: Connection request block
 *	timeout: The initial timeout period
 */
void ninet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				    unsigned long timeout)
{
	req->num_retrans = 0;
	req->num_timeout = 0;
	req->sk = NULL;

	timer_setup(&req->rsk_timer, ninet_reqsk_timer_handler,
		    TIMER_PINNED);
	mod_timer(&req->rsk_timer, jiffies + timeout);

	inet_ehash_insert(req_to_sk(req), NULL, NULL);

	smp_wmb(); /* memory barrier */
	refcount_set(&req->rsk_refcnt, TCP_NUM_2 + 1);

	inet_csk_reqsk_queue_added(sk);
}

