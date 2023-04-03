/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP NET
 * Generic infrastructure for NewIP INET connection oriented protocols.
 *
 * Based on include/net/inet_connection_sock.h
 */
#ifndef _NINET_CONNECTION_SOCK_H
#define _NINET_CONNECTION_SOCK_H

#include <net/inet_sock.h>
#include <net/request_sock.h>
#include <linux/types.h>

struct inet_bind_bucket;
struct request_sock;
struct sk_buff;
struct sock;
struct sockaddr;

int ninet_csk_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl);
void ninet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout);

#endif /* _NINET_CONNECTION_SOCK_H */
