/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Based on include/net/transp_v6.h
 */
#ifndef _TRANSP_NIP_H
#define _TRANSP_NIP_H

extern struct proto nip_udp_prot;

int nip_udp_init(void);
void nip_udp_exit(void);

int nip_udp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);

void nip_datagram_recv_ctl(struct sock *sk, struct msghdr *msg,
			   struct sk_buff *skb);
void nip_datagram_recv_common_ctl(struct sock *sk, struct msghdr *msg,
				  struct sk_buff *skb);
void nip_datagram_recv_specific_ctl(struct sock *sk, struct msghdr *msg,
				    struct sk_buff *skb);

void nip_dgram_sock_seq_show(struct seq_file *seq, struct sock *sp, __u16 srcp,
			     __u16 destp, int bucket);

void ninet_destroy_sock(struct sock *sk);

#endif
