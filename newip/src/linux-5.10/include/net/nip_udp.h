/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Definitions for the NewIP UDP module.
 *
 * Based on include/net/udp.h
 */
#ifndef _NET_NEWIP_UDP_H
#define _NET_NEWIP_UDP_H

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/skbuff.h>

#define NIP_UDP_HSLOT_COUNT 10

int nip_udp_init(void);

int nip_udp_output(struct sock *sk, struct msghdr *msg, size_t len);

int nip_udp_input(struct sk_buff *skb);
int nip_udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		    int noblock, int flags, int *addr_len);

#endif
