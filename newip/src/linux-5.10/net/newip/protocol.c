// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * NewIP INET protocol dispatch tables.
 *
 * Based on net/ipv6/protocol.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/protocol.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include "tcp_nip_parameter.h"

const struct ninet_protocol __rcu *ninet_protos[MAX_INET_PROTOS] __read_mostly;

int ninet_add_protocol(const struct ninet_protocol *prot,
		       unsigned char protocol)
{
	return !cmpxchg((const struct ninet_protocol **)&ninet_protos[protocol],
			NULL, prot) ? 0 : -1;
}

int ninet_del_protocol(const struct ninet_protocol *prot,
		       unsigned char protocol)
{
	int ret;

	ret = (cmpxchg((const struct ninet_protocol **)&ninet_protos[protocol],
		       prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}

