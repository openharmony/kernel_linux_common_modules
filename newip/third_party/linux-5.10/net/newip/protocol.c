// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv6/protocol.c
 * Authors:	Pedro Roque	<roque@di.fc.ul.pt>
 *
 *      Changes:
 *
 *      Vince Laviano (vince@cs.stanford.edu)       16 May 2001
 *      - Removed unused variable 'inet6_protocol_base'
 *      - Modified inet6_del_protocol() to correctly maintain copy bit.
 *
 * NewIP INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * NewIP INET protocol dispatch tables.
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

