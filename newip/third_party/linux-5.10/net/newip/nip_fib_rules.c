// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv4/fib_rules.c
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Thomas Graf <tgraf@suug.ch>
 *
 * Fixes:
 *		Rani Assaf	:	local_rule cannot be deleted
 *		Marc Boucher	:	routing by fwmark
 *
 * Based on net/ipv6/fib6_rules.c
 * Copyright (C)2003-2006 Helsinki University of Technology
 * Copyright (C)2003-2006 USAGI/WIDE Project
 *
 * Authors
 *	Thomas Graf		<tgraf@suug.ch>
 *	Ville Nuorvala		<vnuorval@tcs.hut.fi>
 *
 * NewIP Routing Policy Rules
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/nip_fib.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/export.h>
#include "tcp_nip_parameter.h"

struct dst_entry *nip_fib_rule_lookup(struct net *net, struct flow_nip *fln,
				      int flags, int *tbl_type, nip_pol_lookup_t lookup)
{
	struct nip_rt_info *rt;

	rt = lookup(net, net->newip.nip_fib_local_tbl, fln, flags);
	if (rt != net->newip.nip_null_entry) {
		*tbl_type = (int)RT_TABLE_LOCAL;
		return &rt->dst;
	}
	nip_rt_put(rt);
	rt = lookup(net, net->newip.nip_fib_main_tbl, fln, flags);
	if (rt != net->newip.nip_null_entry) {
		*tbl_type = (int)RT_TABLE_MAIN;
		return &rt->dst;
	}
	nip_rt_put(rt);

	dst_hold(&net->newip.nip_null_entry->dst);
	*tbl_type = (int)RT_TABLE_MAX;
	return &net->newip.nip_null_entry->dst;
}
