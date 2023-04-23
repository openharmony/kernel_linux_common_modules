/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on include/net/netns/ipv6.h
 * No Authors, no Copyright
 *
 * NewIP in net namespaces
 */
#ifndef __NETNS_NEWIP_H__
#define __NETNS_NEWIP_H__

#include <net/inet_frag.h>
#include <net/dst_ops.h>

struct ctl_table_header;

struct netns_sysctl_newip {
	int nip_rt_gc_interval;
};
struct netns_newip {
	uint32_t resv;
	struct netns_sysctl_newip sysctl;
	struct nip_devconf *devconf_dflt;

	struct nip_rt_info *nip_null_entry;
	struct nip_rt_info *nip_broadcast_entry;

	struct dst_ops nip_dst_ops;
	struct nip_fib_table *nip_fib_main_tbl;
	struct nip_fib_table *nip_fib_local_tbl;
};

#endif

