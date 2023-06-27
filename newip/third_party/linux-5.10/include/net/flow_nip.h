/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on include/net/flow.h
 * No Authors, no Copyright
 *
 * NewIP Generic internet FLOW.
 */
#ifndef _NET_FLOW_NIP_H
#define _NET_FLOW_NIP_H

#include <net/flow.h>

struct flow_nip {
	struct flowi_common __fl_common;
#define FLOWIN_OIF		__fl_common.flowic_oif
#define FLOWIN_IIF		__fl_common.flowic_iif
	struct nip_addr daddr;
	struct nip_addr saddr;
	union flowi_uli uli;
#define FLN_SPORT		uli.ports.sport
#define FLN_DPORT		uli.ports.dport
} __attribute__((__aligned__(BITS_PER_LONG / 8)));

#endif
