/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP Generic internet FLOW.
 *
 * Based on include/net/flow.h
 */
#ifndef _NET_FLOW_NIP_H
#define _NET_FLOW_NIP_H

#include <net/flow.h>

struct flow_nip {
	struct flowi_common __fl_common;
#define flowin_oif		__fl_common.flowic_oif
#define flowin_iif		__fl_common.flowic_iif
	struct nip_addr daddr;
	struct nip_addr saddr;
	union flowi_uli uli;
#define fln_sport		uli.ports.sport
#define fln_dport		uli.ports.dport
} __attribute__((__aligned__(BITS_PER_LONG / 8)));

#endif
