/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */
#ifndef _NIP_CHECKSUM_H
#define _NIP_CHECKSUM_H

#include "nip_addr.h"

struct nip_pseudo_header {
	struct nip_addr saddr;    /* Source address, network order.(big end) */
	struct nip_addr daddr;    /* Destination address, network order.(big end) */
	unsigned short check_len; /* network order.(big end) */
	unsigned char nexthdr;    /* Upper-layer Protocol Type: IPPROTO_UDP */
};

/* The checksum is calculated when the packet is received
 * Note:
 * 1.chksum_header->check_len is network order.(big end)
 * 2.data_len is host order.
 */
unsigned short nip_check_sum_parse(unsigned char *data,
				   unsigned short check_len,
				   struct nip_pseudo_header *chksum_header);

/* The checksum is calculated when the packet is sent
 * Note:
 * 1.chksum_header->check_len is network order.(big end)
 * 2.data_len is host order.
 */
unsigned short nip_check_sum_build(unsigned char *data,
				   unsigned short data_len,
				   struct nip_pseudo_header *chksum_header);

#endif /* _NIP_CHECKSUM_H */

