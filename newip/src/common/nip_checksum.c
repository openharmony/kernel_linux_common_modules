// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Provides some functionalities for
 * checksum calculation in the NewIP protocol.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-18
 */
#include "nip_hdr.h"
#include "nip_checksum.h"

#define USHORT_PAYLOAD 16
#define NIP_CHECKSUM_UINT8_PAYLOAD 8
unsigned int _nip_check_sum(const unsigned char *data, unsigned short data_len)
{
	unsigned int i = 0;
	unsigned int sum = 0;

	while (i + 1 < data_len) {
		sum += (data[i] << NIP_CHECKSUM_UINT8_PAYLOAD) + data[i + 1];
		i += 2; /* Offset 2 bytes */
	}

	if (i < (unsigned int)data_len)
		sum += (data[i] << NIP_CHECKSUM_UINT8_PAYLOAD);

	return sum;
}

unsigned int _nip_header_chksum(struct nip_pseudo_header *chksum_header)
{
	int i, j;
	int addr_len;
	unsigned char pseudo_header[NIP_HDR_MAX] = {0};
	unsigned short hdr_len = 0;

	addr_len = chksum_header->saddr.bitlen / NIP_ADDR_BIT_LEN_8;
	if (addr_len && addr_len < NIP_HDR_MAX) {
		j = 0;
		for (i = 0; i < addr_len; i++, j++)
			pseudo_header[j] = chksum_header->saddr.NIP_ADDR_FIELD8[i];
		hdr_len += addr_len;
	}

	addr_len = chksum_header->daddr.bitlen / NIP_ADDR_BIT_LEN_8;
	if (addr_len && addr_len < NIP_HDR_MAX) {
		j = hdr_len;
		for (i = 0; i < addr_len; i++, j++)
			pseudo_header[j] = chksum_header->daddr.NIP_ADDR_FIELD8[i];
		hdr_len += addr_len;
	}

	/* chksum_header->check_len is network order.(big end) */
	if (hdr_len < NIP_HDR_MAX) {
		*(unsigned short *)(pseudo_header + hdr_len) = chksum_header->check_len;
		hdr_len += sizeof(chksum_header->check_len);
	}

	if (hdr_len < NIP_HDR_MAX) {
		*(pseudo_header + hdr_len) = chksum_header->nexthdr;
		hdr_len += sizeof(chksum_header->nexthdr);
	}

	return _nip_check_sum(pseudo_header, hdr_len);
}

/* The checksum is calculated when the packet is received
 * Note:
 * 1.chksum_header->check_len is network order.(big end)
 * 2.check_len is host order.
 */
unsigned short nip_check_sum_parse(unsigned char *data,
				   unsigned short check_len,
				   struct nip_pseudo_header *chksum_header)
{
	unsigned int sum = 0;

	sum = _nip_check_sum(data, check_len);
	sum += _nip_header_chksum(chksum_header);

	while (sum >> USHORT_PAYLOAD)
		sum = (sum >> USHORT_PAYLOAD) + (sum & 0xffff);
	return (unsigned short)sum;
}

/* The checksum is calculated when the packet is sent
 * Note:
 * 1.chksum_header->check_len is network order.(big end)
 * 2.data_len is host order.
 */
unsigned short nip_check_sum_build(unsigned char *data,
				   unsigned short data_len,
				   struct nip_pseudo_header *chksum_header)
{
	unsigned int sum = 0;

	sum = _nip_check_sum(data, data_len);
	sum += _nip_header_chksum(chksum_header);

	while (sum >> USHORT_PAYLOAD)
		sum = (sum >> USHORT_PAYLOAD) + (sum & 0xffff);
	return (unsigned short)(~sum);
}

