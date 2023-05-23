// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: This file implements the function
 * of decapsulating the NewIP protocol header.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-18
 */
#include "nip_hdr.h"

/* Must carry the current field */
static int _get_nip_hdr_bitmap(unsigned char *buf,
			       unsigned char bitmap[],
			       unsigned char bitmap_index_max)
{
	int i = 0;
	unsigned char *p = buf;

	if (*p & NIP_BITMAP_INVALID_SET)
		return -NIP_HDR_BITMAP_INVALID;

	do {
		if (i >= bitmap_index_max)
			return -NIP_HDR_BITMAP_NUM_OUT_RANGE;

		bitmap[i] = *p;
		p++;
	} while (bitmap[i++] & NIP_BITMAP_HAVE_MORE_BIT);

	return i;
}

/* Must carry the current field */
static int _get_nip_hdr_ttl(const unsigned char *buf,
			    unsigned char bitmap,
			    struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_TTL))
		return -NIP_HDR_NO_TTL;

	niph->ttl = *buf;
	niph->include_ttl = 1;

	return sizeof(niph->ttl);
}

/* Optional fields */
/* Communication between devices of the same version may not carry packet Header length,
 * but communication between devices of different versions must carry packet header length
 */
static int _get_nip_hdr_len(const unsigned char *buf,
			    unsigned char bitmap,
			    struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_HDR_LEN))
		return 0;

	/* Total_len is a network sequence and cannot be
	 * compared directly with the local sequence
	 */
	niph->hdr_len = *buf;
	niph->include_hdr_len = 1;

	if (niph->include_total_len && niph->hdr_len >= niph->rcv_buf_len)
		return -NIP_HDR_LEN_OUT_RANGE;

	return sizeof(niph->hdr_len);
}

/* Must carry the current field */
static int _get_nip_hdr_nexthdr(const unsigned char *buf,
				unsigned char bitmap,
				struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_NEXT_HDR))
		return -NIP_HDR_NO_NEXT_HDR;

	niph->nexthdr = *buf;
	niph->include_nexthdr = 1;

	return sizeof(niph->nexthdr);
}

/* Must carry the current field */
/* Note: niph->saddr is network order.(big end) */
static int _get_nip_hdr_daddr(unsigned char *buf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	unsigned char *p;

	if (!(bitmap & NIP_BITMAP_INCLUDE_DADDR))
		return -NIP_HDR_NO_DADDR;

	p = decode_nip_addr(buf, &niph->daddr);
	if (!p)
		return -NIP_HDR_DECAP_DADDR_ERR;

	if (nip_addr_invalid(&niph->daddr))
		return -NIP_HDR_DADDR_INVALID;

	niph->include_daddr = 1;
	return (niph->daddr.bitlen / NIP_ADDR_BIT_LEN_8);
}

/* Optional fields */
/* Note: niph->daddr is network order.(big end) */
static int _get_nip_hdr_saddr(unsigned char *buf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	unsigned char *p;

	if (!(bitmap & NIP_BITMAP_INCLUDE_SADDR))
		return 0;

	p = decode_nip_addr(buf, &niph->saddr);
	if (!p)
		return -NIP_HDR_DECAP_SADDR_ERR;

	if (nip_addr_invalid(&niph->saddr))
		return -NIP_HDR_SADDR_INVALID;

	niph->include_saddr = 1;
	return (niph->saddr.bitlen / NIP_ADDR_BIT_LEN_8);
}

/* Optional fields: tcp/arp need, udp needless */
/* Note: niph->total_len is network order.(big end), need change to host order */
static int _get_nip_total_len(unsigned char *buf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_TOTAL_LEN))
		return 0;

	/* Total_len is a network sequence and cannot be
	 * compared directly with the local sequence
	 */
	niph->total_len = *((unsigned short *)buf);
	niph->include_total_len = 1;

	return sizeof(niph->total_len);
}

static int _nip_hdr_bitmap0_parse(unsigned char *buf,
				  unsigned char bitmap,
				  struct nip_hdr_decap *niph)
{
	int len;
	int len_total = 0;

	len = _get_nip_hdr_ttl(buf, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	/* Optional fields */
	len = _get_nip_total_len(buf + len_total, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	len = _get_nip_hdr_nexthdr(buf + len_total, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	len = _get_nip_hdr_daddr(buf + len_total, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	len = _get_nip_hdr_saddr(buf + len_total, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	return len_total;
}

static int _nip_hdr_bitmap1_parse(unsigned char *buf,
				  unsigned char bitmap,
				  struct nip_hdr_decap *niph)
{
	int len;
	int len_total = 0;

	/* If add new field needs to be modified with the macro definition */
	if (bitmap & NIP_INVALID_BITMAP_2)
		niph->include_unknown_bit = 1;

	/* Optional fields */
	len = _get_nip_hdr_len(buf + len_total, bitmap, niph);
	if (len < 0)
		return len;
	len_total += len;

	return len_total;
}

static int _nip_hdr_unknown_bit_check(unsigned char *buf,
				      unsigned char bitmap,
				      struct nip_hdr_decap *niph)
{
	niph->include_unknown_bit = 1;
	return 0;
}

#define FACTORY_NUM_MAX 3
static int (*hdr_parse_factory[FACTORY_NUM_MAX])(unsigned char *,
						 unsigned char,
						 struct nip_hdr_decap *) = {
	_nip_hdr_bitmap0_parse,
	_nip_hdr_bitmap1_parse,
	_nip_hdr_unknown_bit_check,
};

static int nip_hdr_check(struct nip_hdr_decap *niph)
{
	if (niph->include_unknown_bit && !niph->include_hdr_len)
		/* different ver pkt but no hdr len */
		return -NIP_HDR_UNKNOWN_AND_NO_HDR_LEN;

	if (niph->include_hdr_len) {
		if (niph->hdr_len == 0 ||
		    niph->hdr_len < niph->hdr_real_len)
			return -NIP_HDR_LEN_INVALID;
	}

	return 0;
}

/* Note:
 * 1.niph->total_len is network order.(big end), need change to host order
 * 2.niph->saddr/daddr is network order.(big end)
 */
int nip_hdr_parse(unsigned char *rcv_buf, unsigned int buf_len, struct nip_hdr_decap *niph)
{
	int i = 0;
	int ret;
	unsigned char *buf = rcv_buf;
	unsigned char bitmap[BITMAP_MAX] = {0};
	int num = _get_nip_hdr_bitmap(buf, bitmap, BITMAP_MAX);

	if (num <= 0 || !rcv_buf)
		return num;

	niph->hdr_real_len = num * sizeof(bitmap[0]);
	buf += niph->hdr_real_len;

	niph->rcv_buf_len = buf_len;
	while (i < num) {
		int len;

		if (i >= FACTORY_NUM_MAX)
			break;
		len = hdr_parse_factory[i](buf, bitmap[i], niph);
		if (len < 0)
			return len;

		buf += len;
		niph->hdr_real_len += len;
		if (niph->hdr_real_len >= buf_len)
			return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;
		i++;
	}

	ret = nip_hdr_check(niph);
	if (ret < 0)
		return ret;

	return niph->hdr_len > niph->hdr_real_len ?
	       niph->hdr_len : niph->hdr_real_len;
}

