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
static int _get_nip_hdr_bitmap(struct nip_buff *nbuf,
			       unsigned char bitmap[],
			       unsigned char bitmap_index_max)
{
	int i = 0;

	if (nbuf->remaining_len < sizeof(unsigned char))
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	if (*nbuf->data & NIP_BITMAP_INVALID_SET)
		return -NIP_HDR_BITMAP_INVALID;

	do {
		if (i >= bitmap_index_max)
			return -NIP_HDR_BITMAP_NUM_OUT_RANGE;

		if (nbuf->remaining_len < sizeof(unsigned char))
			return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

		bitmap[i] = *nbuf->data;
		nip_buff_pull(nbuf, sizeof(unsigned char));
	} while (bitmap[i++] & NIP_BITMAP_HAVE_MORE_BIT);

	return i;
}

/* Must carry the current field */
static int _get_nip_hdr_ttl(struct nip_buff *nbuf,
			    unsigned char bitmap,
			    struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_TTL))
		return -NIP_HDR_NO_TTL;

	if (nbuf->remaining_len < sizeof(niph->ttl))
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	niph->ttl = *nbuf->data;
	niph->include_ttl = 1;
	nip_buff_pull(nbuf, sizeof(niph->ttl));

	return 0;
}

/* Optional fields */
/* Communication between devices of the same version may not carry packet Header length,
 * but communication between devices of different versions must carry packet header length
 */
static int _get_nip_hdr_len(struct nip_buff *nbuf,
			    unsigned char bitmap,
			    struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_HDR_LEN))
		return 0;

	if (nbuf->remaining_len < sizeof(niph->hdr_len))
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	/* Total_len is a network sequence and cannot be
	 * compared directly with the local sequence
	 */
	niph->hdr_len = *nbuf->data;
	niph->include_hdr_len = 1;
	nip_buff_pull(nbuf, sizeof(niph->hdr_len));

	if (niph->include_total_len && niph->hdr_len >= niph->rcv_buf_len)
		return -NIP_HDR_LEN_OUT_RANGE;

	return 0;
}

/* Must carry the current field */
static int _get_nip_hdr_nexthdr(struct nip_buff *nbuf,
				unsigned char bitmap,
				struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_NEXT_HDR))
		return -NIP_HDR_NO_NEXT_HDR;

	if (nbuf->remaining_len < sizeof(niph->nexthdr))
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	niph->nexthdr = *nbuf->data;
	niph->include_nexthdr = 1;
	nip_buff_pull(nbuf, sizeof(niph->nexthdr));

	return 0;
}

/* Must carry the current field */
/* Note: niph->saddr is network order.(big end) */
static int _get_nip_hdr_daddr(struct nip_buff *nbuf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	unsigned char *p;

	if (!(bitmap & NIP_BITMAP_INCLUDE_DADDR))
		return -NIP_HDR_NO_DADDR;

	p = decode_nip_addr(nbuf, &niph->daddr);
	if (!p)
		return -NIP_HDR_DECAP_DADDR_ERR;

	if (nip_addr_invalid(&niph->daddr))
		return -NIP_HDR_DADDR_INVALID;

	niph->include_daddr = 1;
	return 0;
}

/* Optional fields */
/* Note: niph->daddr is network order.(big end) */
static int _get_nip_hdr_saddr(struct nip_buff *nbuf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	unsigned char *p;

	if (!(bitmap & NIP_BITMAP_INCLUDE_SADDR))
		return 0;

	p = decode_nip_addr(nbuf, &niph->saddr);
	if (!p)
		return -NIP_HDR_DECAP_SADDR_ERR;

	if (nip_addr_invalid(&niph->saddr))
		return -NIP_HDR_SADDR_INVALID;

	niph->include_saddr = 1;
	return 0;
}

/* Optional fields: tcp/arp need, udp needless */
/* Note: niph->total_len is network order.(big end), need change to host order */
static int _get_nip_total_len(struct nip_buff *nbuf,
			      unsigned char bitmap,
			      struct nip_hdr_decap *niph)
{
	if (!(bitmap & NIP_BITMAP_INCLUDE_TOTAL_LEN))
		return 0;

	if (nbuf->remaining_len < sizeof(niph->total_len))
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	/* Total_len is a network sequence and cannot be
	 * compared directly with the local sequence
	 */
	niph->total_len = *((unsigned short *)nbuf->data);
	niph->include_total_len = 1;
	nip_buff_pull(nbuf, sizeof(niph->total_len));

	return 0;
}

static int _nip_hdr_bitmap0_parse(struct nip_buff *nbuf,
				  unsigned char bitmap,
				  struct nip_hdr_decap *niph)
{
	int err;

	err = _get_nip_hdr_ttl(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	/* Optional fields */
	err = _get_nip_total_len(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	err = _get_nip_hdr_nexthdr(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	err = _get_nip_hdr_daddr(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	err = _get_nip_hdr_saddr(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	return 0;
}

static int _nip_hdr_bitmap1_parse(struct nip_buff *nbuf,
				  unsigned char bitmap,
				  struct nip_hdr_decap *niph)
{
	int err;

	/* If add new field needs to be modified with the macro definition */
	if (bitmap & NIP_INVALID_BITMAP_2)
		niph->include_unknown_bit = 1;

	/* Optional fields */
	err = _get_nip_hdr_len(nbuf, bitmap, niph);
	if (err < 0)
		return err;

	return 0;
}

static int _nip_hdr_unknown_bit_check(struct nip_buff *nbuf,
				      unsigned char bitmap,
				      struct nip_hdr_decap *niph)
{
	niph->include_unknown_bit = 1;
	return 0;
}

#define FACTORY_NUM_MAX 3
static int (*hdr_parse_factory[FACTORY_NUM_MAX])(struct nip_buff *,
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
	unsigned char bitmap[BITMAP_MAX] = {0};
	int num;
	struct nip_buff nbuf;

	nbuf.data = rcv_buf;
	if (!nbuf.data)
		return 0;

	nbuf.remaining_len = buf_len;
	num = _get_nip_hdr_bitmap(&nbuf, bitmap, BITMAP_MAX);
	if (num <= 0)
		return num;

	niph->rcv_buf_len = buf_len;
	while (i < num) {
		int err;

		if (i >= FACTORY_NUM_MAX)
			break;

		err = hdr_parse_factory[i](&nbuf, bitmap[i], niph);
		if (err < 0)
			return err;

		i++;
	}

	if (buf_len < nbuf.remaining_len)
		return -NIP_HDR_RCV_BUF_READ_OUT_RANGE;

	niph->hdr_real_len = (unsigned char)(buf_len - nbuf.remaining_len);
	ret = nip_hdr_check(niph);
	if (ret < 0)
		return ret;

	return niph->hdr_len > niph->hdr_real_len ?
	       niph->hdr_len : niph->hdr_real_len;
}

