/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Constructs and functions are provided
 * to handle encapsulation and parsing of the NewIP
 * network layer protocol header.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-18
 */
#ifndef _NEWIP_HDR_H
#define _NEWIP_HDR_H

#include "nip_addr.h"

/* Ethernet head 14B, +2B byte alignment, +66 to avoid
 * HMAC driver SKB space expansion caused by Coredum problem
 */
/* This parameter is used only to apply for the length of the packet buffer,
 * but not to determine the actual packet header length
 */
#define NIP_ETH_HDR_BASE_LEN 14
#define NIP_ETH_HDR_LEN (NIP_ETH_HDR_BASE_LEN + 2 + 66)

/* bitmap1 + bitmap2 + TTL + total len + nexthd + daddr + saddr
 * 1B        1B        1B    2B          1B       9B      9B    = 24B
 * V4  TCP 1448
 * NIP TCP 1430 + 30 = 1460
 */
/* This interface is only used to define the buffer length.
 * To calculate the packet header length, use the "get_nip_hdr_len" func
 */
#define NIP_HDR_MAX 24
#define NIP_UDP_HDR_LEN 8
#define NIP_TCP_HDR_LEN 20
#define NIP_MIN_MTU (NIP_HDR_MAX + NIP_TCP_HDR_LEN)
#define NIP_BYTE_ALIGNMENT 2

#define NIP_BITMAP_HAVE_MORE_BIT     0x01

/* Bitmap 1st Byte: bit0 - bit7 */
#define NIP_BITMAP_INVALID_SET       0x80                      /* Bit 0 is set */
#define NIP_BITMAP_INCLUDE_TTL       0x40                      /* Bit 1 is set */
#define NIP_BITMAP_INCLUDE_TOTAL_LEN 0x20                      /* Bit 2 is set */
#define NIP_BITMAP_INCLUDE_NEXT_HDR  0x10                      /* Bit 3 is set */
#define NIP_BITMAP_INCLUDE_RES1      0x08                      /* Bit 4 is set */
#define NIP_BITMAP_INCLUDE_DADDR     0x04                      /* Bit 5 is set */
#define NIP_BITMAP_INCLUDE_SADDR     0x02                      /* Bit 6 is set */
#define NIP_BITMAP_HAVE_BYTE_2       NIP_BITMAP_HAVE_MORE_BIT  /* Bit 7 is set */

/* Bitmap 2nd Byte: bit0 - bit7 */
#define NIP_BITMAP_INCLUDE_HDR_LEN   0x80                      /* Bit 0 is set */
#define NIP_BITMAP_INCLUDE_RES2      0x40                      /* Bit 1 is set */
#define NIP_BITMAP_INCLUDE_RES3      0x20                      /* Bit 2 is set */
#define NIP_BITMAP_INCLUDE_RES4      0x10                      /* Bit 3 is set */
#define NIP_BITMAP_INCLUDE_RES5      0x08                      /* Bit 4 is set */
#define NIP_BITMAP_INCLUDE_RES6      0x04                      /* Bit 5 is set */
#define NIP_BITMAP_INCLUDE_RES7      0x02                      /* Bit 6 is set */
#define NIP_BITMAP_HAVE_BYTE_3       NIP_BITMAP_HAVE_MORE_BIT  /* Bit 7 is set */

/* Bitmap 1st Byte:
 * | valid | ttl | total_len | next_hdr | res1 | daddr | saddr | have byte2 |
 * |   0   |  1  |     0     |     1    |  0   |   1   |   1   |     0      |
 */
#define NIP_UDP_BITMAP_1          0x56
#define NIP_UDP_BITMAP_1_INC_2    0x57

/* Bitmap 1st Byte:
 * | valid | ttl | total_len | next_hdr | res1 | daddr | saddr | have byte2 |
 * |   0   |  1  |     1     |     1    |  0   |   1   |   1   |     0      |
 */
#define NIP_NORMAL_BITMAP_1        0x76
#define NIP_NORMAL_BITMAP_1_INC_2  0x77

/* Bitmap 2nd Byte:
 * | hdr_len | res2 | res2 | res2 | res2 | res2 | res2 | have byte3 |
 * |  0 or 1 |  0   |  0   |  0   |  0   |  0   |  0   |      0     |
 */
#define NIP_NODATA_BITMAP_2        0x00
#define NIP_NORMAL_BITMAP_2        0x80

/* invalid Bitmap 2nd Byte:
 * | hdr_len | res2 | res2 | res2 | res2 | res2 | res2 | have byte3 |
 * |  0 or 1 |  1   |  1   |  1   |  1   |  1   |  1   |      1     |
 */
#define NIP_INVALID_BITMAP_2       0x7F

#define NIP_DEFAULT_TTL 128
#define NIP_ARP_DEFAULT_TTL 64
#define IPPROTO_NIP_ICMP 0xB1

enum NIP_HDR_TYPE {
	NIP_HDR_UDP = 0,
	NIP_HDR_COMM = 1,

	NIP_HDR_TYPE_MAX,
};

enum NIP_HDR_DECAP_ERR {
	NIP_HDR_BITMAP_INVALID = 1,
	NIP_HDR_BITMAP_NUM_OUT_RANGE = 2,
	NIP_HDR_NO_TTL = 3,
	NIP_HDR_NO_NEXT_HDR = 4,
	NIP_HDR_NO_DADDR = 5,
	NIP_HDR_DECAP_DADDR_ERR = 6,
	NIP_HDR_DADDR_INVALID = 7,
	NIP_HDR_DECAP_SADDR_ERR = 8,
	NIP_HDR_SADDR_INVALID = 9,
	NIP_HDR_RCV_BUF_READ_OUT_RANGE = 10,
	NIP_HDR_UNKNOWN_AND_NO_HDR_LEN = 11,
	NIP_HDR_LEN_INVALID = 12,
	NIP_HDR_LEN_OUT_RANGE = 13,

	NIP_HDR_DECAP_ERRCODE_MAX,
};

/* The newIP header contains variable-length fields.
 * The header structure is defined only for function parameter transmission.
 * The fields are parsed in the original packet and saved
 */
struct nip_hdr_decap {
	struct nip_addr saddr; /* Source address, network order.(big end) */
	struct nip_addr daddr; /* Destination address, network order.(big end) */

	unsigned char ttl;          /* Hop count limit */
	unsigned char nexthdr;      /* Upper-layer Protocol Type: IPPROTO_UDP */
	unsigned char hdr_len;      /* Indicates the length of the packet header */
	unsigned char hdr_real_len; /* Indicates the actual length of the packet header */

	unsigned short total_len;   /* Packet length (Header + packet), network order.(big end) */
	unsigned short no_hdr_len : 1;  /* The header does not contain a header length field */
	unsigned short include_unknown_bit : 1; /* There is no other bitmap field */
	unsigned short include_saddr : 1;
	unsigned short include_daddr : 1;
	unsigned short include_ttl : 1;
	unsigned short include_nexthdr : 1;
	unsigned short include_hdr_len : 1;
	unsigned short include_total_len : 1;
	unsigned short res : 8;

	unsigned int rcv_buf_len;
};

/* The newIP packet header function is an incoming or outgoing parameter,
 * which is not the content encapsulated in the packet
 */
#define BITMAP_MAX 8
#define RES_NUM 2
struct nip_hdr_encap {
	struct nip_addr daddr; /* Destination address, network order.(big end) */
	struct nip_addr saddr; /* Source address, network order.(big end) */

	unsigned char ttl;     /* Hop count limit */
	unsigned char nexthdr; /* Upper-layer Protocol Type: IPPROTO_UDP */
	unsigned short total_len; /* Packet header length + packet data length */

	void *usr_data;             /* User data pointer */
	unsigned int usr_data_len;  /* Length of data sent by the user */
	unsigned int trans_hdr_len; /* Transport layer header length */

	unsigned short sport;
	unsigned short dport;

	/* The following are the output parameters */
	unsigned char bitmap[BITMAP_MAX]; /* Bitmap currently supports a maximum of 8 bytes */
	unsigned int bitmap_num;          /* Number of valid elements in the bitmap array */

	unsigned char *hdr_buf;        /* Cache the newIP header */
	unsigned int hdr_buf_pos;      /* Buf Buffer writable address offset */
	unsigned short *frag_id_pos;   /* Fragment Offset in the original packet */
	unsigned char *hdr_len_pos;    /* Indicates the actual length of the packet header */
	unsigned short *total_len_pos; /* Total length position of the packet */

	/* Whether the bitmap of the packet header carries a flag */
	unsigned char encap_ttl : 1;
	unsigned char encap_hdr_len : 1;
	unsigned char encap_daddr : 1;
	unsigned char encap_saddr : 1;
	unsigned char encap_total_len : 1;
	unsigned char encap_res : 3;
};

/* Packet segment information */
struct nip_pkt_seg_info {
	unsigned int mid_pkt_num;      /* Number of intermediate segments */
	unsigned int last_pkt_num;     /* Number of last segments */

	unsigned int mid_usr_pkt_len;  /* Middle segment data length (8B aligned) */
	unsigned int last_usr_pkt_len; /* Length of the last data segment */

	unsigned char *usr_data;       /* Holds a pointer to the user's raw data */
	unsigned int usr_data_len;     /* Length of user data read this time */
};

void nip_calc_pkt_frag_num(unsigned int mtu,
			   unsigned int nip_hdr_len,
			   unsigned int usr_data_len,
			   struct nip_pkt_seg_info *seg_info);

void nip_hdr_udp_encap(struct nip_hdr_encap *head);

/* need update total len after this func, call nip_update_total_len */
void nip_hdr_comm_encap(struct nip_hdr_encap *head);

/* input must be network order. */
void nip_update_total_len(struct nip_hdr_encap *head, unsigned short total_len);

/* Note: a function call requires its own byte order conversion.(niph->total_len) */
int nip_hdr_parse(unsigned char *rcv_buf, unsigned int buf_len, struct nip_hdr_decap *niph);

/* The length of the packet header is obtained according to the packet type,
 * source ADDRESS, and destination address.
 * If the packet does not carry the source address or destination address, fill in the blank
 */
int get_nip_hdr_len(enum NIP_HDR_TYPE hdr_type,
		    const struct nip_addr *saddr,
		    const struct nip_addr *daddr);

struct udp_hdr {
	unsigned short	sport;
	unsigned short	dport;
	unsigned short	len;
	unsigned short	checksum;
};

/* input must be network order. */
static inline void nip_build_udp_hdr(unsigned short sport, unsigned short dport,
				     unsigned short len, unsigned char *buf,
				     unsigned short checksum)
{
	struct udp_hdr *uh;

	uh = (struct udp_hdr *)buf;
	uh->sport = sport;
	uh->dport = dport;
	uh->len = len;
	uh->checksum = checksum;
}

#endif /* _NEWIP_HDR_H */

