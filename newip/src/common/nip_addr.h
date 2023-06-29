/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Provide operations and conversions
 * related to NewIP address.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-18
 */
#ifndef _UAPI_NEWIP_ADDR_H
#define _UAPI_NEWIP_ADDR_H

#define NIP_ADDR_LEN_1 1
#define NIP_ADDR_LEN_2 2
#define NIP_ADDR_LEN_3 3
#define NIP_ADDR_LEN_4 4
#define NIP_ADDR_LEN_5 5
#define NIP_ADDR_LEN_7 7
#define NIP_ADDR_LEN_8 8

#define NIP_ADDR_BIT_LEN_8    8
#define NIP_ADDR_BIT_LEN_16   16
#define NIP_ADDR_BIT_LEN_24   24
#define NIP_ADDR_BIT_LEN_40   40
#define NIP_ADDR_BIT_LEN_MAX  64

enum nip_addr_check_value {
	ADDR_FIRST_DC = 0xDC,
	ADDR_FIRST_F0 = 0xF0,
	ADDR_FIRST_F1,
	ADDR_FIRST_F2,
	ADDR_FIRST_F3,
	ADDR_FIRST_FE = 0xFE,
	ADDR_FIRST_FF = 0xFF,
	ADDR_SECOND_MIN_DD = 0xDD,
	ADDR_SECOND_MIN_F1 = 0x14,    /* f1 14 00 */
	ADDR_THIRD_MIN_F2 = 0x01,     /* f2 00 01 00 00 */
	ADDR_THIRD_MIN_F3 = 0x01,     /* F3 0001 0000 0000 */
};

enum nip_8bit_addr_index {
	NIP_8BIT_ADDR_INDEX_0 = 0,
	NIP_8BIT_ADDR_INDEX_1 = 1,
	NIP_8BIT_ADDR_INDEX_2 = 2,
	NIP_8BIT_ADDR_INDEX_3 = 3,
	NIP_8BIT_ADDR_INDEX_4 = 4,
	NIP_8BIT_ADDR_INDEX_5 = 5,
	NIP_8BIT_ADDR_INDEX_6 = 6,
	NIP_8BIT_ADDR_INDEX_7 = 7,
	NIP_8BIT_ADDR_INDEX_MAX,
};

enum nip_16bit_addr_index {
	NIP_16BIT_ADDR_INDEX_0 = 0,
	NIP_16BIT_ADDR_INDEX_1 = 1,
	NIP_16BIT_ADDR_INDEX_2 = 2,
	NIP_16BIT_ADDR_INDEX_3 = 3,
	NIP_16BIT_ADDR_INDEX_MAX,
};

enum nip_32bit_addr_index {
	NIP_32BIT_ADDR_INDEX_0 = 0,
	NIP_32BIT_ADDR_INDEX_1 = 1,
	NIP_32BIT_ADDR_INDEX_MAX,
};

#define NIP_ADDR_FIELD8 v.u.field8
#define NIP_ADDR_FIELD16 v.u.field16
#define NIP_ADDR_FIELD32 v.u.field32

#pragma pack(1)
struct nip_addr_field {
	union {
		unsigned char   field8[NIP_8BIT_ADDR_INDEX_MAX];
		unsigned short field16[NIP_16BIT_ADDR_INDEX_MAX]; /* big-endian */
		unsigned int   field32[NIP_32BIT_ADDR_INDEX_MAX]; /* big-endian */
	} u;
};

struct nip_addr {
	unsigned char bitlen; /* The address length is in bit (not byte) */
	struct nip_addr_field v;
};

#pragma pack()

enum nip_index {
	INDEX_0 = 0,
	INDEX_1 = 1,
	INDEX_2 = 2,
	INDEX_3 = 3,
	INDEX_4 = 4,
	INDEX_5 = 5,
	INDEX_6 = 6,
	INDEX_7 = 7,
	INDEX_8 = 8,
	INDEX_9 = 9,
	INDEX_10 = 10,
	INDEX_11 = 11,
	INDEX_12 = 12,
	INDEX_13 = 13,
	INDEX_14 = 14,
	INDEX_15 = 15,
	INDEX_MAX,
};

extern const struct nip_addr nip_any_addr;
extern const struct nip_addr nip_broadcast_addr_arp;

int nip_addr_invalid(const struct nip_addr *addr);
int nip_addr_public(const struct nip_addr *addr);
int nip_addr_any(const struct nip_addr *addr);
int get_nip_addr_len(const struct nip_addr *addr);
unsigned char *build_nip_addr(const struct nip_addr *addr, unsigned char *buf);
unsigned char *decode_nip_addr(unsigned char *buf, struct nip_addr *addr);
int is_nip_local_addr(const struct nip_addr *addr);

#endif /* _UAPI_NEWIP_ADDR_H */

