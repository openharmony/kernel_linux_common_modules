// SPDX-License-Identifier: GPL-2.0-or-later
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
#include "nip_addr.h"

/* This is similar to 0.0.0.0 in IPv4. Does not appear as a real address,
 * just a constant used by the native for special processing
 */
const struct nip_addr nip_any_addr = {
	.bitlen = NIP_ADDR_BIT_LEN_16,
	.nip_addr_field8[0] = 0xFF, /* 0xFF09 addr, big-endian */
	.nip_addr_field8[1] = 0x09,
};

const struct nip_addr nip_broadcast_addr_arp = {
	.bitlen = NIP_ADDR_BIT_LEN_16,
	.nip_addr_field8[0] = 0xFF, /* 0xFF04 addr, big-endian */
	.nip_addr_field8[1] = 0x04,
};

static const struct nip_addr nip_local_addr = {
	.bitlen = NIP_ADDR_BIT_LEN_16,
	.nip_addr_field8[0] = 0xFF, /* 0xFF00 addr, big-endian */
	.nip_addr_field8[1] = 0x00,
};

enum addr_check_ret {
	NOT_CURRENT_ADDR = -1,
	CURRENT_ADDR_VALID = 0,
	ADDR_2BYTE_INVALID = 1,
	ADDR_3BYTE_INVALID = 2,
	ADDR_5BYTE_INVALID = 3,
	ADDR_7BYTE_INVALID = 4,
	ADDR_BITLEN_INVALID = 5,
	NIP_ADDR_UNKNOWN,
};

#define NIP_TRUE 1
#define NIP_FALSE 0

/* Short address range:
 * 【1-byte】0 ~ 220
 * 00 ~ DC
 */
static inline int is_1byte_addr_flag(unsigned char first_byte)
{
	return first_byte <= ADDR_FIRST_DC ? NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【2-byte】221 ~ 5119
 * DD/DE/.../F0 is a 2-byte address descriptor followed by the address value
 * DDDD ~ DDFF : 221 ~ 255
 * DE00 ~ DEFF : 256 ~ 511
 * DF00 ~ DFFF : 512 ~ 767
 * ...
 * F000 ~ F0FF : 4864 ~ 5119
 */
static inline int is_2byte_addr_flag(unsigned char first_byte)
{
	return (first_byte > ADDR_FIRST_DC) && (first_byte <= ADDR_FIRST_F0) ?
	       NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【3-byte】5120 ~ 65535
 * F1 is a 3-byte address descriptor followed by the address value
 * F1 1400 ~ F1 FFFF
 */
static inline int is_3byte_addr_flag(unsigned char first_byte)
{
	return first_byte == ADDR_FIRST_F1 ? NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【5-byte】65536 ~ 4,294,967,295
 * F2 is a 5-byte address descriptor followed by the address value
 * F2 0001 0000 ~ F2 FFFF FFFF
 */
static inline int is_5byte_addr_flag(unsigned char first_byte)
{
	return first_byte == ADDR_FIRST_F2 ? NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【7-byte】4,294,967,296 ~ 281,474,976,710,655
 * F3 is a 7-byte address descriptor followed by the address value
 * F3 0001 0000 0000 ~ F3 FFFF FFFF FFFF
 */
static inline int is_7byte_addr_flag(unsigned char first_byte)
{
	return first_byte == ADDR_FIRST_F3 ? NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【8-byte】
 * F4 is a 8-byte address descriptor followed by the address value
 * F400 0000 0000 0000 ~ F4FF FFFF FFFF FFFF
 */
static inline int is_8byte_addr_flag(unsigned char first_byte)
{
	return first_byte == ADDR_FIRST_FE ? NIP_TRUE : NIP_FALSE;
}

/* Short address range:
 * 【public addr】
 * 0xFF00 - The loopback address
 * 0xFF01 - Public address for access authentication
 * 0xFF02 - Public address of access authentication
 * 0xFF03 - The neighbor found a public address
 * 0xFF04 - Address resolution (ARP)
 * 0xFF05 - DHCP public address
 * 0xFF06 - Public address for minimalist access authentication
 * 0xFF07 - Self-organizing protocol public address
 * 0xFF08 - The IEEE EUI - 64 addresses
 * 0xFF09 - any_addr
 */
static inline int is_public_addr_flag(unsigned char first_byte)
{
	return first_byte == ADDR_FIRST_FF ? NIP_TRUE : NIP_FALSE;
}

int is_nip_local_addr(const struct nip_addr *addr)
{
	int result = 0;

	if (addr->bitlen == NIP_ADDR_BIT_LEN_16) {
		if (addr->nip_addr_field16[0] == nip_local_addr.nip_addr_field16[0] &&
		    addr->nip_addr_field16[1] == nip_local_addr.nip_addr_field16[1])
			result = 1;
	}
	return result;
}

/* Short address range:
 * 【1-byte】0 ~ 220
 * 00 ~ DC
 */
static int nip_addr_1byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_1byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_1)
		ret = CURRENT_ADDR_VALID;

	return ret;
}

/* Short address range:
 * 【2-byte】221 ~ 5119
 * DD/DE/.../F0 is a 2-byte address descriptor followed by the address value
 * DDDD ~ DDFF : 221 ~ 255
 * DE00 ~ DEFF : 256 ~ 511
 * DF00 ~ DFFF : 512 ~ 767
 * ...
 * F000 ~ F0FF : 4864 ~ 5119
 */
static int nip_addr_2byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_2byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_2) {
		if (first_byte > ADDR_FIRST_DC + 1 ||
		    second_byte >= ADDR_SECOND_MIN_DD)
			ret = CURRENT_ADDR_VALID;
		else
			ret = ADDR_2BYTE_INVALID;
	}

	return ret;
}

/* Short address range:
 * 【3-byte】5120 ~ 65535
 * F1 is a 3-byte address descriptor followed by the address value
 * F1 1400 ~ F1 FFFF
 */
static int nip_addr_3byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_3byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_3) {
		if (second_byte >= ADDR_SECOND_MIN_F1)
			ret = CURRENT_ADDR_VALID;
		else
			ret = ADDR_3BYTE_INVALID;
	}

	return ret;
}

/* Short address range:
 * 【5-byte】65536 ~ 4,294,967,295
 * F2 is a 5-byte address descriptor followed by the address value
 * F2 0001 0000 ~ F2 FFFF FFFF
 */
static int nip_addr_5byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_5byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_5) {
		if (second_byte > 0 || third_byte >= ADDR_THIRD_MIN_F2)
			ret = CURRENT_ADDR_VALID;
		else
			ret = ADDR_5BYTE_INVALID;
	}

	return ret;
}

/* Short address range:
 * 【7-byte】4,294,967,296 ~ 281,474,976,710,655
 * F3 is a 7-byte address descriptor followed by the address value
 * F3 0001 0000 0000 ~ F3 FFFF FFFF FFFF
 */
static int nip_addr_7byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_7byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_7) {
		if (second_byte > 0 || third_byte >= ADDR_THIRD_MIN_F3)
			ret = CURRENT_ADDR_VALID;
		else
			ret = ADDR_7BYTE_INVALID;
	}

	return ret;
}

/* Short address range:
 * 【8-byte】
 * F4 is a 8-byte address descriptor followed by the address value
 * F400 0000 0000 0000 ~ F4FF FFFF FFFF FFFF
 */
static int nip_addr_8byte_check(unsigned char first_byte, unsigned char second_byte,
				unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_8byte_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_8)
		ret = CURRENT_ADDR_VALID;

	return ret;
}

/* Short address range:
 * 【public addr】
 * 0xFF00 - The loopback address
 * 0xFF01 - Public address for access authentication
 * 0xFF02 - Public address of access authentication
 * 0xFF03 - The neighbor found a public address
 * 0xFF04 - Address resolution (ARP)
 * 0xFF05 - DHCP public address
 * 0xFF06 - Public address for minimalist access authentication
 * 0xFF07 - Self-organizing protocol public address
 * 0xFF08 - The IEEE EUI - 64 addresses
 * 0xFF09 - any_addr
 */
static int nip_addr_public_check(unsigned char first_byte, unsigned char second_byte,
				 unsigned char third_byte, int addr_len)
{
	int ret = NOT_CURRENT_ADDR;

	if (is_public_addr_flag(first_byte) && addr_len == NIP_ADDR_LEN_2)
		ret = CURRENT_ADDR_VALID;

	return ret;
}

static int nip_addr_unknown(unsigned char first_byte, unsigned char second_byte,
			    unsigned char third_byte, int addr_len)
{
	return NIP_ADDR_UNKNOWN;
}

#define CHECK_FUN_MAX 8
static int (*nip_addr_check_fun[CHECK_FUN_MAX])(unsigned char first_byte,
						unsigned char second_byte,
						unsigned char third_byte,
						int addr_len) = {
	nip_addr_1byte_check,
	nip_addr_2byte_check,
	nip_addr_3byte_check,
	nip_addr_5byte_check,
	nip_addr_7byte_check,
	nip_addr_8byte_check,
	nip_addr_public_check,
	nip_addr_unknown,
};

int nip_addr_invalid(const struct nip_addr *addr)
{
	int i;
	int addr_len;
	int ret = NIP_ADDR_UNKNOWN;
	unsigned char first_byte, second_byte, third_byte;

	first_byte = addr->nip_addr_field8[NIP_8BIT_ADDR_INDEX_0];
	second_byte = addr->nip_addr_field8[NIP_8BIT_ADDR_INDEX_1];
	third_byte = addr->nip_addr_field8[NIP_8BIT_ADDR_INDEX_2];
	addr_len = addr->bitlen / NIP_ADDR_BIT_LEN_8;

	/* The value of the field after the effective length of the short address should be 0 */
	for (i = addr_len; i < NIP_8BIT_ADDR_INDEX_MAX; i++) {
		if (addr->nip_addr_field8[i] > 0x00)
			return ADDR_BITLEN_INVALID;
	}

	for (i = 0; i < CHECK_FUN_MAX; i++) {
		ret = nip_addr_check_fun[i](first_byte, second_byte, third_byte, addr_len);
		if (ret == CURRENT_ADDR_VALID)
			return ret;
		else if (ret == NOT_CURRENT_ADDR)
			continue;
		else
			return ret;
	}

	return ret;
}

/* 0xFF00 - The loopback address
 * 0xFF01 - Public address for access authentication
 * 0xFF02 - Public address of access authentication
 * 0xFF03 - The neighbor found a public address
 * 0xFF04 - Address resolution (ARP)
 * 0xFF05 - DHCP public address
 * 0xFF06 - Public address for minimalist access authentication
 * 0xFF07 - Self-organizing protocol public address
 * 0xFF08 - The IEEE EUI - 64 addresses
 * 0xFF09 - any_addr
 */
int nip_addr_public(const struct nip_addr *addr)
{
	if (is_public_addr_flag(addr->nip_addr_field8[NIP_8BIT_ADDR_INDEX_0]) &&
	    addr->bitlen == NIP_ADDR_BIT_LEN_16)
		return 1;
	else
		return 0;
}

/* judge whether the nip_addr is equal to 0xFF09 */
int nip_addr_any(const struct nip_addr *addr)
{
	int result = 0;

	if (addr->bitlen == NIP_ADDR_BIT_LEN_16) {
		if (addr->nip_addr_field16[0] == nip_any_addr.nip_addr_field16[0] &&
		    addr->nip_addr_field16[1] == nip_any_addr.nip_addr_field16[1])
			result = 1;
	}
	return result;
}

int get_nip_addr_len(const struct nip_addr *addr)
{
	int len = 0;
	unsigned char first_byte = addr->nip_addr_field8[0];

	if (is_1byte_addr_flag(first_byte))
		len = NIP_ADDR_LEN_1;
	else if (is_2byte_addr_flag(first_byte) || is_public_addr_flag(first_byte))
		len = NIP_ADDR_LEN_2;
	else if (is_3byte_addr_flag(first_byte))
		len = NIP_ADDR_LEN_3;
	else if (is_5byte_addr_flag(first_byte))
		len = NIP_ADDR_LEN_5;
	else if (is_7byte_addr_flag(first_byte))
		len = NIP_ADDR_LEN_7;
	else if (is_8byte_addr_flag(first_byte))
		len = NIP_ADDR_LEN_8;

	return len;
}

unsigned char *build_nip_addr(const struct nip_addr *addr, unsigned char *buf)
{
	int i;
	unsigned char *p = buf;
	int addr_len = get_nip_addr_len(addr);

	if (addr_len == 0)
		return 0;

	for (i = 0; i < addr_len; i++) {
		*p = addr->nip_addr_field8[i];
		p++;
	}

	return p;
}

unsigned char *decode_nip_addr(unsigned char *buf, struct nip_addr *addr)
{
	int i;
	int ret;
	int addr_len;
	unsigned char *p = buf;

	addr->nip_addr_field8[0] = *p;
	addr_len = get_nip_addr_len(addr);
	if (addr_len == 0)
		return 0;

	for (i = 0; i < addr_len; i++) {
		addr->nip_addr_field8[i] = *p;
		p++;
	}
	addr->bitlen = addr_len * NIP_ADDR_BIT_LEN_8;

	ret = nip_addr_invalid(addr);
	if (ret)
		return 0;

	return p;
}

