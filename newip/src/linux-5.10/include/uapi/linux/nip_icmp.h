/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Definitions for the NewIP ICMP protocol.
 *
 * Based on include/uapi/linux/icmp.h
 */
#ifndef _UAPI_LINUX_NIP_ICMP_H
#define _UAPI_LINUX_NIP_ICMP_H

#include <asm/byteorder.h>
#include <linux/types.h>

struct nip_icmp_hdr {
	__u8 nip_icmp_type;
	__u8 nip_icmp_code;
	__sum16 nip_icmp_cksum;
};

#endif
