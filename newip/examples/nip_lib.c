// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/if.h>  /* struct ifreq depend */

#include "nip_uapi.h"
#include "nip_lib.h"

#define ADDR_STR_LEN 2
#define STR_FMT_1    55
#define STR_FMT_2    87

int32_t nip_get_ifindex(const char *ifname, int *ifindex)
{
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	fd = socket(AF_NINET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("creat socket fail, ifname=%s\n", ifname);
		return -1;
	}
	if ((ioctl(fd, SIOCGIFINDEX, &ifr)) < 0) {
		printf("get ifindex fail, ifname=%s\n", ifname);
		close(fd);
		return -1;
	}
	close(fd);

	printf("%s ifindex=%u\n", ifname, ifr.ifr_ifindex);
	*ifindex = ifr.ifr_ifindex;
	return 0;
}

int nip_addr_fmt(char *addr_str, struct nip_addr *sap, int addrlen_input)
{
	unsigned char first_byte;
	int addrlen, i;

	memset(sap, 0, sizeof(struct nip_addr));
	for (i = 0; i < INDEX_MAX; i++) {
		if (addr_str[i] == 0)
			break;

		/* 0 ~ 9 = 48 ~ 57,  '0'构造成 0  = 48 - 48 */
		if (addr_str[i] >= '0' && addr_str[i] <= '9') {
			addr_str[i] = addr_str[i] - '0';
		/* A ~ F = 65 ~ 70,  'A'构造成 10 = 65 - 55 */
		} else if (addr_str[i] >= 'A' && addr_str[i] <= 'F') {
			addr_str[i] = addr_str[i] - STR_FMT_1;
		/* a ~ f = 97 ~ 102, 'a'构造成 10 = 97 - 87 */
		} else if (addr_str[i] >= 'a' && addr_str[i] <= 'f') {
			addr_str[i] = addr_str[i] - STR_FMT_2;
		} else {
			printf("Newip addr error: uaddr[%d]=%c\n", i, addr_str[i]);
			return 1;
		}
	}

	first_byte = addr_str[0] << NIP_ADDR_LEN_4;
	first_byte += addr_str[1];
	if (first_byte <= ADDR_FIRST_DC)
		addrlen = NIP_ADDR_LEN_1;
	else if (first_byte <= ADDR_FIRST_F0 || first_byte == ADDR_FIRST_FF)
		addrlen = NIP_ADDR_LEN_2;
	else if (first_byte == ADDR_FIRST_F1)
		addrlen = NIP_ADDR_LEN_3;
	else if (first_byte == ADDR_FIRST_F2)
		addrlen = NIP_ADDR_LEN_5;
	else if (first_byte == ADDR_FIRST_F3)
		addrlen = NIP_ADDR_LEN_7;
	else if (first_byte == ADDR_FIRST_FE)
		addrlen = NIP_ADDR_LEN_8;
	else
		addrlen = 0;

	if (addrlen_input != addrlen) {
		printf("Newip addr error, first_byte=0x%x\n", first_byte);
		return 1;
	}

	sap->bitlen = addrlen * NIP_ADDR_LEN_8;
	printf("*************************************************\n");
	printf("Newip addr len=%d\n", addrlen);
	for (i = 0; i < addrlen; i++) {
		sap->nip_addr_field8[i] = addr_str[i * INDEX_2] << INDEX_4;
		sap->nip_addr_field8[i] += addr_str[i * INDEX_2 + 1];
		printf("%02x ", sap->nip_addr_field8[i]);
	}
	printf("\n*************************************************\n\n");

	return 0;
}

int nip_get_addr(char **args, struct nip_addr *addr)
{
	unsigned int len;
	char *sp = *args;
	int addrlen_input = 0;
	__u8 addr_str[INDEX_MAX] = {0};

	while (*sp != '\0') {
		addrlen_input += 1;
		sp++;
	}

	if (addrlen_input % ADDR_STR_LEN != 0) {
		printf("NewIP addr str-len invalid, addrlen_input=%d\n", addrlen_input);
		return -1;
	}

	len = strlen(*args);
	if (!len || len >= (INDEX_MAX - 1))
		return -1;
	memcpy(addr_str, *args, len);
	addr_str[len + 1] = '\0';

	return nip_addr_fmt(addr_str, addr, addrlen_input / ADDR_STR_LEN);
}

