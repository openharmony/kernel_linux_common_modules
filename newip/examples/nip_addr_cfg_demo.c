// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of configuring NewIP address.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-18
 */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "nip_uapi.h"
#include "nip_lib.h"

/* get ifindex based on the device name
 * struct ifreq ifr;
 * struct nip_ifreq ifrn;
 * ioctl(fd, SIOGIFINDEX, &ifr);
 * ifr.ifr_ifindex; ===> ifindex
 */
int nip_add_addr(int ifindex, const unsigned char *addr, unsigned char addr_len)
{
	int fd, ret;
	struct nip_ifreq ifrn;

	fd = socket(AF_NINET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifrn, 0, sizeof(ifrn));
	ifrn.ifrn_addr.bitlen = addr_len * BITS_PER_BYTE; // Byte length is converted to bit length
	memcpy(ifrn.ifrn_addr.nip_addr_field8, addr, addr_len);
	ifrn.ifrn_ifindex = ifindex;

	ret = ioctl(fd, SIOCSIFADDR, &ifrn);
	if (ret < 0 && errno != EEXIST) { // ignore File Exists error
		printf("cfg newip addr fail, ifindex=%d, ret=%d\n", ifindex, ret);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/* Before executing the use case, run ifconfig XXX up.
 * XXX indicates the NIC name, for example, eth0 and wlan0
 */
int main(int argc, char **argv)
{
	int ifindex = 0;
	int ret;
	unsigned char client_addr[INDEX_1] = {0x50};       // 1-byte address of the client: 0x50
	unsigned char server_addr[INDEX_2] = {0xDE, 0x00}; // 2-byte address of the server: 0xDE00
	unsigned char *addr;
	unsigned char addr_len;

	if (argc == DEMO_INPUT_1) {
		if (!strcmp(*(argv + 1), "server")) {
			printf("server cfg addr=0x%02x%02x\n",
			       server_addr[INDEX_0], server_addr[INDEX_1]);
			addr = server_addr;
			addr_len = sizeof(server_addr);
		} else if (!strcmp(*(argv + 1), "client")) {
			printf("client cfg addr=0x%02x\n", client_addr[INDEX_0]);
			addr = client_addr;
			addr_len = sizeof(client_addr);
		} else {
			printf("invalid addr cfg input\n");
			return -1;
		}
	} else {
		printf("unsupport addr cfg input\n");
		return -1;
	}

	ret = nip_get_ifindex(NIC_NAME, &ifindex);
	if (ret != 0)
		return -1;

	ret = nip_add_addr(ifindex, addr, addr_len);
	if (ret != 0)
		return -1;

	printf("%s %s(ifindex=%d) cfg addr success\n", *argv, NIC_NAME, ifindex);
	return 0;
}

