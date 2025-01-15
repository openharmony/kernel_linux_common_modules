// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of configuring NewIP address.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
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
static int nip_add_addr(int ifindex, const struct nip_addr *addr, int opt)
{
	int fd, ret;
	struct nip_ifreq ifrn;

	fd = socket(AF_NINET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifrn, 0, sizeof(ifrn));
	ifrn.ifrn_addr = *addr;
	ifrn.ifrn_ifindex = ifindex;

	ret = ioctl(fd, (unsigned long)opt, &ifrn);
	if (ret < 0 && errno != EEXIST) { // ignore File Exists error
		printf("cfg newip addr fail, ifindex=%d, opt=%d, ret=%d.\n", ifindex, opt, ret);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static void cmd_help(void)
{
	/* nip_addr wlan0 add 01 (在wlan0上配置地址01) */
	/* nip_addr wlan0 del 01 (在wlan0上删除地址01) */
	printf("[cmd example] nip_addr <netcard-name> { add | del } <addr>\n");
}

static int parse_name(char **argv, int *ifindex, char *dev)
{
	size_t len = strlen(*argv);

	memset(dev, 0, ARRAY_LEN);
	if (!len || len >= (ARRAY_LEN - 1))
		return -1;
	memcpy(dev, *argv, len);
	dev[len + 1] = '\0';

	if (strncmp(dev, NIC_NAME_CHECK, strlen(NIC_NAME_CHECK))) {
		printf("unsupport addr cfg cmd-1, cmd=%s\n", dev);
		cmd_help();
		return -1;
	}
	return nip_get_ifindex(dev, ifindex);
}

static int parse_cmd(char **argv, int *opt)
{
	char cmd[ARRAY_LEN];
	size_t len = strlen(*argv);

	memset(cmd, 0, ARRAY_LEN);
	if (!len || len >= (ARRAY_LEN - 1))
		return -1;
	memcpy(cmd, *argv, len);
	cmd[len + 1] = '\0';

	if (!strncmp(cmd, CMD_ADD, strlen(CMD_ADD))) {
		*opt = SIOCSIFADDR;
	} else if (!strncmp(cmd, CMD_DEL, strlen(CMD_DEL))) {
		*opt = SIOCDIFADDR;
	} else {
		printf("unsupport addr cfg cmd-2, cmd=%s\n", cmd);
		cmd_help();
		return -1;
	}
	return 0;
}

int main(int argc, char **argv_input)
{
	char dev[ARRAY_LEN];
	int ret;
	int opt;
	int ifindex = 0;
	char **argv = argv_input;
	struct nip_addr addr = {0};

	if (argc != DEMO_INPUT_3) {
		printf("unsupport addr cfg input, argc=%d\n", argc);
		cmd_help();
		return -1;
	}

	/* 配置参数1解析: <netcard-name> */
	argv++;
	ret = parse_name(argv, &ifindex, dev);
	if (ret != 0)
		return -1;

	/* 配置参数2解析: { add | del } */
	argv++;
	ret = parse_cmd(argv, &opt);
	if (ret != 0)
		return -1;

	/* 配置参数3解析: <addr> */
	argv++;
	if (nip_get_addr(argv, &addr)) {
		printf("unsupport addr cfg cmd-3\n");
		cmd_help();
		return 1;
	}

	ret = nip_add_addr(ifindex, &addr, opt);
	if (ret != 0)
		return -1;

	printf("%s (ifindex=%d) cfg addr success\n", dev, ifindex);
	return 0;
}

