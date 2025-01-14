// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of configuring NewIP route.
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
#include <linux/route.h>

#include "nip_uapi.h"
#include "nip_lib.h"
#include "newip_route.h"

/* get ifindex based on the device name
 * struct ifreq ifr;
 * struct nip_ifreq ifrn;
 * ioctl(fd, SIOGIFINDEX, &ifr);
 * ifr.ifr_ifindex; ===> ifindex
 */
static int nip_route_add(int ifindex, const struct nip_addr *dst_addr,
		  const struct nip_addr *gateway_addr, __u8 gateway_flag, int opt)
{
	int fd, ret;
	struct nip_rtmsg rt;

	fd = socket(AF_NINET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&rt, 0, sizeof(rt));
	rt.rtmsg_ifindex = ifindex;
	rt.rtmsg_flags = RTF_UP;
	rt.rtmsg_dst = *dst_addr;

	if (gateway_flag) {
		rt.rtmsg_gateway = *gateway_addr;
		rt.rtmsg_flags |= RTF_GATEWAY;
	}

	ret = ioctl(fd, (unsigned long)opt, &rt);
	if (ret < 0 && errno != EEXIST) { // ignore File Exists error
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static void cmd_help(void)
{
	/* nip_route add 02   wlan0
	 * (配置目的地址02设备路由，出口是wlan0)
	 * nip_route add 02   wlan0 03
	 * (配置目的地址02设备路由，出口是wlan0，网关地址是03)
	 * nip_route add ff09 wlan0 03
	 * (配置广播默认路由，      出口是wlan0，网关地址是03)
	 */
	printf("\n[cmd example]\n");
	printf("nip_route { add | del } <dst-addr> <netcard-name>\n");
	printf("nip_route { add | del } <dst-addr> <netcard-name> <gateway-addr>\n");
}

static int parse_name(char **argv, int *ifindex, char *dev)
{
	size_t len = strlen(*argv);

	memset(dev, 0, ARRAY_LEN);
	if (len >= (ARRAY_LEN - 1) || !len)
		return -1;
	memcpy(dev, *argv, len);
	dev[len + 1] = '\0';

	if (strncmp(dev, NIC_NAME_CHECK, strlen(NIC_NAME_CHECK))) {
		printf("unsupport addr cfg cmd-3, cmd=%s\n", dev);
		cmd_help();
		return -1;
	}
	return nip_get_ifindex(dev, ifindex);
}

static int parse_cmd(char **argv, int *opt)
{
	size_t len = strlen(*argv);
	char cmd[ARRAY_LEN];

	memset(cmd, 0, ARRAY_LEN);
	if (!len || len >= (ARRAY_LEN - 1))
		return -1;
	memcpy(cmd, *argv, len);
	cmd[len + 1] = '\0';

	if (!strncmp(cmd, CMD_ADD, strlen(CMD_ADD))) {
		*opt = SIOCADDRT;
	} else if (!strncmp(cmd, CMD_DEL, strlen(CMD_DEL))) {
		*opt = SIOCDELRT;
	} else {
		printf("unsupport route cfg cmd-1, cmd=%s\n", cmd);
		cmd_help();
		return -1;
	}
	return 0;
}

static int parse_args(char **argv, int *opt, __u8 *gateway_flag, int *ifindex,
	       struct nip_addr *dst_addr, struct nip_addr *gateway_addr, char *dev, int argc)
{
	/* 配置参数1解析: { add | del } */
	int ret;

	argv++;
	ret = parse_cmd(argv, opt);
	if (ret != 0)
		return -1;

	/* 配置参数2解析: <dst-addr> */
	argv++;
	if (nip_get_addr(argv, dst_addr)) {
		printf("unsupport route cfg cmd-2\n");
		cmd_help();
		return -1;
	}

	/* 配置参数3解析: <netcard-name> */
	argv++;
	ret = parse_name(argv, ifindex, dev);
	if (ret != 0)
		return -1;

	/* 配置参数4解析: <gateway-addr> */
	if (argc == DEMO_INPUT_4) {
		argv++;
		if (nip_get_addr(argv, gateway_addr)) {
			printf("unsupport route cfg cmd-4\n");
			cmd_help();
			return -1;
		}
		*gateway_flag = 1;
	}
	return ret;
}

int main(int argc, char **argv_input)
{
	int ret;
	int opt;
	int ifindex = 0;
	__u8 gateway_flag = 0;
	char **argv = argv_input;
	char dev[ARRAY_LEN];
	struct nip_addr dst_addr = {0};
	struct nip_addr gateway_addr = {0};

	if (argc != DEMO_INPUT_3 && argc != DEMO_INPUT_4) {
		printf("unsupport route cfg input, argc=%d\n", argc);
		cmd_help();
		return -1;
	}

	ret = parse_args(argv, &opt, &gateway_flag, &ifindex,
			 &dst_addr, &gateway_addr, dev, argc);
	if (ret != 0)
		return -1;

	ret = nip_get_ifindex(dev, &ifindex);
	if (ret != 0) {
		printf("get %s ifindex fail, ret=%d\n", dev, ret);
		return -1;
	}

	ret = nip_route_add(ifindex, &dst_addr, &gateway_addr, gateway_flag, opt);
	if (ret != 0) {
		printf("get %s ifindex fail, ret=%d\n", dev, ret);
		return -1;
	}

	printf("%s (ifindex=%d) cfg route success\n", dev, ifindex);
	return 0;
}

