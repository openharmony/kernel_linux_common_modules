/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */
#ifndef _NIP_LIB_H
#define _NIP_LIB_H

/* AF_NINET by reading/sys/module/newip/parameters/af_ninet file to get the type value */
#define AF_NINET 45

#define DEMO_INPUT_1  2  /* The DEMO program contains one parameter */
#define DEMO_INPUT_2  3
#define DEMO_INPUT_3  4
#define DEMO_INPUT_4  5

/* Change the value based on the actual interface */
#define NIC_NAME       "wlan0"
#define NIC_NAME_CHECK "wlan"
#define CMD_ADD        "add"
#define CMD_DEL        "del"

#define BUFLEN          1024
#define LISTEN_MAX      3
#define PKTCNT          10      /* Number of sent packets */
#define PKTLEN          1024    /* Length of sent packet */
#define SLEEP_US        500000  /* Packet sending interval (ms) */
#define SELECT_TIME     600
#define TCP_SERVER_PORT 5556    /* TCP Server Port */
#define UDP_SERVER_PORT 9090    /* UDP Server Port */

#define ARRAY_LEN     255

int nip_get_ifindex(const char *ifname, int *ifindex);
int nip_get_addr(char **args, struct nip_addr *addr);

#endif /* _NIP_LIB_H */
