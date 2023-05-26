/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Definitions for the structure
 * associated with NewIP route.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
 */
#ifndef _NEWIP_ROUTE_H
#define _NEWIP_ROUTE_H

#include "nip.h"

struct nip_rtmsg {
	struct nip_addr rtmsg_dst;
	struct nip_addr rtmsg_src;
	struct nip_addr rtmsg_gateway;
	char dev_name[10];
	unsigned int rtmsg_type;
	int rtmsg_ifindex;
	unsigned int rtmsg_metric;
	unsigned long rtmsg_info;
	unsigned int rtmsg_flags;
};

#endif /* _NEWIP_ROUTE_H */
