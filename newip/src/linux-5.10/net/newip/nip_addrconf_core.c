// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP library code, needed by static components when full NewIP support is
 * not configured or static.
 *
 * Based on net/ipv6/addrconf_core.c
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/nip.h>
#include <net/nip_addrconf.h>
#include <net/ip.h>
#include <linux/export.h>
#include "tcp_nip_parameter.h"

static void nin_dev_finish_destroy_rcu(struct rcu_head *head)
{
	struct ninet_dev *idev = container_of(head, struct ninet_dev, rcu);

	kfree(idev);
}

void nin_dev_finish_destroy(struct ninet_dev *idev)
{
	struct net_device *dev = idev->dev;

	WARN_ON(!list_empty(&idev->addr_list));

	dev_put(dev);
	if (idev->dead)
		call_rcu(&idev->rcu, nin_dev_finish_destroy_rcu);
}

