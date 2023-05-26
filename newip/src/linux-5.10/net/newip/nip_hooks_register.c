// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Definitions for the NewIP Hooks
 * Register module.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-20
 */
#ifdef CONFIG_NEWIP_HOOKS
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/ninet_hashtables.h>      /* ninet_ehashfn */
#include <net/if_ninet.h>
#include <trace/hooks/inet.h>
#include "tcp_nip_parameter.h"

void vendor_ninet_ehashfn(void *data, const struct sock *sk, u32 *ret)
{
	*ret = ninet_ehashfn(sock_net(sk), &sk->sk_nip_rcv_saddr,
			     sk->sk_num, &sk->sk_nip_daddr, sk->sk_dport);
}

void vendor_ninet_gifconf(void *data, struct net_device *dev,
			  char __user *buf, int len, int size, int *ret)
{
	if (*ret >= 0) {
		int done = ninet_gifconf(dev, buf + *ret, len - *ret, size);

		if (done < 0)
			*ret = done;
		else
			*ret += done;
	}
}

int ninet_hooks_register(void)
{
	int ret;

	ret = register_trace_vendor_ninet_ehashfn(&vendor_ninet_ehashfn, NULL);
	if (ret) {
		nip_dbg("failed to register to vendor_ninet_ehashfn");
		return -1;
	}

	ret = register_trace_vendor_ninet_gifconf(&vendor_ninet_gifconf, NULL);
	if (ret) {
		nip_dbg("failed to register to vendor_ninet_gifconf");
		return -1;
	}

	return 0;
}
#endif /* CONFIG_NEWIP_HOOKS */

