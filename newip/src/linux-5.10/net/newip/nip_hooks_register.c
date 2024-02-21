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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/hck/lite_hck_inet.h>
#include <linux/netdevice.h>
#include <net/ninet_hashtables.h>      /* ninet_ehashfn */
#include <net/if_ninet.h>
#include "tcp_nip_parameter.h"

/* call the newip hook function in sk_ehashfn function (net\ipv4\inet_hashtables.c):
 */
void nip_ninet_ehashfn(const struct sock *sk, u32 *ret)
{
	if (!sk || !ret)
		return;

	*ret = ninet_ehashfn(sock_net(sk), &sk->SK_NIP_RCV_SADDR,
			     sk->sk_num, &sk->SK_NIP_DADDR, sk->sk_dport);
}

/* call the newip hook function in inet_gifconf function (net\ipv4\devinet.c):
 */
void nip_ninet_gifconf(struct net_device *dev,
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

void nip_ninet_ehashfn_lhck_register(void)
{
	REGISTER_HCK_LITE_HOOK(nip_ninet_ehashfn_lhck, nip_ninet_ehashfn);
}

void nip_ninet_gifconf_lhck_register(void)
{
	REGISTER_HCK_LITE_HOOK(nip_ninet_gifconf_lhck, nip_ninet_gifconf);
}

int __init ninet_hooks_init(void)
{
	nip_ninet_ehashfn_lhck_register();
	nip_ninet_gifconf_lhck_register();
	return 0;
}

void __exit ninet_hooks_exit(void)
{
}

module_init(ninet_hooks_init);
module_exit(ninet_hooks_exit);

#endif /* CONFIG_NEWIP_HOOKS */

