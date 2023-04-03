/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Based on include/net/addrconf.h
 */
#ifndef _NIP_ADDRCONF_H
#define _NIP_ADDRCONF_H

#include <net/if_ninet.h>
#include <net/nip.h>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>

#define ADDRCONF_NOTIFY_PRIORITY 0
#define NIN_ADDR_HSIZE_SHIFT     (4)
#define NIN_ADDR_HSIZE           (1 << NIN_ADDR_HSIZE_SHIFT)

#define DST_HOST                 0x0001 /* NIP */

int nip_addrconf_add_ifaddr(struct net *net, void __user *arg);
int nip_addrconf_del_ifaddr(struct net *net, void __user *arg);

int nip_dev_get_saddr(struct net *net, const struct net_device *dev,
		      const struct nip_addr *daddr, struct nip_addr *saddr);

int nip_addrconf_init(void);
void nip_addrconf_cleanup(void);
void nip_addr_to_str(const struct nip_addr *addr, unsigned char *buf, int buf_len);

/**
 * __nin_dev_get - get ninet_dev pointer from netdevice
 * @dev: network device
 *
 * Caller must hold rcu_read_lock or RTNL, because this function
 * does not take a reference on the ninet_dev.
 */
static inline struct ninet_dev *__nin_dev_get(const struct net_device *dev)
{
	return rcu_dereference_rtnl(dev->nip_ptr);
}

/**
 * nin_dev_get - get ninet_dev pointer from netdevice
 * @dev: network device
 */
static inline struct ninet_dev *nin_dev_get(const struct net_device *dev)
{
	struct ninet_dev *idev;

	rcu_read_lock();
	idev = rcu_dereference(dev->nip_ptr);
	if (idev)
		refcount_inc(&idev->refcnt);
	rcu_read_unlock();
	return idev;
}

static inline struct neigh_parms *__nin_dev_nd_parms_get_rcu(
	const struct net_device *dev)
{
	struct ninet_dev *idev = __nin_dev_get(dev);

	return idev ? idev->nd_parms : NULL;
}

void nin_dev_finish_destroy(struct ninet_dev *idev);

static inline void nin_dev_put(struct ninet_dev *idev)
{
	if (refcount_dec_and_test(&idev->refcnt))
		nin_dev_finish_destroy(idev);
}

static inline void nin_dev_put_clear(struct ninet_dev **pidev)
{
	struct ninet_dev *idev = *pidev;

	if (idev) {
		nin_dev_put(idev);
		*pidev = NULL;
	}
}

static inline void __nin_dev_put(struct ninet_dev *idev)
{
	refcount_dec(&idev->refcnt);
}

static inline void nin_dev_hold(struct ninet_dev *idev)
{
	refcount_inc(&idev->refcnt);
}

void ninet_ifa_finish_destroy(struct ninet_ifaddr *ifp);

static inline void nin_ifa_put(struct ninet_ifaddr *ifp)
{
	if (refcount_dec_and_test(&ifp->refcnt))
		ninet_ifa_finish_destroy(ifp);
}

static inline void __nin_ifa_put(struct ninet_ifaddr *ifp)
{
	refcount_dec(&ifp->refcnt);
}

static inline void nin_ifa_hold(struct ninet_ifaddr *ifp)
{
	refcount_inc(&ifp->refcnt);
}

#endif
