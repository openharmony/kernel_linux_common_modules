// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv6/addrconf.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 *	Changes:
 *
 *	Janos Farkas			:	delete timer on ifdown
 *	<chexum@bankinf.banki.hu>
 *	Andi Kleen			:	kill double kfree on module
 *						unload.
 *	Maciej W. Rozycki		:	FDDI support
 *	sekiya@USAGI			:	Don't send too many RS
 *						packets.
 *	yoshfuji@USAGI			:       Fixed interval between DAD
 *						packets.
 *	YOSHIFUJI Hideaki @USAGI	:	improved accuracy of
 *						address validation timer.
 *	YOSHIFUJI Hideaki @USAGI	:	Privacy Extensions (RFC3041)
 *						support.
 *	Yuji SEKIYA @USAGI		:	Don't assign a same IPv6
 *						address on a same interface.
 *	YOSHIFUJI Hideaki @USAGI	:	ARCnet support
 *	YOSHIFUJI Hideaki @USAGI	:	convert /proc/net/if_inet6 to
 *						seq_file.
 *	YOSHIFUJI Hideaki @USAGI	:	improved source address
 *						selection; consider scope,
 *						status etc.
 *
 * NewIP Address [auto]configuration
 * Linux NewIP INET implementation
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>

#include <linux/netdevice.h>
#include <linux/route.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/hash.h>
#include <linux/proc_fs.h>

#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/nip.h>
#include <net/protocol.h>
#include <net/ndisc.h>
#include <net/nip_route.h>
#include <net/nip_addrconf.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/addrconf.h>
#include <linux/rtnetlink.h>
#include <linux/export.h>

#include "nip_hdr.h"
#include "tcp_nip_parameter.h"

#define	INFINITY_LIFE_TIME	0xFFFFFFFF

/* Configured unicast address hash table */
static struct hlist_head ninet_addr_lst[NIN_ADDR_HSIZE];
static DEFINE_SPINLOCK(addrconf_hash_lock);

static bool nip_chk_same_addr(struct net *net, const struct nip_addr *addr,
			      const struct net_device *dev);
static int nip_get_firstaddr(const struct net_device *dev,
			     struct nip_addr *addr);
static int nip_addrconf_ifdown(struct net_device *dev, bool unregister);

static struct nip_devconf newip_devconf_dflt __read_mostly = {
	.forwarding = 0,
	.mtu = NIP_MIN_MTU,
	.disable_nip = 0,
	.ignore_routes_with_linkdown = 0,
};

/* Check if link is ready: is it up and is a valid qdisc available */
static inline bool nip_addrconf_link_ready(const struct net_device *dev)
{
	return netif_oper_up(dev) && !qdisc_tx_is_noop(dev);
}

static void nip_link_dev_addr(struct ninet_dev *idev, struct ninet_ifaddr *ifp)
{
	list_add_tail(&ifp->if_list, &idev->addr_list);
}

static u32 ninet_addr_hash(const struct nip_addr *addr)
{
	return hash_32(nip_addr_hash(addr), NIN_ADDR_HSIZE_SHIFT);
}

static struct ninet_ifaddr *nip_add_addr(struct ninet_dev *idev,
					 const struct nip_addr *addr,
					 u32 flags, u32 valid_lft,
					 u32 preferred_lft)
{
	struct ninet_ifaddr *ifa = NULL;
	struct nip_rt_info *rt = NULL;
	unsigned int hash;
	int err = 0;

	rcu_read_lock_bh();

	nin_dev_hold(idev);

	if (idev->dead) {
		err = -ENODEV;
		goto rcu_lock_out;
	}

	if (!netif_running(idev->dev)) {
		nip_dbg("network interface is not running");
		err = -ENODEV;
		goto rcu_lock_out;
	}

	if (idev->cnf.disable_nip) {
		err = -EACCES;
		goto rcu_lock_out;
	}

	spin_lock(&addrconf_hash_lock);

	/* Do not configure two same addresses in a netdevice */
	if (nip_chk_same_addr(dev_net(idev->dev), addr, idev->dev)) {
		nip_dbg("already assigned");
		err = -EEXIST;
		goto spin_lock_out;
	}

	ifa = kzalloc(sizeof(*ifa), GFP_ATOMIC);
	if (!ifa) {
		/* If you add log here, there will be an alarm:
		 * WARNING: Possible unnecessary 'out of memory' message
		 */
		err = -ENOBUFS;
		goto spin_lock_out;
	}

	rt = nip_addrconf_dst_alloc(idev, addr);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto spin_lock_out;
	}

	neigh_parms_data_state_setall(idev->nd_parms);

	ifa->addr = *addr;

	spin_lock_init(&ifa->lock);
	INIT_HLIST_NODE(&ifa->addr_lst);
	ifa->flags = flags;
	ifa->valid_lft = valid_lft;
	ifa->preferred_lft = preferred_lft;
	ifa->tstamp = jiffies;
	ifa->cstamp = ifa->tstamp;

	ifa->rt = rt;

	ifa->idev = idev;
	refcount_set(&ifa->refcnt, 1);

	/* Add to big hash table */
	hash = ninet_addr_hash(addr);

	hlist_add_head_rcu(&ifa->addr_lst, &ninet_addr_lst[hash]);
	spin_unlock(&addrconf_hash_lock);

	write_lock(&idev->lock);
	/* Add to ninet_dev unicast addr list. */
	nip_link_dev_addr(idev, ifa);

	nin_ifa_hold(ifa);
	write_unlock(&idev->lock);

rcu_lock_out:
	rcu_read_unlock_bh();

	if (likely(err == 0)) {
		char add_addr[NIP_ADDR_BIT_LEN_MAX] = {0};

		nip_addr_to_str(addr, add_addr, NIP_ADDR_BIT_LEN_MAX);
		nip_dbg("success, %s ifindex=%u (addr=%s, idev->refcnt=%u, ifa->refcnt=%u)",
			idev->dev->name, idev->dev->ifindex, add_addr,
			refcount_read(&idev->refcnt), refcount_read(&ifa->refcnt));
	} else {
		kfree(ifa);
		nin_dev_put(idev);
		ifa = ERR_PTR(err);
	}

	return ifa;
spin_lock_out:
	spin_unlock(&addrconf_hash_lock);
	goto rcu_lock_out;
}

static struct ninet_dev *nip_add_dev(struct net_device *dev)
{
	struct ninet_dev *ndev;
	int err = -ENOMEM;

	ASSERT_RTNL();

	if (dev->mtu < NIP_MIN_MTU)
		return ERR_PTR(-EINVAL);

	ndev = kzalloc(sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return ERR_PTR(err);

	rwlock_init(&ndev->lock);
	ndev->dev = dev;
	INIT_LIST_HEAD(&ndev->addr_list);
	memcpy(&ndev->cnf, dev_net(dev)->newip.devconf_dflt, sizeof(ndev->cnf));

	ndev->cnf.mtu = dev->mtu;
	ndev->nd_parms = neigh_parms_alloc(dev, &nnd_tbl);
	if (!ndev->nd_parms) {
		kfree(ndev);
		return ERR_PTR(err);
	}

	/* We refer to the device */
	dev_hold(dev);

	refcount_set(&ndev->refcnt, 1);

	nip_dbg("init ninet_dev success, set ndev->refcnt=1");

	if (netif_running(dev) && nip_addrconf_link_ready(dev))
		ndev->if_flags |= IF_READY;

	/* protected by rtnl_lock */
	rcu_assign_pointer(dev->nip_ptr, ndev);
	return ndev;
}

static struct ninet_dev *nip_find_idev(struct net_device *dev)
{
	struct ninet_dev *idev;

	ASSERT_RTNL();

	idev = __nin_dev_get(dev);
	if (!idev) {
		idev = nip_add_dev(dev);
		if (IS_ERR(idev))
			return NULL;
	}
	return idev;
}

static struct ninet_dev *nip_addrconf_add_dev(struct net_device *dev)
{
	struct ninet_dev *idev;

	ASSERT_RTNL();

	idev = nip_find_idev(dev);
	if (!idev)
		return ERR_PTR(-ENOBUFS);

	if (idev->cnf.disable_nip)
		return ERR_PTR(-EACCES);

	return idev;
}

/* Manual configuration of address on an interface */
static int ninet_addr_add(struct net *net, int ifindex,
			  const struct nip_addr *pfx,
			  __u32 ifa_flags, __u32 preferred_lft, __u32 valid_lft)
{
	struct ninet_ifaddr *ifp;
	struct ninet_dev *idev;
	struct net_device *dev;
	unsigned long timeout;
	__u32 ifa_flags_tmp = ifa_flags;
	__u32 valid_lft_tmp = valid_lft;

	ASSERT_RTNL();

	/* check the lifetime */
	if (!valid_lft_tmp || preferred_lft > valid_lft_tmp)
		return -EINVAL;

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	idev = nip_addrconf_add_dev(dev);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	timeout = addrconf_timeout_fixup(valid_lft_tmp, HZ);
	if (addrconf_finite_timeout(timeout))
		valid_lft_tmp = timeout;
	else
		ifa_flags_tmp |= IFA_F_PERMANENT;

	timeout = addrconf_timeout_fixup(preferred_lft, HZ);
	if (addrconf_finite_timeout(timeout)) {
		if (timeout == 0)
			ifa_flags_tmp |= IFA_F_DEPRECATED;
		preferred_lft = timeout;
	}

	ifp = nip_add_addr(idev, pfx, ifa_flags_tmp,
			   valid_lft_tmp,
			   preferred_lft);
	if (!IS_ERR(ifp)) {
		nin_ifa_put(ifp);
		nip_ins_rt(ifp->rt);
		nip_dbg("success, ifp->refcnt=%u", refcount_read(&ifp->refcnt));
		return 0;
	}

	return PTR_ERR(ifp);
}

/* Nobody refers to this ifaddr, destroy it */
void ninet_ifa_finish_destroy(struct ninet_ifaddr *ifp)
{
	WARN_ON(!hlist_unhashed(&ifp->addr_lst));

	nip_dbg("before idev put. idev->refcnt=%u", refcount_read(&ifp->idev->refcnt));
	nin_dev_put(ifp->idev);
	nip_rt_put(ifp->rt);
	kfree_rcu(ifp, rcu);
}

static void nip_del_addr(struct ninet_ifaddr *ifp)
{
	int state;

	ASSERT_RTNL();

	spin_lock_bh(&ifp->lock);
	state = ifp->state;
	ifp->state = NINET_IFADDR_STATE_DEAD;
	spin_unlock_bh(&ifp->lock);

	if (state == NINET_IFADDR_STATE_DEAD)
		goto out;

	spin_lock_bh(&addrconf_hash_lock);
	hlist_del_init_rcu(&ifp->addr_lst);
	spin_unlock_bh(&addrconf_hash_lock);

	write_lock_bh(&ifp->idev->lock);

	list_del_init(&ifp->if_list);
	__nin_ifa_put(ifp);

	write_unlock_bh(&ifp->idev->lock);

	if (ifp->rt) {
		/* If the ifp - & gt; Rt does not belong to any NIP_FIB_node.
		 * The DST reference count does not change
		 */
		if (dst_hold_safe(&ifp->rt->dst))
			nip_del_rt(ifp->rt);
	}

out:
	nin_ifa_put(ifp);
}

static int ninet_addr_del(struct net *net, int ifindex, u32 ifa_flags,
			  const struct nip_addr *pfx)
{
	struct ninet_ifaddr *ifp;
	struct ninet_dev *idev;
	struct net_device *dev;

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	idev = __nin_dev_get(dev);
	if (!idev)
		return -ENXIO;

	read_lock_bh(&idev->lock);
	list_for_each_entry(ifp, &idev->addr_list, if_list) {
		if (nip_addr_eq(pfx, &ifp->addr)) {
			char addr[NIP_ADDR_BIT_LEN_MAX] = {0};

			nin_ifa_hold(ifp);
			read_unlock_bh(&idev->lock);

			nip_addr_to_str(&ifp->addr, addr, NIP_ADDR_BIT_LEN_MAX);
			nip_del_addr(ifp);
			nip_dbg("success, %s ifindex=%u (addr=%s, ifp->refcnt=%u, idev->refcnt=%u)",
				idev->dev->name, ifindex, addr, refcount_read(&ifp->refcnt),
				refcount_read(&idev->refcnt));
			return 0;
		}
	}
	read_unlock_bh(&idev->lock);
	return -EADDRNOTAVAIL;
}

int nip_addrconf_ifaddr_check(struct net *net, void __user *arg, struct nip_ifreq *ireq)
{
	if (copy_from_user(ireq, arg, sizeof(struct nip_ifreq))) {
		nip_dbg("fail to copy cfg data");
		return -EFAULT;
	}

	if (nip_addr_invalid(&ireq->ifrn_addr)) {
		nip_dbg("nip addr invalid, bitlen=%u", ireq->ifrn_addr.bitlen);
		return -EFAULT;
	}

	if (nip_addr_public(&ireq->ifrn_addr)) {
		nip_dbg("The public address cannot be configured");
		return -EFAULT;
	}
	return 0;
}

int nip_addrconf_add_ifaddr(struct net *net, void __user *arg)
{
	struct nip_ifreq ireq;
	int err;

	err = nip_addrconf_ifaddr_check(net, arg, &ireq);
	if (err < 0) {
		nip_dbg("The ifaddr check failed");
		return err;
	}

	rtnl_lock();
	err = ninet_addr_add(net, ireq.ifrn_ifindex, &ireq.ifrn_addr,
			     IFA_F_PERMANENT, INFINITY_LIFE_TIME,
			     INFINITY_LIFE_TIME);
	rtnl_unlock();
	return err;
}

int nip_addrconf_del_ifaddr(struct net *net, void __user *arg)
{
	struct nip_ifreq ireq;
	int err;

	err = nip_addrconf_ifaddr_check(net, arg, &ireq);
	if (err < 0) {
		nip_dbg("The ifaddr check failed");
		return err;
	}

	rtnl_lock();
	err = ninet_addr_del(net, ireq.ifrn_ifindex, 0, &ireq.ifrn_addr);
	rtnl_unlock();
	return err;
}

static bool nip_chk_same_addr(struct net *net, const struct nip_addr *addr,
			      const struct net_device *dev)
{
	unsigned int hash = ninet_addr_hash(addr);
	struct ninet_ifaddr *ifp;

	hlist_for_each_entry(ifp, &ninet_addr_lst[hash], addr_lst) {
		if (!net_eq(dev_net(ifp->idev->dev), net))
			continue;
		if (nip_addr_eq(&ifp->addr, addr)) {
			if (!dev || ifp->idev->dev == dev)
				return true;
		}
	}
	return false;
}

static int __nip_get_firstaddr(struct ninet_dev *idev, struct nip_addr *addr)
{
	struct ninet_ifaddr *ifp;
	int err = -EADDRNOTAVAIL;

	list_for_each_entry(ifp, &idev->addr_list, if_list) {
		*addr = ifp->addr;
		err = 0;
		break;
	}
	return err;
}

static int nip_get_firstaddr(const struct net_device *dev,
			     struct nip_addr *addr)
{
	struct ninet_dev *idev;
	int err = -EADDRNOTAVAIL;

	rcu_read_lock();
	idev = __nin_dev_get(dev);
	if (idev) {
		read_lock_bh(&idev->lock);
		err = __nip_get_firstaddr(idev, addr);
		read_unlock_bh(&idev->lock);
	}
	rcu_read_unlock();
	return err;
}

int nip_dev_get_saddr(struct net *net, const struct net_device *dev,
		      const struct nip_addr *daddr, struct nip_addr *saddr)
{
	if (!dev || !saddr)
		return -EADDRNOTAVAIL;

	return nip_get_firstaddr(dev, saddr);
}

static int nip_addrconf_notify(struct notifier_block *this, unsigned long event,
			       void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct ninet_dev *idev = __nin_dev_get(dev);
	struct net *net = dev_net(dev);

	switch (event) {
	case NETDEV_REGISTER:
		if (!idev && dev->mtu >= NIP_MIN_MTU) {
			nip_dbg("NIP_ADDRCONF(NETDEV_REGISTER): ");
			idev = nip_add_dev(dev);
			if (IS_ERR(idev))
				return notifier_from_errno(PTR_ERR(idev));
		}
		break;

	case NETDEV_CHANGEMTU:
		/* if MTU under NIP_MIN_MTU stop New IP on this interface. */
		if (dev->mtu < NIP_MIN_MTU) {
			nip_addrconf_ifdown(dev, dev != net->loopback_dev);
			break;
		}

		if (idev) {
			idev->cnf.mtu = dev->mtu;
			break;
		}

		/* allocate new idev */
		idev = nip_add_dev(dev);
		if (IS_ERR_OR_NULL(idev))
			break;

		/* device is still not ready */
		if (!(idev->if_flags & IF_READY))
			break;

		fallthrough;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		if (dev->flags & IFF_SLAVE)
			break;

		if (idev && idev->cnf.disable_nip)
			break;

		if (event == NETDEV_UP) {
			if (!nip_addrconf_link_ready(dev)) {
				/* device is not ready yet. */
				nip_dbg("NIP_ADDRCONF(NETDEV_UP)");
				nip_dbg("%s:link is not ready", dev->name);
				break;
			}

			if (!idev && dev->mtu >= NIP_MIN_MTU)
				idev = nip_add_dev(dev);

			if (!IS_ERR_OR_NULL(idev))
				idev->if_flags |= IF_READY;
		} else if (event == NETDEV_CHANGE) {
			if (!nip_addrconf_link_ready(dev))
				/* device is still not ready. */
				break;

			if (idev)
				idev->if_flags |= IF_READY;

			nip_dbg("NIP_ADDRCONF(NETDEV_CHANGE)");
			nip_dbg("%s:link becomes ready", dev->name);
		}

		if (!IS_ERR_OR_NULL(idev)) {
			/* If the MTU changed during the interface down,
			 * when the interface up, the changed MTU must be
			 * reflected in the idev as well as routers.
			 */
			if (idev->cnf.mtu != dev->mtu && dev->mtu >= NIP_MIN_MTU)
				idev->cnf.mtu = dev->mtu;
			idev->tstamp = jiffies;

			/* If the changed mtu during down is lower than
			 * NIP_MIN_MTU stop New IP on this interface.
			 */
			if (dev->mtu < NIP_MIN_MTU)
				nip_addrconf_ifdown(dev, dev != net->loopback_dev);
		}
		break;

	case NETDEV_DOWN:
	case NETDEV_UNREGISTER:
		/* Remove all addresses from this interface. */
		nip_addrconf_ifdown(dev, event != NETDEV_DOWN);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static int nip_addrconf_ifdown(struct net_device *dev, bool unregister)
{
	struct net *net = dev_net(dev);
	struct ninet_dev *idev = __nin_dev_get(dev);
	struct ninet_ifaddr *ifa, *tmp;
	struct list_head del_list;
	int i;

	ASSERT_RTNL();

	nip_dbg("%s ifindex=%u, unregister=%u (unregister:1, down:0)",
		dev->name, dev->ifindex, unregister);

	nip_rt_ifdown(net, dev);
	neigh_ifdown(&nnd_tbl, dev);
	if (!idev)
		return -ENODEV;

	/* Step 1: remove reference to newip device from parent device.
	 *         Do not dev_put!
	 */
	if (unregister) {
		idev->dead = 1;

		/* protected by rtnl_lock */
		RCU_INIT_POINTER(dev->nip_ptr, NULL);
	}

	/* Step 2: clear hash table */
	for (i = 0; i < NIN_ADDR_HSIZE; i++) {
		struct hlist_head *h = &ninet_addr_lst[i];

		spin_lock_bh(&addrconf_hash_lock);
		hlist_for_each_entry_rcu(ifa, h, addr_lst) {
			if (ifa->idev == idev) {
				char addr[NIP_ADDR_BIT_LEN_MAX] = {0};

				nip_addr_to_str(&ifa->addr, addr, NIP_ADDR_BIT_LEN_MAX);
				nip_dbg("clear addr hash table.(addr=%s)", addr);
				hlist_del_init_rcu(&ifa->addr_lst);
			}
		}
		spin_unlock_bh(&addrconf_hash_lock);
	}

	write_lock_bh(&idev->lock);

	/* Step 2: clear flags for stateless addrconf */
	if (!unregister)
		idev->if_flags &= ~(IF_RS_SENT | IF_RA_RCVD | IF_READY);

	/* Step 3: Remove address node from ifa->if_list
	 * and insert it into the list to be del_list
	 */
	INIT_LIST_HEAD(&del_list);
	list_for_each_entry_safe(ifa, tmp, &idev->addr_list, if_list) {
		list_move(&ifa->if_list, &del_list);

		write_unlock_bh(&idev->lock);
		spin_lock_bh(&ifa->lock);
		ifa->state = NINET_IFADDR_STATE_DEAD;
		spin_unlock_bh(&ifa->lock);
		write_lock_bh(&idev->lock);
	}
	write_unlock_bh(&idev->lock);

	/* Step 4: Unchain the node to be deleted and release IFA */
	while (!list_empty(&del_list)) {
		ifa = list_first_entry(&del_list, struct ninet_ifaddr, if_list);
		list_del(&ifa->if_list);
		nin_ifa_put(ifa);
	}

	/* Last: Shot the device (if unregistered) */
	if (unregister) {
		neigh_parms_release(&nnd_tbl, idev->nd_parms);
		neigh_ifdown(&nnd_tbl, dev);
		nip_dbg("%s (ifindex=%u) before idev put. idev->refcnt=%u",
			dev->name, dev->ifindex, refcount_read(&idev->refcnt));
		nin_dev_put(idev);
	}
	return 0;
}

static int nip_addr_proc_show(struct seq_file *seq, void *v)
{
	struct net *net = seq->private;
	struct ninet_ifaddr *ifp;
	int i, j;

	rcu_read_lock();
	for (i = 0; i < NIN_ADDR_HSIZE; i++)
		hlist_for_each_entry_rcu(ifp, &ninet_addr_lst[i], addr_lst) {
			if (!net_eq(dev_net(ifp->idev->dev), net))
				continue;

			for (j = 0; j < ifp->addr.bitlen / NIP_ADDR_BIT_LEN_8; j++)
				seq_printf(seq, "%02x", ifp->addr.nip_addr_field8[j]);
			seq_printf(seq, "\t%8s\n", ifp->idev->dev ? ifp->idev->dev->name : "");
		}

	rcu_read_unlock();
	return 0;
}

static int __net_init nip_addr_net_init(struct net *net)
{
	int err = -ENOMEM;
	struct nip_devconf *dflt;

	dflt = kmemdup(&newip_devconf_dflt,
		       sizeof(newip_devconf_dflt),
		       GFP_KERNEL);
	if (!dflt)
		goto err_alloc_dflt;

	net->newip.devconf_dflt = dflt;

	if (!proc_create_net_single("nip_addr", 0444, net->proc_net,
				    nip_addr_proc_show, NULL)) {
		goto err_addr_proc;
	}

	return 0;

err_addr_proc:
	kfree(dflt);
err_alloc_dflt:
	return err;
}

static void __net_exit nip_addr_net_exit(struct net *net)
{
	kfree(net->newip.devconf_dflt);
	remove_proc_entry("nip_addr", net->proc_net);
}

static struct pernet_operations nip_route_proc_net_ops = {
	.init = nip_addr_net_init,
	.exit = nip_addr_net_exit,
};

/* addrconf module should be notified of a device going up
 */
static struct notifier_block nip_dev_notf = {
	.notifier_call = nip_addrconf_notify,
	.priority = ADDRCONF_NOTIFY_PRIORITY,
};

int __init nip_addrconf_init(void)
{
	int err;

	err = register_pernet_subsys(&nip_route_proc_net_ops);
	if (err < 0) {
		nip_dbg("register_pernet_subsys failed");
		goto out;
	}

	register_netdevice_notifier(&nip_dev_notf);

out:
	return err;
}

void nip_addrconf_cleanup(void)
{
	struct net_device *dev;
	int i;

	unregister_netdevice_notifier(&nip_dev_notf);
	unregister_pernet_subsys(&nip_route_proc_net_ops);

	rtnl_lock();

	/* clean dev list */
	for_each_netdev(&init_net, dev) {
		if (!__nin_dev_get(dev))
			continue;
		nip_addrconf_ifdown(dev, 1);
	}

	/* Check hash table. */
	spin_lock_bh(&addrconf_hash_lock);
	for (i = 0; i < NIN_ADDR_HSIZE; i++)
		WARN_ON(!hlist_empty(&ninet_addr_lst[i]));
	spin_unlock_bh(&addrconf_hash_lock);
	rtnl_unlock();
}

static int ninet_addr_get(const struct net_device *dev, struct ninet_ifaddr *ifa)
{
	int err;
	struct nip_addr addr;

	err = nip_get_firstaddr(dev, &addr);
	if (!err)
		ifa->addr = addr;

	return err;
}

int nip_addrconf_get_ifaddr(struct net *net, unsigned int cmd, void __user *arg)
{
	struct nip_devreq ifr;
	struct sockaddr_nin *snin;
	struct ninet_ifaddr ifa;
	struct net_device *dev;
	void __user *p = (void __user *)arg;
	int ret = -EFAULT;

	if (copy_from_user(&ifr, p, sizeof(struct nip_ifreq)))
		goto out;

	ifr.nip_ifr_name[IFNAMSIZ - 1] = 0;
	snin = (struct sockaddr_nin *)&ifr.nip_dev_addr;

	nip_dbg("dev name is %s", ifr.nip_ifr_name);
	dev_load(net, ifr.nip_ifr_name);

	if (cmd == SIOCGIFADDR) {
		memset(snin, 0, sizeof(*snin));
		snin->sin_family = AF_NINET;
	} else {
		goto out;
	}

	rtnl_lock();

	dev = __dev_get_by_name(net, ifr.nip_ifr_name);
	if (!dev)
		goto done;

	ret = ninet_addr_get(dev, &ifa);
	if (ret)
		goto done;
	/* Get interface address */
	snin->sin_addr = ifa.addr;

	if (copy_to_user(p, &ifr, sizeof(struct nip_devreq)))
		ret = -EFAULT;

done:
	rtnl_unlock();
out:
	return ret;
}

void nip_addr_to_str(const struct nip_addr *addr, unsigned char *buf, int buf_len)
{
	int i;
	int total_len = 0;
	int addr_num = addr->bitlen / NIP_ADDR_BIT_LEN_8;

	if (!buf)
		return;

	total_len = sprintf(buf, "%s", "0x");
	for (i = 0; (i < addr_num) && (total_len < buf_len); i++) {
		int len = sprintf(buf + total_len, "%02x", addr->nip_addr_field8[i]);

		if (len <= 0)
			break;
		total_len += len;
	}

	switch (addr_num) {
	case NIP_ADDR_LEN_1:
		buf[INDEX_2] = '*'; /* 0x*0 ~ 0x*C */
		break;
	case NIP_ADDR_LEN_2:
		buf[INDEX_2] = '*'; /* 0x**DD ~ 0x**FF */
		buf[INDEX_3] = '*';
		break;
	case NIP_ADDR_LEN_3:
		buf[INDEX_4] = '*'; /* 0xF1**00 ~ 0xF1**FF */
		buf[INDEX_5] = '*';
		break;
	case NIP_ADDR_LEN_5:
		buf[INDEX_4] = '*'; /* 0xF2 **** 0000 ~ 0xF2 **** FFFF */
		buf[INDEX_5] = '*';
		buf[INDEX_6] = '*';
		buf[INDEX_7] = '*';
		break;
	case NIP_ADDR_LEN_7:
		buf[INDEX_4] = '*'; /* 0xF3 **** 0000 0000 ~ 0xF3 **** FFFF FFFF */
		buf[INDEX_5] = '*';
		buf[INDEX_6] = '*';
		buf[INDEX_7] = '*';
		break;
	case NIP_ADDR_LEN_8:
		buf[INDEX_4] = '*'; /* 0xF4** **** 0000 0000 ~ 0xF4** **** FFFF FFFF */
		buf[INDEX_5] = '*';
		buf[INDEX_6] = '*';
		buf[INDEX_7] = '*';
		buf[INDEX_8] = '*';
		buf[INDEX_9] = '*';
		break;
	default:
		break;
	}
}

