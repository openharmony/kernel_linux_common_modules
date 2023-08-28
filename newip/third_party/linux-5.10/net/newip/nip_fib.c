// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on net/ipv6/ip6_fib.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Changes:
 *	Yuji SEKIYA @USAGI:	Support default route on router node;
 *				remove ip6_null_entry from the top of
 *				routing table.
 *	Ville Nuorvala:		Fixed routing subtrees.
 *
 * Linux NewIP INET implementation
 * Forwarding Information Database
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/list.h>

#include <net/nip.h>
#include <net/ndisc.h>
#include <net/addrconf.h>

#include <net/nip_fib.h>
#include <net/nip_route.h>
#include "tcp_nip_parameter.h"

static struct kmem_cache *nip_fib_node_kmem __read_mostly;

struct nip_fib_table *nip_fib_get_table(struct net *net, u32 id)
{
	if (id == NIP_RT_TABLE_MAIN)
		return net->newip.nip_fib_main_tbl;
	else if (id == NIP_RT_TABLE_LOCAL)
		return net->newip.nip_fib_local_tbl;
	else
		return NULL;
}

static struct nip_fib_node *nip_node_alloc(void)
{
	struct nip_fib_node *fn;

	fn = kmem_cache_zalloc(nip_fib_node_kmem, GFP_ATOMIC);

	return fn;
}

void nip_rt_free_pcpu(struct nip_rt_info *non_pcpu_rt)
{
	int cpu;

	if (!non_pcpu_rt->rt_pcpu)
		return;

	for_each_possible_cpu(cpu) {
		struct nip_rt_info **ppcpu_rt;
		struct nip_rt_info *pcpu_rt;

		ppcpu_rt = per_cpu_ptr(non_pcpu_rt->rt_pcpu, cpu);
		pcpu_rt = *ppcpu_rt;
		if (pcpu_rt) {
			dst_dev_put(&pcpu_rt->dst);
			dst_release(&pcpu_rt->dst);
			*ppcpu_rt = NULL;
		}
	}

	free_percpu(non_pcpu_rt->rt_pcpu);
	non_pcpu_rt->rt_pcpu = NULL;
}

static u32 ninet_route_hash(const struct nip_addr *addr)
{
	return hash_32(nip_addr_hash(addr), NIN_ROUTE_HSIZE_SHIFT);
}

struct nip_fib_node *nip_fib_locate(struct hlist_head *nip_tb_head,
				    const struct nip_addr *daddr)
{
	struct nip_fib_node *fib_node;
	struct hlist_head *h;
	unsigned int hash;

	/* hash calc ensures that the hash index is valid without memory overruns */
	hash = ninet_route_hash(daddr);
	h = &nip_tb_head[hash];

	hlist_for_each_entry_rcu(fib_node, h, fib_hlist) {
		if (nip_addr_eq(&fib_node->nip_route_info->rt_dst, daddr))
			return fib_node;
	}

	/* find default route */
	/* hash calc ensures that the hash index is valid without memory overruns */
	hash = ninet_route_hash(&nip_any_addr);
	h = &nip_tb_head[hash];

	hlist_for_each_entry_rcu(fib_node, h, fib_hlist) {
		if (nip_addr_eq(&fib_node->nip_route_info->rt_dst, &nip_any_addr))
			return fib_node;
	}

	return NULL;
}

static bool is_nip_route_exist(const struct hlist_head *h, const struct nip_rt_info *rt,
			       u8 table_id)
{
	struct nip_fib_node *fib_node;

	hlist_for_each_entry(fib_node, h, fib_hlist) {
		if (table_id  == NIP_RT_TABLE_MAIN) {
			if (nip_addr_eq(&fib_node->nip_route_info->rt_dst,
					&rt->rt_dst))
				return true;
		} else if (table_id == NIP_RT_TABLE_LOCAL) {
			if (nip_addr_and_ifindex_eq
				(&fib_node->nip_route_info->rt_dst, &rt->rt_dst,
				fib_node->nip_route_info->rt_idev->dev->ifindex,
				rt->rt_idev->dev->ifindex))
				return true;
		}
	}
	return false;
}

/* nip_tb_lock must be taken to avoid racing */
int nip_fib_add(struct nip_fib_table *table, struct nip_rt_info *rt)
{
	struct nip_fib_node *new_node;
	int err = 0;
	struct hlist_head *h;
	unsigned int hash;
	char dst[NIP_ADDR_BIT_LEN_MAX] = {0};
	char gateway[NIP_ADDR_BIT_LEN_MAX] = {0};

	/* hash calc ensures that the hash index is valid without memory overruns */
	hash = ninet_route_hash(&rt->rt_dst);
	h = &table->nip_tb_head[hash];

	nip_addr_to_str(&rt->rt_dst, dst, NIP_ADDR_BIT_LEN_MAX);
	nip_addr_to_str(&rt->gateway, gateway, NIP_ADDR_BIT_LEN_MAX);
	nip_dbg("%s ifindex=%u (addr=%s, gateway=%s, rt_idev->refcnt=%u)",
		rt->rt_idev->dev->name, rt->rt_idev->dev->ifindex,
		dst, gateway, refcount_read(&rt->rt_idev->refcnt));

	if (is_nip_route_exist(h, rt, table->nip_tb_id)) {
		err = -EEXIST;
		nip_dbg("File exists");
		goto fail;
	}

	new_node = nip_node_alloc();
	if (!new_node) {
		nip_dbg("fail to alloc mem");
		err = -ENOMEM;
		goto fail;
	}
	new_node->nip_route_info = rt;
	rcu_assign_pointer(rt->rt_node, new_node);
	atomic_inc(&rt->rt_ref);
	hlist_add_tail_rcu(&new_node->fib_hlist, h);

out:
	return err;

fail:
	dst_release_immediate(&rt->dst);
	goto out;
}

static void nip_fib_destroy_rcu(struct rcu_head *head)
{
	struct nip_fib_node *fn = container_of(head, struct nip_fib_node, rcu);

	nip_rt_release(fn->nip_route_info);
	kfree(fn);
}

/* nip_tb_lock must be taken to avoid racing */
int nip_fib_del(struct nip_rt_info *rt, struct nl_info *info)
{
	struct nip_fib_node *fn;
	struct net *net = info->nl_net;

	fn = rcu_dereference_protected(rt->rt_node,
				       lockdep_is_held(&rt->rt_table->nip_tb_lock));
	if (!fn || rt == net->newip.nip_null_entry)
		return -ENOENT;

	hlist_del_init_rcu(&fn->fib_hlist);

	/* route_info directed by the fib_node can be released
	 * only after the fib_node is released
	 */
	RCU_INIT_POINTER(rt->rt_node, NULL);
	call_rcu(&fn->rcu, nip_fib_destroy_rcu);

	return 0;
}

static void nip_fib_free_table(struct nip_fib_table *table)
{
	kfree(table);
}

/* caller must hold nip_tb_lock */
static void nip_fib_clean_hash(struct net *net, struct hlist_head *nip_tb_head,
			       int (*func)(struct nip_rt_info *, void *arg),
			       void *arg)
{
	int i;
	int err;
	struct nip_fib_node *fn;
	struct hlist_node *tmp;
	struct nl_info info = {
		.nl_net = net,
	};

	for (i = 0; i < NIN_ROUTE_HSIZE; i++) {
		struct hlist_head *h = &nip_tb_head[i];

		hlist_for_each_entry_safe(fn, tmp, h, fib_hlist) {
			if (func(fn->nip_route_info, arg) < 0) {
				char dst[NIP_ADDR_BIT_LEN_MAX] = {0};
				char gateway[NIP_ADDR_BIT_LEN_MAX] = {0};

				nip_addr_to_str(&fn->nip_route_info->rt_dst, dst,
						NIP_ADDR_BIT_LEN_MAX);
				nip_addr_to_str(&fn->nip_route_info->gateway, gateway,
						NIP_ADDR_BIT_LEN_MAX);

				nip_dbg("try to del rt_info, rt_dst=%s, gateway=%s", dst, gateway);
				err = nip_fib_del(fn->nip_route_info, &info);
				if (err)
					nip_dbg("nip_fib_del failed");
			}
		}
	}
}

void nip_fib_clean_all(struct net *net,
		       int (*func)(struct nip_rt_info *, void *arg), void *arg)
{
	struct nip_fib_table *main_tbl = net->newip.nip_fib_main_tbl;
	struct nip_fib_table *local_tbl = net->newip.nip_fib_local_tbl;

	spin_lock_bh(&main_tbl->nip_tb_lock);
	nip_fib_clean_hash(net, main_tbl->nip_tb_head, func, arg);
	spin_unlock_bh(&main_tbl->nip_tb_lock);

	spin_lock_bh(&local_tbl->nip_tb_lock);
	nip_fib_clean_hash(net, local_tbl->nip_tb_head, func, arg);
	spin_unlock_bh(&local_tbl->nip_tb_lock);
}

static void nip_fib_link_table(struct nip_fib_table *tb)
{
	/* You need to initialize multiple routing tables */
	spin_lock_init(&tb->nip_tb_lock);
}

static void __net_init nip_fib_tables_init(struct net *net)
{
	nip_fib_link_table(net->newip.nip_fib_main_tbl);
	nip_fib_link_table(net->newip.nip_fib_local_tbl);
}

static int __net_init nip_fib_net_init(struct net *net)
{
	net->newip.nip_fib_main_tbl =
	    kzalloc(sizeof(*net->newip.nip_fib_main_tbl), GFP_KERNEL);
	if (!net->newip.nip_fib_main_tbl)
		goto out_fib_table_hash;

	net->newip.nip_fib_main_tbl->nip_tb_id = NIP_RT_TABLE_MAIN;
	net->newip.nip_fib_main_tbl->flags = 1;

	net->newip.nip_fib_local_tbl =
	    kzalloc(sizeof(*net->newip.nip_fib_local_tbl), GFP_KERNEL);
	if (!net->newip.nip_fib_local_tbl)
		goto out_main_tbl;

	net->newip.nip_fib_local_tbl->nip_tb_id = NIP_RT_TABLE_LOCAL;

	nip_fib_tables_init(net);

	return 0;

out_main_tbl:
	kfree(net->newip.nip_fib_main_tbl);
out_fib_table_hash:
	return -ENOMEM;
}

static void __net_exit nip_fib_net_exit(struct net *net)
{
	nip_fib_free_table(net->newip.nip_fib_main_tbl);
	nip_fib_free_table(net->newip.nip_fib_local_tbl);
}

static struct pernet_operations nip_fib_net_ops = {
	.init = nip_fib_net_init,
	.exit = nip_fib_net_exit,
};

int __init nip_fib_init(void)
{
	int ret = -ENOMEM;

	nip_fib_node_kmem = kmem_cache_create("nip_fib_nodes",
					      sizeof(struct nip_fib_node),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!nip_fib_node_kmem)
		goto out;

	nip_dbg("nip_fib_node size is %lu",
		sizeof(struct nip_fib_node) + sizeof(struct nip_rt_info));

	ret = register_pernet_subsys(&nip_fib_net_ops);
	if (ret)
		goto out_kmem_cache_create;

out:
	return ret;

out_kmem_cache_create:
	kmem_cache_destroy(nip_fib_node_kmem);
	goto out;
}

/* When adding the __exit tag to a function, it is important to
 * ensure that the function is only called during the exit phase
 * to avoid unnecessary warnings and errors.
 */
void nip_fib_gc_cleanup(void)
{
	unregister_pernet_subsys(&nip_fib_net_ops);
	kmem_cache_destroy(nip_fib_node_kmem);
}

