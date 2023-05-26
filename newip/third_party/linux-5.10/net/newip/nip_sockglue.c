// SPDX-License-Identifier: GPL-2.0
/*
 * Based on net/ipv4/ip_sockglue.c
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip.c for history.
 *		Martin Mares	:	TOS setting fixed.
 *		Alan Cox	:	Fixed a couple of oopses in Martin's
 *					TOS tweaks.
 *		Mike McLagan	:	Routing by source
 *
 * NewIP INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * The NewIP to API glue.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/sock.h>
#include <net/nip.h>
#include <net/nip_udp.h>
#include <net/route.h>
#include <net/nip_fib.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/nip.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include "tcp_nip_parameter.h"

#define NIP_OPTNAME_MAX 255

static void __nip_set_sock_tos(struct sock *sk, int val)
{
	sk->sk_priority = rt_tos2priority(val);
	sk_dst_reset(sk);
}

static bool nip_setsockopt_needs_rtnl(int optname)
{
	switch (optname) {
	case IP_MSFILTER:
		return true;
	default:
		return false;
	}
}

static bool nip_getsockopt_needs_rtnl(int optname)
{
	switch (optname) {
	case IP_MSFILTER:
		return true;
	default:
		return false;
	}
}

static int do_nip_setsockopt(struct sock *sk, int level, int optname,
			     sockptr_t optval, unsigned int optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	int val = 0;
	int err = 0;
	bool needs_rtnl = nip_setsockopt_needs_rtnl(optname);

	if (optlen >= sizeof(int)) {
		if (copy_from_sockptr(&val, optval, sizeof(val)))
			return -EFAULT;
	} else if (optlen >= sizeof(char)) {
		unsigned char ucval;

		if (copy_from_sockptr(&ucval, optval, sizeof(ucval)))
			return -EFAULT;
		val = (int)ucval;
	}

	if (needs_rtnl)
		rtnl_lock();
	lock_sock(sk);

	switch (optname) {
	case IP_TOS:
		inet->tos = val;
		__nip_set_sock_tos(sk, val);
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	if (needs_rtnl)
		rtnl_unlock();

	return err;
}

int nip_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		   unsigned int optlen)
{
	int err;

	if (level != SOL_IP)
		return -ENOPROTOOPT;

	err = do_nip_setsockopt(sk, level, optname, optval, optlen);

	return err;
}

static int do_nip_getsockopt(struct sock *sk, int level, int optname,
			     char __user *optval, int __user *optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	bool needs_rtnl = nip_getsockopt_needs_rtnl(optname);
	int val, err = 0;
	int len;

	if (level != SOL_IP)
		return -EOPNOTSUPP;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	if (needs_rtnl)
		rtnl_lock();
	lock_sock(sk);

	switch (optname) {
	case IP_TOS:
		val = inet->tos;
		break;
	default:
		err = -ENOPROTOOPT;
		goto out;
	}

	if (len < sizeof(int) && len > 0 && val >= 0 && val <= NIP_OPTNAME_MAX) {
		unsigned char ucval = (unsigned char)val;

		len = 1;
		if (put_user(len, optlen)) {
			err = -EFAULT;
			goto out;
		}
		if (copy_to_user(optval, &ucval, 1)) {
			err = -EFAULT;
			goto out;
		}
	} else {
		len = min_t(unsigned int, sizeof(int), len);
		if (put_user(len, optlen)) {
			err = -EFAULT;
			goto out;
		}
		if (copy_to_user(optval, &val, len)) {
			err = -EFAULT;
			goto out;
		}
	}
out:
	release_sock(sk);
	if (needs_rtnl)
		rtnl_unlock();

	return err;
}

int nip_getsockopt(struct sock *sk, int level,
		   int optname, char __user *optval, int __user *optlen)
{
	return do_nip_getsockopt(sk, level, optname, optval, optlen);
}

