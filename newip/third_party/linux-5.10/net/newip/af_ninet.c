// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Based on  linux/net/ipv6/af_inet6.c
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 *	Fixes:
 *	piggy, Karl Knutson	:	Socket protocol table
 *	Hideaki YOSHIFUJI	:	sin6_scope_id support
 *	Arnaldo Melo		:	check proc_net_create return, cleanups
 *
 * NewIP INET socket protocol family
 * Linux NewIP INET implementation
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/sched/signal.h> /* for signal_pending() */

#include <net/nip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/route.h>
#include <net/nndisc.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

#include <net/transp_nip.h>
#include <net/nip_fib.h>
#include <net/nip_route.h>
#include <net/nip_addrconf.h>
#include <net/tcp_nip.h>
#include <linux/nip.h>
#include <linux/newip_route.h>

#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/netlink.h>

#ifdef CONFIG_NEWIP_HOOKS
#include "nip_hooks_register.h"
#endif
#include "tcp_nip_parameter.h"

#define NINET_IOCTL_FLAG_LEN    8
#define NINET_IOCTL_HEAD_LEN    12
#define NINET_IOCTL_FLAG_VALUE  {0xea, 0xdd, 0xea, 0xdd, 0xea, 0xdd, 0xea, 0xdd}

MODULE_DESCRIPTION("NewIP protocol stack");

/* The inetsw_nip table contains everything that ninet_create needs to
 * build a new socket
 */
static struct list_head inetsw_nip[SOCK_MAX];
static DEFINE_SPINLOCK(inetsw_nip_lock);
/* count the socket number */
atomic_t g_nip_socket_number = ATOMIC_INIT(0);

static int disable_nip_mod;
module_param_named(disable, disable_nip_mod, int, 0444);
MODULE_PARM_DESC(disable, "Disable NewIP module such that it is non_functional");

bool newip_mod_enabled(void)
{
	return disable_nip_mod == 0;
}
EXPORT_SYMBOL_GPL(newip_mod_enabled);

static int ninet_create(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct inet_sock *inet;
	struct sock *sk;
	struct inet_protosw *answer;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int err;
	int num;

	if (protocol < 0 ||
	    protocol >= IPPROTO_MAX ||
	    sock->type >= SOCK_MAX)
		return -EINVAL;

	num = atomic_add_return(1, &g_nip_socket_number);
	if (num > NIP_MAX_SOCKET_NUM) {
		nip_dbg("The number of socket is biger than %u", NIP_MAX_SOCKET_NUM);
		err = -EPERM;
		goto number_sub;
	}

	sock->state = SS_UNCONNECTED;
	/* look for the requested type/protocol pair. */
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw_nip[sock->type], list) {
		err = 0;
		/* Check the non-wild matcg */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* check for the two wild case. */
			if (protocol == IPPROTO_IP) {
				protocol = answer->protocol;
				break;
			}
			if (answer->protocol == IPPROTO_IP)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (err)
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOBUFS;
	sk = sk_alloc(net, PF_NINET, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto number_sub;

	sock_init_data(sock, sk);

	err = 0;
	if (answer_flags & INET_PROTOSW_REUSE)
		sk->sk_reuse = SK_CAN_REUSE;
	inet = inet_sk(sk);
	inet->is_icsk = (answer_flags & INET_PROTOSW_ICSK) != 0;
	inet->nodefrag = 0;

	if (sock->type == SOCK_RAW) {
		inet->inet_num = protocol;
		if (protocol == IPPROTO_RAW)
			inet->hdrincl = 1;
	}

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_family = PF_NINET;
	sk->sk_protocol = protocol;
	sk->sk_backlog_rcv = answer->prot->backlog_rcv;
	sk->SK_NIP_DADDR = nip_any_addr;
	sk->SK_NIP_RCV_SADDR = nip_any_addr;

	inet->uc_ttl = -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;
	sk_refcnt_debug_inc(sk);

	if (inet->inet_num) {
		inet->inet_sport = htons(inet->inet_num);
		err = sk->sk_prot->hash(sk);
		if (err) {
			sk_common_release(sk);
			goto number_sub;
		}
	}
	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			sk_common_release(sk);
			goto number_sub;
		}
	}
out:
	nip_dbg("The final number of socket is: %d", num);
	return err;
out_rcu_unlock:
	rcu_read_unlock();
number_sub:
	atomic_dec_if_positive(&g_nip_socket_number);
	num = atomic_read(&g_nip_socket_number);
	nip_dbg("[error] The final number of socket is: %d (after dec)", num);
	goto out;
}

int ninet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_nin *addr = (struct sockaddr_nin *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	u_short snum;
	int err = 0;

	/* If the socket has its own bind function then use it */
	if (sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, uaddr, addr_len);

	if (addr_len < sizeof(struct sockaddr_nin))
		return -EINVAL;

	snum = ntohs(addr->sin_port);
	if (snum && snum < PROT_SOCK)
		return -EACCES;

	if (nip_bind_addr_check(net, &addr->sin_addr) == false) {
		nip_dbg("binding-addr invalid, bitlen=%u", addr->sin_addr.bitlen);
		return -EADDRNOTAVAIL;
	}
	lock_sock(sk);

	/* check these errors (active socket, double bind) */
	if (sk->sk_state != TCP_CLOSE || inet->inet_num) {
		err = -EINVAL;
		goto out;
	}

	sk->SK_NIP_RCV_SADDR = addr->sin_addr;

	/* make sure we are allowed to bind here */
	if ((snum || !inet->bind_address_no_port) &&
	    sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = 0;
		err = -EADDRINUSE;
		goto out;
	}
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);

out:
	release_sock(sk);
	return err;
}

/* Function
 *	Move a socket into listening state.
 * Parameter
 *	sock: The socket
 *	backlog: Specifies the number of clients that use a three-way handshake
 *	         to establish a TCP connection
 */
int ninet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	WRITE_ONCE(sk->sk_max_ack_backlog, backlog);
	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	err = 0;

out:
	release_sock(sk);
	return err;
}

int ninet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	int num;

	if (!sk)
		return -EINVAL;

	atomic_dec_if_positive(&g_nip_socket_number);
	err = inet_release(sock);
	num = atomic_read(&g_nip_socket_number);
	nip_dbg("%s, The final number of socket is: %d",
		err ? "failed" : "success", num);
	return err;
}

void ninet_destroy_sock(struct sock *sk)
{
	;
}

int ninet_getname(struct socket *sock, struct sockaddr *uaddr,
		  int peer)
{
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_nin *, sin, uaddr);

	sin->sin_family = AF_NINET;
	if (peer) {
		if (!inet->inet_dport)
			return -ENOTCONN;
		if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
		    peer == 1)
			return -ENOTCONN;
		sin->sin_port = inet->inet_dport;
		sin->sin_addr = sk->SK_NIP_DADDR;
	} else {
		sin->sin_port = inet->inet_sport;
		sin->sin_addr = sk->SK_NIP_RCV_SADDR;
	}
	return sizeof(*sin);
}

static long ninet_wait_for_connect(struct sock *sk, long timeo, int writebias)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending += writebias;

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending -= writebias;
	return timeo;
}

/* Function
 *	The client socket layer is used to establish connection requests
 * Parameter
 *	sock: The socket
 *	uaddr:The destination address
 */
int __ninet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			   int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	if (uaddr) {
		if (addr_len < sizeof(uaddr->sa_family))
			return -EINVAL;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;
		/* Call the tcp_nip_connect function */
		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;
		/* Switch to connecting, and then perform subsequent operations */
		sock->state = SS_CONNECTING;
		err = -EINPROGRESS;
		break;
	}

	/* Get blocking time */
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int writebias = 0;
		/* Error code is set above */
		if (!timeo || !ninet_wait_for_connect(sk, timeo, writebias))
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;
	sock->state = SS_CONNECTED;
	err = 0;

out:
	return err;
sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_DISCONNECTING;
	goto out;
}

int ninet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			 int addr_len, int flags)
{
	int err;

	lock_sock(sock->sk);
	err = __ninet_stream_connect(sock, uaddr, addr_len, flags);
	release_sock(sock->sk);
	return err;
}

int ninet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);

	nip_dbg("cmd=0x%x", cmd);
	switch (cmd) {
	case SIOCADDRT:
	case SIOCDELRT: {
		struct nip_rtmsg rtmsg;

		if (copy_from_user(&rtmsg, (void __user *)arg, sizeof(rtmsg))) {
			nip_dbg("fail to copy route cfg data");
			return -EFAULT;
		}
		return nip_route_ioctl(net, cmd, &rtmsg);
	}
	case SIOCSIFADDR:
		return nip_addrconf_add_ifaddr(net, (void __user *)arg);
	case SIOCDIFADDR:
		return nip_addrconf_del_ifaddr(net, (void __user *)arg);
	case SIOCGIFADDR:
		return nip_addrconf_get_ifaddr(net, cmd, (void __user *)arg);

	default:
		if (!sk->sk_prot->ioctl) {
			nip_dbg("sock sk_prot ioctl is null, cmd=0x%x", cmd);
			return -ENOIOCTLCMD;
		}
		return sk->sk_prot->ioctl(sk, cmd, arg);
	}
}

#ifdef CONFIG_COMPAT
struct compat_nip_rtmsg {
	struct nip_addr rtmsg_dst;
	struct nip_addr rtmsg_src;
	struct nip_addr rtmsg_gateway;
	char dev_name[10];
	unsigned int rtmsg_type;
	int rtmsg_ifindex;
	unsigned int rtmsg_metric;
	unsigned int rtmsg_info;  /* long convert to int */
	unsigned int rtmsg_flags;
};

static int ninet_compat_routing_ioctl(struct sock *sk, unsigned int cmd,
				      struct compat_nip_rtmsg __user *ur)
{
	struct nip_rtmsg rt;

	if (copy_from_user(&rt.rtmsg_dst, &ur->rtmsg_dst, INDEX_3 * sizeof(struct nip_addr)) ||
	    copy_from_user(&rt.dev_name, &ur->dev_name, sizeof(rt.dev_name)) ||
	    get_user(rt.rtmsg_type, &ur->rtmsg_type) ||
	    get_user(rt.rtmsg_ifindex, &ur->rtmsg_ifindex) ||
	    get_user(rt.rtmsg_metric, &ur->rtmsg_metric) ||
	    get_user(rt.rtmsg_info, &ur->rtmsg_info) ||
	    get_user(rt.rtmsg_flags, &ur->rtmsg_flags)) {
		nip_dbg("fail to convert input para, cmd=0x%x", cmd);
		return -EFAULT;
	}

	nip_dbg("cmd=0x%x", cmd);
	return nip_route_ioctl(sock_net(sk), cmd, &rt);
}

int ninet_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	void __user *argp = compat_ptr(arg);
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCADDRT:
	case SIOCDELRT:
		return ninet_compat_routing_ioctl(sk, cmd, argp);
	default:
		return -ENOIOCTLCMD;
	}
}
EXPORT_SYMBOL_GPL(ninet_compat_ioctl);

static int compat_select_ninet_ioctl(struct socket *sock, unsigned int cmd,
				     unsigned long arg, int arglen)
{
	switch (cmd) {
	case SIOCADDRT:
	case SIOCDELRT:
		if (sizeof(struct nip_rtmsg) != arglen) {
			void __user *argp = compat_ptr(arg);
			struct sock *sk = sock->sk;

			return ninet_compat_routing_ioctl(sk, cmd, argp);
		}
		return ninet_ioctl(sock, cmd, arg);
	default:
		return ninet_ioctl(sock, cmd, arg);
	}
}
#endif /* CONFIG_COMPAT */

static int __ninet_ioctl_cmd(struct socket *sock, unsigned int cmd,
			     void __user *iov_base, __kernel_size_t iov_len)
{
	unsigned long arg = (unsigned long)((char *)iov_base + NINET_IOCTL_HEAD_LEN);
#ifdef CONFIG_COMPAT
	int arglen = iov_len - NINET_IOCTL_HEAD_LEN;

	return compat_select_ninet_ioctl(sock, cmd, arg, arglen);
#else
	return ninet_ioctl(sock, cmd, arg);
#endif
}

int ninet_ioctl_cmd(struct socket *sock, const struct iovec *iov)
{
	const char ioctl_flag[NINET_IOCTL_FLAG_LEN] = NINET_IOCTL_FLAG_VALUE;
	char ioctl_head[NINET_IOCTL_HEAD_LEN];
	int i;
	unsigned int cmd;

	if (!iov || !iov->iov_base || !sock ||
	    iov->iov_len < NINET_IOCTL_HEAD_LEN) {
		nip_dbg("invalid parameter");
		return -NIP_IOCTL_FLAG_INVALID;
	}

	if (copy_from_user(ioctl_head, (void __user *)iov->iov_base, NINET_IOCTL_HEAD_LEN)) {
		nip_dbg("fail to copy ioctl head");
		return -NIP_IOCTL_FLAG_INVALID;
	}

	for (i = 0; i < NINET_IOCTL_FLAG_LEN; i++) {
		if (ioctl_head[i] != ioctl_flag[i]) {
			nip_dbg("not ninet ioctl cmd");
			return -NIP_IOCTL_FLAG_INVALID;
		}
	}
	cmd = *(unsigned int *)(ioctl_head + NINET_IOCTL_FLAG_LEN);
	return __ninet_ioctl_cmd(sock, cmd, iov->iov_base, iov->iov_len);
}

/* register new	IP socket */
const struct proto_ops ninet_dgram_ops = {
	.family = PF_NINET,
	.owner = THIS_MODULE,
	.release = ninet_release,
	.bind = ninet_bind,
	.connect = inet_dgram_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = ninet_getname,
	.poll = datagram_poll,
	.ioctl = ninet_ioctl,
	.gettstamp = sock_gettstamp,
	.listen = sock_no_listen,
	.shutdown = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = inet_sendmsg,
	.recvmsg = inet_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
	.set_peek_off = sk_set_peek_off,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ninet_compat_ioctl,
#endif
};

const struct proto_ops ninet_stream_ops = {
	.family		   = PF_NINET,
	.owner		   = THIS_MODULE,
	.release	   = ninet_release,
	.bind		   = ninet_bind,
	.connect	   = ninet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = ninet_getname,
	.poll		   = tcp_poll,
	.ioctl		   = ninet_ioctl,
	.listen		   = ninet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_ioctl	   = ninet_compat_ioctl,
#endif
};

static const struct net_proto_family ninet_family_ops = {
	.family = PF_NINET,
	.create = ninet_create,
	.owner = THIS_MODULE,
};

int ninet_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	struct list_head *last_perm;
	int protocol = p->protocol;
	int ret;

	spin_lock_bh(&inetsw_nip_lock);

	ret = -EINVAL;
	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	ret = -EPERM;
	last_perm = &inetsw_nip[p->type];
	list_for_each(lh, &inetsw_nip[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (answer->flags & INET_PROTOSW_PERMANENT) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	list_add_rcu(&p->list, last_perm);
	ret = 0;
out:
	spin_unlock_bh(&inetsw_nip_lock);
	return ret;

out_permanent:
	nip_dbg("Attempt to override permanent protocol %d", protocol);
	goto out;

out_illegal:
	nip_dbg("Ignoring attempt to register invalid socket type %d", p->type);
	goto out;
}

void ninet_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		nip_dbg("Attempt to unregister permanent protocol %d", p->protocol);
	} else {
		spin_lock_bh(&inetsw_nip_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetsw_nip_lock);

		synchronize_net();
	}
}

int ninet_sk_rebuild_header(struct sock *sk)
{
	return 0;
}

/* register to data link layer */
static struct packet_type nip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_NEWIP),
	.func = nip_rcv,
};

static int __init nip_packet_init(void)
{
	dev_add_pack(&nip_packet_type);
	return 0;
}

static int __net_init ninet_net_init(struct net *net)
{
	int err = 0;
	return err;
}

static void __net_exit ninet_net_exit(struct net *net)
{
	;
}

static struct pernet_operations ninet_net_ops = {
	.init = ninet_net_init,
	.exit = ninet_net_exit,
};

static int __init ninet_init(void)
{
	struct list_head *r;
	int err = 0;

	sock_skb_cb_check_size(sizeof(struct ninet_skb_parm));

	nip_dbg("NET: start to init nip network");
	/* register the socket-side information for ninet_create */
	for (r = &inetsw_nip[0]; r < &inetsw_nip[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	if (!newip_mod_enabled()) {
		nip_dbg("Loaded, but administratively disabled, reboot required to enable");
		goto out;
	}

	err = proto_register(&tcp_nip_prot, 1);
	if (err)
		goto out;

	err = proto_register(&nip_udp_prot, 1);
	if (err) {
		nip_dbg("failed to register udp proto");
		goto out_udp_register_fail;
	}

	err = sock_register(&ninet_family_ops);
	if (err) {
		nip_dbg("failed to register newip_family_ops");
		goto out_sock_register_fail;
	}

	err = register_pernet_subsys(&ninet_net_ops);
	if (err) {
		nip_dbg("failed to register ninet_net_ops");
		goto register_pernet_fail;
	}

	err = nip_icmp_init();
	if (err) {
		nip_dbg("nip_icmp_init failed");
		goto nip_icmp_fail;
	}

	err = nndisc_init();
	if (err) {
		nip_dbg("nndisc_init failed");
		goto nndisc_fail;
	}

	err = nip_route_init();
	if (err)
		goto nip_route_fail;

	err = nip_addrconf_init();
	if (err)
		goto nip_addr_fail;

	err = nip_udp_init();
	if (err) {
		nip_dbg("failed to init udp layer");
		goto udp_fail;
	}

	err = tcp_nip_init();
	if (err) {
		nip_dbg("failed to init tcp layer");
		goto tcp_fail;
	} else {
		nip_dbg("nip_tcp_init ok");
	}

	err = nip_packet_init();
	if (err) {
		nip_dbg("failed to register to l2 layer");
		goto nip_packet_fail;
	}

#ifdef CONFIG_NEWIP_HOOKS
	ninet_hooks_init();
#endif
	nip_dbg("init newip address family ok");

out:
	return err;

nip_packet_fail:
	tcp_nip_exit();
tcp_fail:
	nip_udp_exit();
udp_fail:
	nip_addrconf_cleanup();
nip_addr_fail:
	nip_route_cleanup();
nip_route_fail:
nndisc_fail:
nip_icmp_fail:
	unregister_pernet_subsys(&ninet_net_ops);
register_pernet_fail:
	sock_unregister(PF_NINET);
out_sock_register_fail:
	proto_unregister(&nip_udp_prot);
out_udp_register_fail:
	nip_dbg("newip family init failed");
	goto out;
}

module_init(ninet_init);

MODULE_ALIAS_NETPROTO(PF_NINET);

