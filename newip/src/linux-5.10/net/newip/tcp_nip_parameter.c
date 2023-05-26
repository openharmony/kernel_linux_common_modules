// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * NewIP INET
 * An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. NewIP INET is implemented using the  BSD Socket
 * interface as the means of communication with the user level.
 *
 * Description: Definitions for the NewIP parameter module.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-07-25
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s:%d] " fmt, __func__, __LINE__

#include <net/dst.h>
#include <net/tcp.h>
#include <net/tcp_nip.h>
#include <net/inet_common.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>
#include <linux/errqueue.h>

/*********************************************************************************************/
/*                            Newip protocol name                                            */
/*********************************************************************************************/
int g_af_ninet = AF_NINET;
module_param_named(af_ninet, g_af_ninet, int, 0444);

/*********************************************************************************************/
/*                            Rto timeout timer period (HZ/n)                                */
/*********************************************************************************************/
/* RTT RTO in the small-delay scenario */
int g_nip_rto = 5;
module_param_named(nip_rto, g_nip_rto, int, 0644);

int get_nip_rto(void)
{
	return g_nip_rto;
}

/*********************************************************************************************/
/*                            TCP sending and receiving buffer configuration                 */
/*********************************************************************************************/
int g_nip_sndbuf = 1050000; // 1M
module_param_named(nip_sndbuf, g_nip_sndbuf, int, 0644);

int get_nip_sndbuf(void)
{
	return g_nip_sndbuf;
}

int g_nip_rcvbuf = 2000000; // 2M
module_param_named(nip_rcvbuf, g_nip_rcvbuf, int, 0644);

int get_nip_rcvbuf(void)
{
	return g_nip_rcvbuf;
}

/*********************************************************************************************/
/*                            Window configuration                                           */
/*********************************************************************************************/
/* Maximum receiving window */
bool g_wscale_enable = 1;
module_param_named(wscale_enable, g_wscale_enable, bool, 0644);

bool get_wscale_enable(void)
{
	return g_wscale_enable;
}

/* Window scale configuration, 2^n */
int g_wscale = 7;
module_param_named(wscale, g_wscale, int, 0644);

int get_wscale(void)
{
	return g_wscale;
}

/*********************************************************************************************/
/*                            Enables the debugging of special scenarios                     */
/*********************************************************************************************/
/* After receiving n packets, an ACK packet is sent */
int g_ack_num = 5;
module_param_named(ack_num, g_ack_num, int, 0644);

int get_ack_num(void)
{
	return g_ack_num;
}

/* Reset the packet sending window threshold after receiving n ACK packets */
int g_nip_ssthresh_reset = 10000000; // 10M
module_param_named(nip_ssthresh_reset, g_nip_ssthresh_reset, int, 0644);

int get_nip_ssthresh_reset(void)
{
	return g_nip_ssthresh_reset;
}

/*********************************************************************************************/
/*                            Retransmission parameters after ACK                            */
/*********************************************************************************************/
/* Three DUP ACK packets indicates the number of retransmission packets */
int g_dup_ack_retrans_num = 5;
module_param_named(dup_ack_retrans_num, g_dup_ack_retrans_num, int, 0644);

int get_dup_ack_retrans_num(void)
{
	return g_dup_ack_retrans_num;
}

/* Common ACK Indicates the number of retransmissions */
int g_ack_retrans_num = 5;
module_param_named(ack_retrans_num, g_ack_retrans_num, int, 0644);

int get_ack_retrans_num(void)
{
	return g_ack_retrans_num;
}

int g_dup_ack_snd_max = 6;
module_param_named(dup_ack_snd_max, g_dup_ack_snd_max, int, 0644);

int get_dup_ack_snd_max(void)
{
	return g_dup_ack_snd_max;
}

/*********************************************************************************************/
/*                            RTT timestamp parameters                                       */
/*********************************************************************************************/
int g_rtt_tstamp_rto_up = 100;  // rtt_tstamp >= 100  ==> shorten rto
module_param_named(rtt_tstamp_rto_up, g_rtt_tstamp_rto_up, int,  0644);

int get_rtt_tstamp_rto_up(void)
{
	return g_rtt_tstamp_rto_up;
}

int g_rtt_tstamp_high = 30;     // rtt_tstamp >= 30  ==> ssthresh = 100K
module_param_named(rtt_tstamp_high, g_rtt_tstamp_high, int,  0644);

int get_rtt_tstamp_high(void)
{
	return g_rtt_tstamp_high;
}

int g_rtt_tstamp_mid_high = 20; // rtt_tstamp >= 20  ==> ssthresh = 250K
module_param_named(rtt_tstamp_mid_high, g_rtt_tstamp_mid_high, int,  0644);

int get_rtt_tstamp_mid_high(void)
{
	return g_rtt_tstamp_mid_high;
}

/* rtt_tstamp >= 10  ==> ssthresh = 1M (500K ~ 1M)
 * rtt_tstamp <  10  ==> ssthresh = 1.5M
 */
int g_rtt_tstamp_mid_low = 10;
module_param_named(rtt_tstamp_mid_low, g_rtt_tstamp_mid_low, int,  0644);

int get_rtt_tstamp_mid_low(void)
{
	return g_rtt_tstamp_mid_low;
}

int g_ack_to_nxt_snd_tstamp = 500;
module_param_named(ack_to_nxt_snd_tstamp, g_ack_to_nxt_snd_tstamp, int,  0644);

int get_ack_to_nxt_snd_tstamp(void)
{
	return g_ack_to_nxt_snd_tstamp;
}

/*********************************************************************************************/
/*                            Window threshold parameters                                    */
/*********************************************************************************************/
bool g_ssthresh_enable = 1;
module_param_named(ssthresh_enable, g_ssthresh_enable, bool, 0644);

bool get_ssthresh_enable(void)
{
	return g_ssthresh_enable;
}

int g_nip_ssthresh_default = 300000; // 300K
module_param_named(nip_ssthresh_default, g_nip_ssthresh_default, int, 0644);

int get_nip_ssthresh_default(void)
{
	return g_nip_ssthresh_default;
}

int g_ssthresh_high = 1500000;       // rtt_tstamp <  10  ==> ssthresh = 1.5M
module_param_named(ssthresh_high, g_ssthresh_high, int, 0644);

int get_ssthresh_high(void)
{
	return g_ssthresh_high;
}

int g_ssthresh_mid_high = 1000000;   // rtt_tstamp >= 10  ==> ssthresh = 1M (500K ~ 1M)
module_param_named(ssthresh_mid_high, g_ssthresh_mid_high, int, 0644);

int get_ssthresh_mid_high(void)
{
	return g_ssthresh_mid_high;
}

int g_ssthresh_mid_low = 250000;     // rtt_tstamp >= 20  ==> ssthresh = 250K
module_param_named(ssthresh_mid_low, g_ssthresh_mid_low, int, 0644);

int get_ssthresh_mid_low(void)
{
	return g_ssthresh_mid_low;
}

int g_ssthresh_low = 100000;         // rtt_tstamp >= 30  ==> ssthresh = 100K
module_param_named(ssthresh_low, g_ssthresh_low, int, 0644);

int get_ssthresh_low(void)
{
	return g_ssthresh_low;
}

int g_ssthresh_low_min = 10000;      // rtt_tstamp >= 100  ==> ssthresh = 10K
module_param_named(ssthresh_low_min, g_ssthresh_low_min, int, 0644);

int get_ssthresh_low_min(void)
{
	return g_ssthresh_low_min;
}

int g_ssthresh_high_step = 1;
module_param_named(ssthresh_high_step, g_ssthresh_high_step, int, 0644);

int get_ssthresh_high_step(void)
{
	return g_ssthresh_high_step;
}

/*********************************************************************************************/
/*                            keepalive parameters                                           */
/*********************************************************************************************/
int g_nip_idle_ka_probes_out = 20;
module_param_named(nip_idle_ka_probes_out, g_nip_idle_ka_probes_out, int, 0644);

int get_nip_idle_ka_probes_out(void)
{
	return g_nip_idle_ka_probes_out;
}

int g_nip_keepalive_time = 25;
module_param_named(nip_keepalive_time, g_nip_keepalive_time, int, 0644);

int get_nip_keepalive_time(void)
{
	return g_nip_keepalive_time;
}

int g_nip_keepalive_intvl = 25;
module_param_named(nip_keepalive_intvl, g_nip_keepalive_intvl, int, 0644);

int get_nip_keepalive_intvl(void)
{
	return g_nip_keepalive_intvl;
}

/*********************************************************************************************/
/*                            probe parameters                                               */
/*********************************************************************************************/
int g_nip_probe_max = 2000;
module_param_named(nip_probe_max, g_nip_probe_max, int, 0644);

int get_nip_probe_max(void)
{
	return g_nip_probe_max;
}

/*********************************************************************************************/
/*                            window mode parameters                                         */
/*********************************************************************************************/
bool g_nip_tcp_snd_win_enable;
module_param_named(nip_tcp_snd_win_enable, g_nip_tcp_snd_win_enable, bool, 0644);

bool get_nip_tcp_snd_win_enable(void)
{
	return g_nip_tcp_snd_win_enable;
}

bool g_nip_tcp_rcv_win_enable = true;
module_param_named(nip_tcp_rcv_win_enable, g_nip_tcp_rcv_win_enable, bool, 0644);

bool get_nip_tcp_rcv_win_enable(void)
{
	return g_nip_tcp_rcv_win_enable;
}

/*********************************************************************************************/
/*                            nip debug parameters                                           */
/*********************************************************************************************/
/* Debugging for control DEBUG */
bool g_nip_debug;
module_param_named(nip_debug, g_nip_debug, bool, 0644);

bool get_nip_debug(void)
{
	return g_nip_debug;
}

/* Debugging of threshold change */
bool g_rtt_ssthresh_debug;
module_param_named(rtt_ssthresh_debug, g_rtt_ssthresh_debug, bool,  0644);

bool get_rtt_ssthresh_debug(void)
{
	return g_rtt_ssthresh_debug;
}

/* Debugging of packet retransmission after ACK */
bool g_ack_retrans_debug;
module_param_named(ack_retrans_debug, g_ack_retrans_debug, bool,  0644);

bool get_ack_retrans_debug(void)
{
	return g_ack_retrans_debug;
}

