/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#ifndef _TCP_NIP_PARAMETER_H
#define _TCP_NIP_PARAMETER_H

int get_nip_rto(void);
int get_nip_sndbuf(void);
int get_nip_rcvbuf(void);
bool get_wscale_enable(void);
int get_wscale(void);
int get_ack_num(void);
int get_nip_ssthresh_reset(void);
int get_dup_ack_retrans_num(void);
int get_ack_retrans_num(void);
int get_dup_ack_snd_max(void);
int get_rtt_tstamp_rto_up(void);
int get_rtt_tstamp_high(void);
int get_rtt_tstamp_mid_high(void);
int get_rtt_tstamp_mid_low(void);
int get_ack_to_nxt_snd_tstamp(void);
bool get_ssthresh_enable(void);
int get_nip_ssthresh_default(void);
int get_ssthresh_high(void);
int get_ssthresh_mid_high(void);
int get_ssthresh_mid_low(void);
int get_ssthresh_low(void);
int get_ssthresh_low_min(void);
int get_ssthresh_high_step(void);
int get_nip_idle_ka_probes_out(void);
int get_nip_keepalive_time(void);
int get_nip_keepalive_intvl(void);
int get_nip_probe_max(void);
bool get_nip_tcp_snd_win_enable(void);
bool get_nip_tcp_rcv_win_enable(void);
bool get_nip_debug(void);
bool get_rtt_ssthresh_debug(void);
bool get_ack_retrans_debug(void);

/*********************************************************************************************/
/*                            nip debug parameters                                           */
/*********************************************************************************************/
#define nip_dbg(fmt, ...) \
do { \
	if (get_nip_debug()) \
		pr_crit(fmt, ##__VA_ARGS__); \
} while (0)

/* Debugging of threshold change */
#define ssthresh_dbg(fmt, ...) \
do { \
	if (get_rtt_ssthresh_debug()) \
		pr_crit(fmt, ##__VA_ARGS__); \
} while (0)

/* Debugging of packet retransmission after ACK */
#define retrans_dbg(fmt, ...) \
do { \
	if (get_ack_retrans_debug()) \
		pr_crit(fmt, ##__VA_ARGS__); \
} while (0)

#endif /* _TCP_NIP_PARAMETER_H */
