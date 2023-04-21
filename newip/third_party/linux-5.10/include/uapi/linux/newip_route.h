/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Based on include/uapi/linux/ipv6_route.h
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *
 * Linux NewIP INET implementation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_NEWIP_ROUTE_H
#define _UAPI_LINUX_NEWIP_ROUTE_H

#include "nip_addr.h"

struct nip_rtmsg {
	struct nip_addr rtmsg_dst;
	struct nip_addr rtmsg_src;
	struct nip_addr rtmsg_gateway;
	char dev_name[10];
	unsigned int rtmsg_type;
	int rtmsg_ifindex;
	unsigned int rtmsg_metric;
	unsigned long rtmsg_info;
	unsigned int rtmsg_flags;
};
#endif /* _UAPI_LINUX_NEWIP_ROUTE_H */
