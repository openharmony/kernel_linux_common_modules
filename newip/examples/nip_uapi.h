/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */
#ifndef _NIP_UAPI_H
#define _NIP_UAPI_H

#include "nip.h"

/* The following structure must be larger than V4. System calls use V4.
 * If the definition is smaller than V4, the read process will have memory overruns
 * v4: include\linux\socket.h --> sockaddr (16Byte)
 */
#define POD_SOCKADDR_SIZE 3
struct sockaddr_nin {
	unsigned short sin_family; /* [2Byte] AF_NINET */
	unsigned short sin_port;   /* [2Byte] Transport layer port, big-endian */
	struct nip_addr sin_addr;  /* [9Byte] NIP address */

	unsigned char sin_zero[POD_SOCKADDR_SIZE]; /* [3Byte] Byte alignment */
};

struct nip_ifreq {
	struct nip_addr ifrn_addr;
	int ifrn_ifindex;
};

struct thread_args {
	int cfd;
	struct sockaddr_nin si_server;
};

#endif /* _NIP_UAPI_H */
