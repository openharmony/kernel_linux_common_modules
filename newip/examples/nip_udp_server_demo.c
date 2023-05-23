// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of NewIP udp server.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include "nip_uapi.h"
#include "nip_lib.h"
#include "newip_route.h"

void *recv_send(void *args)
{
	char buf[BUFLEN] = {0};
	int fd, ret, recv_num;
	int count = 0;
	socklen_t slen;
	struct sockaddr_nin si_remote;

	memcpy(&fd, args, sizeof(int));
	while (count < PKTCNT) {
		slen = sizeof(si_remote);
		memset(buf, 0, sizeof(char) * BUFLEN);
		memset(&si_remote, 0, sizeof(si_remote));
		recv_num = recvfrom(fd, buf, BUFLEN, 0, (struct sockaddr *)&si_remote, &slen);
		if (recv_num < 0) {
			printf("server recvfrom fail, ret=%d\n", ret);
			goto END;
		} else if (recv_num == 0) { /* no data */
			;
		} else {
			printf("Received -- %s -- from 0x%x:%d\n", buf,
			       si_remote.sin_addr.nip_addr_field16[0], ntohs(si_remote.sin_port));
			slen = sizeof(si_remote);
			ret = sendto(fd, buf, BUFLEN, 0, (struct sockaddr *)&si_remote, slen);
			if (ret < 0) {
				printf("server sendto fail, ret=%d\n", ret);
				goto END;
			}
			printf("Sending  -- %s -- to 0x%0x:%d\n", buf,
			       si_remote.sin_addr.nip_addr_field8[0], ntohs(si_remote.sin_port));
		}
		count++;
	}
END:	return NULL;
}

int main(int argc, char **argv)
{
	int fd;
	pthread_t th;
	struct sockaddr_nin si_local;

	fd = socket(AF_NINET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset((char *)&si_local, 0, sizeof(si_local));
	si_local.sin_family = AF_NINET;
	si_local.sin_port = htons(UDP_SERVER_PORT);
	// 2-byte address of the server: 0xDE00
	si_local.sin_addr.nip_addr_field8[INDEX_0] = 0xDE;
	si_local.sin_addr.nip_addr_field8[INDEX_1] = 0x00;
	si_local.sin_addr.bitlen = NIP_ADDR_BIT_LEN_16; // 2-byte: 16bit

	if (bind(fd, (const struct sockaddr *)&si_local, sizeof(si_local)) < 0) {
		perror("bind");
		goto END;
	}

	printf("bind success, addr=0x%02x%02x, port=%d\n",
	       si_local.sin_addr.nip_addr_field8[INDEX_0],
	       si_local.sin_addr.nip_addr_field8[INDEX_1], UDP_SERVER_PORT);

	pthread_create(&th, NULL, recv_send, &fd);
	/* Wait for the thread to end and synchronize operations between threads */
	pthread_join(th, NULL);

END:	close(fd);
	return 0;
}

