// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of NewIP tcp client.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "nip_uapi.h"
#include "nip_lib.h"
#include "newip_route.h"

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

int _send(int cfd, int pkt_num)
{
	char buf[BUFLEN] = {0};
	struct timeval sys_time;
	int ret;

	gettimeofday(&sys_time, NULL);
	ret = sprintf(buf, "%ld %6ld NIP_TCP # %6d", sys_time.tv_sec, sys_time.tv_usec, pkt_num);
	if (ret < 0) {
		printf("sprintf failed\n");
		return -1;
	}
	if (send(cfd, buf, PKTLEN, 0) < 0) {
		perror("sendto");
		return -1;
	}

	return 0;
}

int _recv(int cfd, int pkt_num, int *success)
{
	char buf[BUFLEN] = {0};
	fd_set readfds;
	int tmp;
	struct timeval tv;

	FD_ZERO(&readfds);
	FD_SET(cfd, &readfds);
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	if (select(cfd + 1, &readfds, NULL, NULL, &tv) < 0) {
		perror("select");
		return -1;
	}

	if (FD_ISSET(cfd, &readfds)) {
		int ret;
		int no = 0;

		ret = recv(cfd, buf, PKTLEN, MSG_WAITALL);
		if (ret > 0) {
			*success += 1;
			ret = sscanf(buf, "%d %d NIP_TCP # %d", &tmp, &tmp, &no);
			if (ret <= 0) {
				perror("sscanf");
				return -1;
			}
			printf("Received --%s sock %d success:%6d/%6d/no=%6d\n",
			       buf, cfd, *success, pkt_num + 1, no);
		} else {
			printf("recv fail, ret=%d\n", ret);
			return -1;
		}
	}

	return 0;
}

void *send_recv(void *args)
{
	int cfd = ((struct thread_args *)args)->cfd;
	int success = 0;

	for (int i = 0; i < PKTCNT; i++) {
		if (_send(cfd, i) != 0)
			goto END;

		if (_recv(cfd, i, &success) != 0)
			goto END;

		usleep(SLEEP_US);
	}

END:	return NULL;
}

int main(int argc, char **argv)
{
	int cfd;
	pthread_t th;
	struct thread_args th_args;
	struct sockaddr_nin si_server;

	cfd = socket(AF_NINET, SOCK_STREAM, IPPROTO_TCP);
	if (cfd < 0) {
		perror("socket");
		return -1;
	}
	printf("creat newip socket, fd=%d\n", cfd);

	memset((char *)&si_server, 0, sizeof(si_server));
	si_server.sin_family = AF_NINET;
	si_server.sin_port = htons(TCP_SERVER_PORT);
	// 2-byte address of the server: 0xDE00
	si_server.sin_addr.NIP_ADDR_FIELD8[INDEX_0] = 0xDE;
	si_server.sin_addr.NIP_ADDR_FIELD8[INDEX_1] = 0x00;
	si_server.sin_addr.bitlen = NIP_ADDR_BIT_LEN_16; // 2-byte: 16bit
	if (connect(cfd, (struct sockaddr *)&si_server, sizeof(si_server)) < 0) {
		perror("connect");
		return -1;
	}
	printf("connect success, addr=0x%02x%02x, port=%d\n",
	       si_server.sin_addr.NIP_ADDR_FIELD8[INDEX_0],
	       si_server.sin_addr.NIP_ADDR_FIELD8[INDEX_1], TCP_SERVER_PORT);

	th_args.si_server = si_server;
	th_args.si_server.sin_port = htons(TCP_SERVER_PORT);
	th_args.cfd = cfd;
	pthread_create(&th, NULL, send_recv, &th_args);
	/* Wait for the thread to end and synchronize operations between threads */
	pthread_join(th, NULL);
	close(cfd);
	return 0;
}

