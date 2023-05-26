// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: Demo example of NewIP udp client.
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

#define __USE_GNU
#include <sched.h>
#include <pthread.h>

#include "nip_uapi.h"
#include "nip_lib.h"
#include "newip_route.h"

int _sendto(int cfd, struct sockaddr_nin *si_server, int pkt_num)
{
	char buf[BUFLEN] = {0};
	struct timeval sys_time;
	socklen_t slen = sizeof(struct sockaddr_nin);
	int ret;

	gettimeofday(&sys_time, NULL);
	ret = sprintf(buf, "%ld %6ld NIP_UDP # %6d", sys_time.tv_sec, sys_time.tv_usec, pkt_num);
	if (ret < 0) {
		printf("sprintf failed");
		return -1;
	}
	if (sendto(cfd, buf, BUFLEN, 0, (struct sockaddr *)si_server, slen) < 0) {
		printf("client sendto fail, pkt_num=%d", pkt_num);
		return -1;
	}

	return 0;
}

int _recvfrom(int cfd, struct sockaddr_nin *si_server, int pkt_num, int *success)
{
	char buf[BUFLEN] = {0};
	fd_set readfds;
	int tmp;
	struct timeval tv;
	socklen_t slen = sizeof(struct sockaddr_nin);

	FD_ZERO(&readfds);
	FD_SET(cfd, &readfds);
	tv.tv_sec = TIMEOUT_SEC;
	tv.tv_usec = 0;
	if (select(cfd + 1, &readfds, NULL, NULL, &tv) < 0) {
		printf("client select fail, pkt_num=%d", pkt_num);
		return -1;
	}

	if (FD_ISSET(cfd, &readfds)) {
		int ret;
		int no = 0;

		ret = recvfrom(cfd, buf, BUFLEN, 0, (struct sockaddr *)si_server, &slen);
		if (ret > 0) {
			*success += 1;
			ret = sscanf(buf, "%d %d NIP_UDP # %d", &tmp, &tmp, &no);
			if (ret)
				printf("Received --%s sock %d success:%6d/%6d/no=%6d\n",
				       buf, cfd, *success, pkt_num + 1, no);
		} else {
			printf("client recvfrom fail, ret=%d\n", ret);
			return -1;
		}
	}

	return 0;
}

void *send_recv(void *args)
{
	int success = 0;
	int cfd = ((struct thread_args *)args)->cfd;
	struct sockaddr_nin si_server = ((struct thread_args *)args)->si_server;

	for (int i = 0; i < PKTCNT; i++) {
		if (_sendto(cfd, &si_server, i) != 0)
			goto END;

		if (_recvfrom(cfd, &si_server, i, &success) != 0)
			goto END;

		usleep(SLEEP_US);
	}

END:	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	int cfd;
	struct thread_args th_args;
	struct sockaddr_nin si_server;

	cfd = socket(AF_NINET, SOCK_DGRAM, IPPROTO_UDP);
	if (cfd < 0) {
		perror("socket");
		return -1;
	}

	memset((char *)&si_server, 0, sizeof(si_server));
	si_server.sin_family = AF_NINET;
	si_server.sin_port = htons(UDP_SERVER_PORT);
	// 2-byte address of the server: 0xDE00
	si_server.sin_addr.nip_addr_field8[INDEX_0] = 0xDE;
	si_server.sin_addr.nip_addr_field8[INDEX_1] = 0x00;
	si_server.sin_addr.bitlen = NIP_ADDR_BIT_LEN_16; // 2-byte: 16bit

	th_args.si_server = si_server;
	th_args.si_server.sin_port = htons(UDP_SERVER_PORT);
	th_args.cfd = cfd;
	pthread_create(&th, NULL, send_recv, &th_args);
	/* Wait for the thread to end and synchronize operations between threads */
	pthread_join(th, NULL);
	close(cfd);
	return 0;
}

