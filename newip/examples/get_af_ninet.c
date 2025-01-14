// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: get af ninet.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define AF_NINET_PATH        ("/sys/module/newip/parameters/af_ninet")
#define AF_NINET_LENTH       (5)

int g_af_ninet;

static void _get_af_ninet(void)
{
	char tmp[AF_NINET_LENTH];
	FILE *fn = fopen(AF_NINET_PATH, "r");

	if (!fn) {
		printf("fail to open %s\n\n", AF_NINET_PATH);
		return;
	}

	if (fgets(tmp, AF_NINET_LENTH, fn) == NULL) {
		printf("fail to gets %s\n\n", AF_NINET_PATH);
		fclose(fn);
		return;
	}

	if (fclose(fn) == EOF) {
		printf("fclose failed\n");
		return;
	}
	g_af_ninet = atoi(tmp);
}

static int get_af_ninet(void)
{
	if (g_af_ninet == 0)
		_get_af_ninet();

	return g_af_ninet;
}

int main(int argc, char **argv)
{
	printf("af_ninet=%d\n\n", get_af_ninet());
	return 0;
}

