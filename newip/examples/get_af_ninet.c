// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#define AF_NINET_PATH        ("/sys/module/newip/parameters/af_ninet")
#define AF_NINET_LENTH       (5)

int g_af_ninet;

void _get_af_ninet(void)
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

	fclose(fn);
	g_af_ninet = atoi(tmp);
}

int get_af_ninet(void)
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

