// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Description: check NewIP enable.
 *
 * Author: Yang Yanjun <yangyanjun@huawei.com>
 *
 * Data: 2022-09-06
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define NIP_DISABLE_PATH        ("/sys/module/newip/parameters/disable")
#define NIP_DISABLE_LENTH       (5)
#define NIP_ENABLE_INVALID      (0xFF)

int g_nip_enable = NIP_ENABLE_INVALID;

void _check_nip_enable(void)
{
	char tmp[NIP_DISABLE_LENTH];
	FILE *fn = fopen(NIP_DISABLE_PATH, "r");

	if (!fn) {
		printf("fail to open %s\n\n", NIP_DISABLE_PATH);
		return;
	}

	if (fgets(tmp, NIP_DISABLE_LENTH, fn) == NULL) {
		printf("fail to gets %s\n\n", NIP_DISABLE_PATH);
		fclose(fn);
		return;
	}

	if (fclose(fn) == EOF) {
		printf("fclose failed\n");
		return;
	}
	g_nip_enable = atoi(tmp) ? 0 : 1;
}

bool check_nip_enable(void)
{
	if (g_nip_enable == NIP_ENABLE_INVALID) {
		_check_nip_enable();
		g_nip_enable = (g_nip_enable == 1 ? 1 : 0);
	}

	return g_nip_enable;
}

int main(int argc, char **argv)
{
	int af_ninet = check_nip_enable();

	if (af_ninet)
		printf("Support NewIP\n\n");
	else
		printf("Not support NewIP\n\n");
	return 0;
}

