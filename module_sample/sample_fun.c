// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * ko sample
 *
 * Author: z-jax <zhujiaxin@huawei.com>
 *
 * Data: 2023-11-25
 */

#include <linux/init.h>
#include <linux/module.h>

int kosample_fun(void)
{
	pr_info("ko sample call: %s\n", __func__);
	return 0;
}

