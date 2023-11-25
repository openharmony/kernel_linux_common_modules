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

static int kosample_init(void)
{
	pr_err("ko sample: %s\n", __func__);
	return 0;
}
static void kosample_exit(void)
{
	pr_err("ko sample: %s\n", __func__);
}

module_init(kosample_init);
module_exit(kosample_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("z-jax <zhujiaxin@huawei.com>");
