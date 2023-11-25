// SPDX-License-Identifier: GPL-2.0
/*
 * ko sample
 *
 */

#include <linux/init.h>
#include <linux/module.h>

static int kosample_init(void)
{
	pr_info("ko sample: %s\n", __func__);
	return 0;
}
static void kosample_exit(void)
{
	pr_info("ko sample: %s\n", __func__);
}

module_init(kosample_init);
module_exit(kosample_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("zhujiaxin <zhujiaxin@huawei.com>");
