// SPDX-License-Identifier: GPL-2.0
/*
 * ko sample
 *
 */

#include <linux/init.h>
#include <linux/module.h>

int kosample_fun(void)
{
	pr_info("ko sample call: %s\n", __func__);
	return 0;
}

