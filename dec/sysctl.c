// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/sysctl.h>

#include "sysctl.h"
#include "dec_log.h"

int dec_mode = 1;
#define dec_console_loglevel dec_mode

static int dec_proc_dointvec(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	dec_logi("dec_mode changed to %d", dec_console_loglevel);
	return proc_dointvec(table, write, buffer, lenp, ppos);
}

static struct ctl_table dec_sysctls[] = {
	{
		.procname	= "dec_mode",
		.data		= &dec_console_loglevel,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= dec_proc_dointvec,
	},
	{}
};

void __init dec_sysctl_init(void)
{
#ifdef CONFIG_SECURITY_DEC_DEVELOP
	register_sysctl_init("kernel", dec_sysctls);
#endif
}
