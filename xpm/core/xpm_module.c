// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "dsmm_developer.h"
#include "xpm_debugfs.h"
#include "xpm_hck_hooks.h"
#include "xpm_misc_device.h"
#include "xpm_security_hooks.h"
#include "xpm_report.h"
#include "xpm_log.h"

static int __init xpm_module_init(void)
{
	int ret;

	ret = xpm_register_misc_device();
	if (ret) {
		xpm_log_error("xpm register misc device failed, ret = %d", ret);
		report_init_event(DEVICEFS_UNINIT);
		return ret;
	}

	ret = xpm_debugfs_init();
	if (ret) {
		xpm_log_error("xpm init debugfs failed, ret = %d", ret);
		xpm_deregister_misc_device();
		report_init_event(DEBUGFS_UNINIT);
		return ret;
	}

	xpm_register_security_hooks();
	xpm_register_hck_hooks();

	dsmm_developer_proc_create();

	xpm_log_info("xpm module init success");
	return 0;
}

static void __exit xpm_module_exit(void)
{
	xpm_deregister_misc_device();
	xpm_debugfs_exit();

	dsmm_developer_proc_clean();

	xpm_log_info("xpm module exit success");
}

module_init(xpm_module_init);
module_exit(xpm_module_exit);
MODULE_LICENSE("GPL");
