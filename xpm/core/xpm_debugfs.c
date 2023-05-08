// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/debugfs.h>
#include "xpm_log.h"
#include "xpm_debugfs.h"

extern uint8_t xpm_mode;
static struct dentry *xpm_dir;

int xpm_debugfs_init(void)
{
	xpm_dir = debugfs_create_dir("xpm", NULL);
	if (!xpm_dir) {
		xpm_log_error("create xpm debugfs dir failed");
		return -EINVAL;
	}

	debugfs_create_u8("xpm_mode", 0600, xpm_dir, &xpm_mode);

	return 0;
}

void xpm_debugfs_exit(void)
{
	debugfs_remove_recursive(xpm_dir);
}
