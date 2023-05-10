/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_MISC_H
#define _XPM_MISC_H

#include <linux/types.h>

struct xpm_region_info {
	uint64_t addr_base;
	uint64_t length;
};

int xpm_register_misc_device(void);
void xpm_deregister_misc_device(void);

#endif /* _XPM_MISC_H */
