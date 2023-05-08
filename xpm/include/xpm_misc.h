/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_MISC_H
#define _XPM_MISC_H

struct xpm_region_info {
	unsigned long addr_base;
	unsigned long length;
};

int xpm_register_misc_device(void);
void xpm_deregister_misc_device(void);

#endif /* _XPM_MISC_H */
