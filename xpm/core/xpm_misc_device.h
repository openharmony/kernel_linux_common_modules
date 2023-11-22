/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_MISC_DEVICE_H
#define _XPM_MISC_DEVICE_H

#include <linux/xpm_types.h>

#define MAX_OWNERID_LEN 64

struct xpm_config {
	uint64_t region_addr;
	uint64_t region_length;

	uint32_t id_type;
	char ownerid[MAX_OWNERID_LEN];
};

int xpm_register_misc_device(void);
void xpm_deregister_misc_device(void);

#endif /* _XPM_MISC_DEVICE_H */
