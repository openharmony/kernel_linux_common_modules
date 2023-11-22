/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _DSMM_DEVELOPER_H
#define _DSMM_DEVELOPER_H

#define STATE_UNINT 0
#define STATE_ON    1
#define STATE_OFF   2

enum build_variant {
	BUILD_VARIANT_USER = 0,
	BUILD_VARIANT_ENG,

	BUILD_VARIANT_MAX,
};

enum cmdline_dev_state {
	CMDLINE_DEV_STATE_NA = 0,
	CMDLINE_DEV_STATE_ON,
	CMDLINE_DEV_STATE_OFF,

	CMDLINE_DEV_STATE_MAX,
};

void dsmm_developer_proc_create(void);
void dsmm_developer_proc_clean(void);

/**
 * get_developer_mode_state - Get developer state of the device.
 *
 * @state:    State of the device.
 *
 * Returns the developer state, STATE_ON or STATE_OFF.
 */
int get_developer_mode_state(void);

#endif /* _DSMM_DEVELOPER_H */
