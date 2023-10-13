/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef DSMM_DEVELOPER_H
#define DSMM_DEVELOPER_H

#define DEVELOPER_STATUS_ON "true"
#define DEVELOPER_STATUS_OFF "false"

enum build_variant {
	BUILD_VARIANT_USER = 0,
	BUILD_VARIANT_ENG,
	BUILD_VARIANT_MAX,
};

enum developer_proc_status {
	DEVELOPER_PROC_STATUS_NA = 0,
	DEVELOPER_PROC_STATUS_ON,
	DEVELOPER_PROC_STATUS_OFF,
	DEVELOPER_PROC_STATUS_MAX,
};

const char *developer_mode_state(void);

void dsmm_developer_proc_create(void);

void dsmm_developer_proc_clean(void);

#endif // DSMM_DEVELOPER_H
