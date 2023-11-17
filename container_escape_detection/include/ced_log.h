/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CED_LOG_H
#define _CED_LOG_H

#define CED_CHECK_FAILED (-1024)

#define CED_TAG "ced_kernel"
#define CED_INFO_TAG  "I"
#define CED_ERROR_TAG "E"
#define CED_DEBUG_TAG "D"

#define ced_log_info(fmt, args...) pr_info("[%s/%s]%s: " fmt "\n", \
	CED_INFO_TAG, CED_TAG, __func__, ##args)

#define ced_log_error(fmt, args...) pr_err("[%s/%s]%s: " fmt "\n", \
	CED_ERROR_TAG, CED_TAG, __func__, ##args)

#endif /* _CED_LOG_H */