/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_LOG_H
#define _XPM_LOG_H

#define XPM_CHECK_FAILED (-1024)

#define XPM_TAG "xpm_kernel"
#define XPM_INFO_TAG  "I"
#define XPM_ERROR_TAG "E"
#define XPM_DEBUG_TAG "D"

#define xpm_log_info(fmt, args...) pr_info("[%s/%s]%s: " fmt "\n", \
	XPM_INFO_TAG, XPM_TAG, __func__, ##args)

#define xpm_log_error(fmt, args...) pr_err("[%s/%s]%s: " fmt "\n", \
	XPM_ERROR_TAG, XPM_TAG, __func__, ##args)

#ifdef CONFIG_SECURITY_XPM_DEBUG
#define xpm_log_debug(fmt, args...) pr_info("[%s/%s]%s: " fmt "\n", \
	XPM_DEBUG_TAG, XPM_TAG, __func__, ##args)
#else
#define xpm_log_debug(fmt, args...) no_printk(fmt, ##args)
#endif

#endif /* _XPM_LOG_H */
