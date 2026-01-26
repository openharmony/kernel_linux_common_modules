// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_LOG_H
#define _DEC_LOG_H

#include <linux/printk.h>

#define DEC_LOG_PREFIX "DEC: "

#define dec_logd(fmt, ...) pr_debug(DEC_LOG_PREFIX fmt, ##__VA_ARGS__)
#define dec_logi(fmt, ...) pr_info(DEC_LOG_PREFIX fmt, ##__VA_ARGS__)
#define dec_logw(fmt, ...) pr_warn(DEC_LOG_PREFIX fmt, ##__VA_ARGS__)
#define dec_loge(fmt, ...) pr_err(DEC_LOG_PREFIX fmt, ##__VA_ARGS__)
#define dec_logf(fmt, ...) pr_crit(DEC_LOG_PREFIX fmt, ##__VA_ARGS__)

#endif /* _DEC_LOG_H */