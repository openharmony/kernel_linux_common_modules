// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _JIT_MEMORY_LOG_H
#define _JIT_MEMORY_LOG_H

#define JIT_MEMORY_CHECK_FAILED (-1024)

#define JIT_MEMORY_TAG "jit_memory_kernel"
#define JIT_MEMORY_INFO_TAG "I"
#define JIT_MEMORY_ERROR_TAG "E"

#define jit_memory_log_info(fmt, args...) \
	pr_info("[%s/%s]%s: " fmt "\n", JIT_MEMORY_INFO_TAG, JIT_MEMORY_TAG, \
	__func__, ##args)

#define jit_memory_log_error(fmt, args...) \
	pr_err("[%s/%s]%s: " fmt "\n", JIT_MEMORY_ERROR_TAG, JIT_MEMORY_TAG, \
	__func__, ##args)
#endif /* _JIT_MEMORY_LOG_H */