// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/module.h>
#include <linux/hck/lite_hck_jit_memory.h>
#include <linux/hck/lite_vendor_hooks.h>
#include "jit_memory.h"
#include "jit_memory_module.h"

void jit_memory_register_hooks(void)
{
	REGISTER_HCK_LITE_HOOK(find_jit_memory_lhck, find_jit_memory);
	REGISTER_HCK_LITE_HOOK(check_jit_memory_lhck, check_jit_memory);
	REGISTER_HCK_LITE_HOOK(delete_jit_memory_lhck, delete_jit_memory);
	REGISTER_HCK_LITE_HOOK(exit_jit_memory_lhck, exit_jit_memory);
	jit_memory_log_info("jit_memory_register_hooks");
}

MODULE_LICENSE("GPL");