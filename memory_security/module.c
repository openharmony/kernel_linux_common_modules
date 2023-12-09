// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/module.h>
#include "jit_memory_module.h"
#include "hideaddr.h"

int __init mem_security_hooks_init(void)
{
	hideaddr_header_prefix_lhck_register();
	jit_memory_register_hooks();
	return 0;
}

static void __exit mem_security_hooks_exit(void)
{
}

module_init(mem_security_hooks_init);
module_exit(mem_security_hooks_exit);