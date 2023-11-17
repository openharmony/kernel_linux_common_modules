// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/module.h>
#include <linux/hck/lite_hck_ced.h>
#include "ced_detection.h"
#include "ced_log.h"

void ced_register_ced_hooks(void)
{
    REGISTER_HCK_LITE_HOOK(ced_detection_lhck, detection_hook);
    REGISTER_HCK_LITE_HOOK(ced_switch_task_namespaces_lhck, switch_task_namespaces_hook);
    REGISTER_HCK_LITE_HOOK(ced_commit_creds_lhck, commit_creds_hook);
    ced_log_info("ced_register_ced_hooks");
}

static int __init ced_module_init(void)
{
    ced_register_ced_hooks();
    return 0;
}

module_init(ced_module_init);
MODULE_LICENSE("GPL");