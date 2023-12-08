// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CED_PERMISSION_H
#define _CED_PERMISSION_H

#include <linux/cred.h>
#include <linux/sched.h>

void switch_task_namespaces_permission_hook(const struct nsproxy *new, int *ret);

#endif /* _CED_PERMISSION_H */