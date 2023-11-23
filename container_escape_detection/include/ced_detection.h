// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CED_DETECTION_H
#define _CED_DETECTION_H

#include <linux/cred.h>
#include <linux/sched.h>

void detection_hook(struct task_struct *task);
void switch_task_namespaces_hook(const struct nsproxy *new);
void commit_creds_hook(const struct cred *new);

#endif /* _CED_DETECTION_H */