// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _CED_DETECTION_H
#define _CED_DETECTION_H

#include <linux/cred.h>
#include <linux/sched.h>

void ced_initialize(void);
void detection_hook(struct task_struct *task);
void setattr_insert_hook(struct task_struct *task);
void exit_hook(struct task_struct *task);
void switch_task_namespaces_hook(const struct nsproxy *new);
void commit_creds_hook(const struct cred *new);
void kernel_clone_hook(struct task_struct *task);
bool ced_has_check_perm(void);

#endif /* _CED_DETECTION_H */