// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _JIT_PROCESS_H
#define _JIT_PROCESS_H

#include "jit_space_list.h"

struct result_of_find_process {
	struct rb_node **node, *parent;
	struct list_head *head;
};


struct result_of_find_process find_process_jit_space(struct rb_root *root, int pid);
struct list_head *update_process_jit_space(struct rb_root *root, int pid, unsigned long cookie, int *err);
struct jit_process *delete_process_jit_space(struct rb_root *root, int pid);
#endif // _JIT_PROCESS_H