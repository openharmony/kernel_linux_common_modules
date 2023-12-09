// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _JIT_SPACE_LIST_H
#define _JIT_SPACE_LIST_H

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <asm-generic/errno-base.h>

#include "jit_memory_log.h"
static struct rb_root root_tree = RB_ROOT;

extern struct jit_process {
	int pid; // pid is the key and cookie is value in rbTree
	unsigned long cookie;
	struct rb_node node;
	struct list_head head;
};

extern struct jit_space_node {
	unsigned long begin, end;
	struct list_head head;
};

inline struct jit_space_node *init_jit_space_node(unsigned long begin, unsigned long end);

const void find_jit_space(struct list_head *head, unsigned long begin, unsigned long size, int *err);
void update_jit_space(struct list_head *head, unsigned long begin, unsigned long size);
void delete_jit_space(struct list_head *head, unsigned long begin, unsigned long size, int *err);
void exit_jit_space(struct list_head *head);


#endif //_JIT_SPACE_LIST_H