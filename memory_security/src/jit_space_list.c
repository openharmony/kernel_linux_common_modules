// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/list.h>
#include "jit_space_list.h"

inline struct jit_space_node *init_jit_space_node(unsigned long begin, unsigned long end)
{
	struct jit_space_node *new = kmalloc(sizeof(struct jit_space_node), GFP_KERNEL);
	if (new == NULL) {
		jit_memory_log_error("malloc for jit_space_node failed");
		return NULL;
	}
	new->begin = begin;
	new->end = end;
	return new;
}

const void find_jit_space(struct list_head *head, unsigned long begin, unsigned long size, int *err)
{
	unsigned long end = begin + size;
	struct jit_space_node *node;
	struct list_head *cur;

	list_for_each(cur, head)
	{
		node = list_entry(cur, struct jit_space_node, head);
		if (node->begin <= begin && node->end >= end) {
			*err = 0;
			return;
		}
	}
	*err = -EACCES;
}

void update_jit_space(struct list_head *head, unsigned long begin, unsigned long size)
{
	unsigned long end = begin + size;

	struct jit_space_node *new = init_jit_space_node(begin, end);
	if (new == NULL)
		return;
	list_add(&(new->head), head);

	struct jit_space_node *now = list_entry(head->next, struct jit_space_node, head);
}

void delete_jit_space(struct list_head *head, unsigned long begin, unsigned long size, int *err)
{
	unsigned long end = begin + size;
	struct jit_space_node *node;
	struct list_head *cur;

	list_for_each(cur, head) {
		node = list_entry(cur, struct jit_space_node, head);

		if (begin >= node->begin && end <= node->end) {
			if (begin == node->begin && end == node->end) { // [| cut&node |]
				list_del(cur);
				kfree(node);
			} else if (begin != node->begin && end != node->end) { // [ node | cut | node ]
				struct jit_space_node *new = init_jit_space_node(end, node->end);
				if (new == NULL) {
					*err = -ENOMEM;
					return;
				}
				node->end = begin;
				list_add(&(new->head), cur);
			} else if (begin != node->begin) { // [ node | cut |]
				node->end == begin;
			} else if (end != node->end) { // [| cut | node ]
				node->begin = end;
			}
			return;
		}
	}
}

void exit_jit_space(struct list_head *head)
{
	struct list_head *cur, *next;
	struct jit_space_node *node;

	list_for_each_safe(cur, next, head) {
		node = list_entry(cur, struct jit_space_node, head);
		list_del(cur);
		kfree(node);
	}
}