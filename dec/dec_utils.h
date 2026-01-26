// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_UTILS_H
#define _DEC_UTILS_H

#include "dec_common.h"

int is_path_valid(const char *path);
struct trie_node *trie_node_create(const char *component);
struct trie_node *find_child(struct trie_node *node, const char *component);
struct trie_node *insert_child(struct trie_node *parent, const char *component);
void trie_node_destroy(struct trie_node *node);
int split_path_to_component_list(const char *path, struct list_head *comp_list);
void free_component_list(struct list_head *comp_list);

#endif /* _DEC_UTILS_H */