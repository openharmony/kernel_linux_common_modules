// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#ifndef _DEC_COMMON_H
#define _DEC_COMMON_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* Dec operation modes */
#define DEC_NONE          0
#define DEC_READ          (1 << 0)
#define DEC_WRITE         (1 << 1)
#define DEC_PREFIX        (1 << 9)

#define DEC_TOKENID_MASK 0x00000000FFFFFFFF

/**
 * struct permission - Permission entry for a token
 * @tokenid: Unique token identifier
 * @mode: Access mode (allowed DEC_READ/DEC_WRITE)
 * @userid: User identifier associated with this permission
 * @persist_flag: Whether this permission should be persisted
 * @timestamp: Time when permission was created/updated
 * @rb_node: Red-black tree node for insertion into rb_root
 */
struct permission {
    uint64_t tokenid;
    uint32_t mode;
    int userid;
    bool persist_flag;
    uint64_t timestamp;
    struct rb_node rb_node;
};

/**
 * struct trie_node - Trie node for path-based permission storage
 * @component: Path component (directory/file name)
 * @permissions: RB root containing permission entries for this path
 * @children: RB root containing child trie nodes
 * @has_permissions: Flag indicating if this node has active permissions
 * @rb_node: RB node for sorting children
 */
struct trie_node {
    char *component;
    struct rb_root permissions;
    struct rb_root children;
    bool has_permissions;
    struct rb_node rb_node;
};

/**
 * struct trie_stack_item - Stack item for trie traversal
 * @node: Current trie node being processed
 * @parent: Parent node of the current node
 * @child_key: Child component name being looked up
 * @visited_children: Flag indicating if children have been processed
 * @list: List head for linking stack items
 */
struct trie_stack_item {
    struct trie_node *node;
    struct trie_node *parent;
    char *child_key;
    bool visited_children;
    struct list_head list;
};

/**
 * struct path_component - Linked list node for path component decomposition
 * @list: List head for linking components
 * @name: Name of the path component
 */
struct path_component {
    struct list_head list;
    char name[0];
};

/**
 * struct path_tree_params - Parameters for path tree operations
 * @path: Target path for permission operation
 * @tokenid: Token ID to apply permissions
 * @mode: Access mode
 * @userid: User ID for the permission
 * @persist_flag: Persistence flag for the permission
 * @timestamp: Timestamp for the permission
 */
struct path_tree_params {
    const char *path;
    uint64_t tokenid;
    uint32_t mode;
    int userid;
    bool persist_flag;
    uint64_t timestamp;  
};

#endif /* _DEC_COMMON_H */