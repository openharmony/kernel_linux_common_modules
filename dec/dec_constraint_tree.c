// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include "dec_constraint_tree.h"
#include "dec_common.h"
#include "dec_log.h"
#include "dec_utils.h"

static struct trie_node *constraint_tree = NULL;
static struct rw_semaphore *dec_constraint_rwsem = NULL;

static int __init dec_constraint_tree_init(void)
{
    dec_constraint_rwsem = kmalloc(sizeof(struct rw_semaphore), GFP_KERNEL);
    if (!dec_constraint_rwsem) {
        dec_loge("Failed to allocate rwsem for constraint tree");
        return -ENOMEM;
    }
    init_rwsem(dec_constraint_rwsem);

    constraint_tree = trie_node_create("/");
    if (!constraint_tree) {
        kfree(dec_constraint_rwsem);
        dec_constraint_rwsem = NULL;
        dec_loge("Failed to create root node for constraint tree");
        return -ENOMEM;
    }
    dec_logd("Constraint tree initialized successfully");
    return 0;
}

bool dec_constraint_query(const char *path)
{
    struct list_head comp_list;
    struct trie_node *node = constraint_tree;
    struct path_component *comp = NULL;
    bool found = false;

    INIT_LIST_HEAD(&comp_list);

    if (split_path_to_component_list(path, &comp_list) < 0) {
        free_component_list(&comp_list);
        return found;
    }

    down_read(dec_constraint_rwsem);
    /* Check root node first */
    if (node->has_permissions) {
        found = true;
        goto cleanup;
    }
    /* Traverse path components to check child nodes */
    list_for_each_entry(comp, &comp_list, list) {
        node = find_child(node, comp->name);
        if (node == NULL) {
            goto cleanup;
        }

        if (node->has_permissions) {
            found = true;
            goto cleanup;
        }
    }
cleanup:
    up_read(dec_constraint_rwsem);
    free_component_list(&comp_list);
    return found;
}

int dec_constraint_add(char *path)
{
    if (is_path_valid(path) != 0) {
        dec_loge("Invalid path for constraint add: %s", path);
        return -EINVAL;
    }
    int ret = 0;
    struct trie_node *node = constraint_tree;
    struct list_head comp_list;
    INIT_LIST_HEAD(&comp_list);

    ret = split_path_to_component_list(path, &comp_list);
    if (ret < 0) {
        dec_loge("Failed to split path components for add: %s (err=%d)", path, ret);
        free_component_list(&comp_list);
        return ret;
    }

    down_write(dec_constraint_rwsem);
    struct path_component *comp;
    list_for_each_entry(comp, &comp_list, list) {
        struct trie_node *child = find_child(node, comp->name);
        if (child == NULL) {
            child = insert_child(node, comp->name);
            if (child == NULL) {
                dec_loge("Failed to allocate child node for %s", comp->name);
                ret = -ENOMEM;
                goto cleanup;
            }
        }
        node = child;
    }

    node->has_permissions = true;
    dec_logi("Constraint added for path: %s", path);
cleanup:
    up_write(dec_constraint_rwsem);
    free_component_list(&comp_list);
    return ret;
}

/* Register initialization function for filesystem init phase */
fs_initcall(dec_constraint_tree_init);