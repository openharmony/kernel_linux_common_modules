// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rwsem.h>
#include <linux/errno.h>

#include "dec_path_tree.h"
#include "dec_common.h"
#include "dec_utils.h"
#include "dec_log.h"

/* Prefix tokenid greater then tokenid mask */
#define PREFIX_TOKENID  (1ULL << 32)
#define PREFIX_USERID   (1 << 30)

enum query_state {
    DEC_INIT,
    DEC_ALLOWED,
    DEC_NOT_ALLOWED,
};

static struct trie_node *path_tree = NULL;
static struct rw_semaphore *dec_path_tree_rwsem = NULL;

static int __init dec_path_tree_init(void)
{
    dec_path_tree_rwsem = kmalloc(sizeof(struct rw_semaphore), GFP_KERNEL);
    if (!dec_path_tree_rwsem) {
        dec_loge("Failed to allocate rwsem for path tree");
        return -ENOMEM;
    }
    init_rwsem(dec_path_tree_rwsem);
    
    path_tree = trie_node_create("/");
    if (!path_tree) {
        dec_loge("Failed to create root node for path tree");
        kfree(dec_path_tree_rwsem);
        dec_path_tree_rwsem = NULL;
        return -ENOMEM;
    }
    dec_logd("Path tree initialized successfully");
    return 0;
}

static struct list_head *create_path_stack(void)
{
    struct list_head *stack = kmalloc(sizeof(struct list_head), GFP_KERNEL);
    if (!stack) {
        dec_loge("Failed to allocate memory for path stack");
        return NULL;
    }

    INIT_LIST_HEAD(stack);
    return stack;
}

static int add_to_path_stack(struct list_head *stack, struct trie_node *node, 
                            struct trie_node *parent, const char *child_key)
{
    struct trie_stack_item *item = kmalloc(sizeof(struct trie_stack_item), GFP_KERNEL);
    if (!item)
        return -ENOMEM;

    item->node = node;
    item->parent = parent;
    item->child_key = child_key ? kstrdup(child_key, GFP_KERNEL) : NULL;
    item->visited_children = false;
    INIT_LIST_HEAD(&item->list);

    list_add(&item->list, stack);
    return 0;
}

static void destroy_path_stack(struct list_head *stack)
{
    if (stack) {
        struct trie_stack_item *item, *tmp;
        list_for_each_entry_safe(item, tmp, stack, list) {
            list_del(&item->list);
            if (item->child_key)
                kfree(item->child_key);
            kfree(item);
        }
        kfree(stack);
    }
}

static struct permission *find_permission(struct trie_node *node, uint64_t tokenid)
{
    struct rb_node *rb_node = node->permissions.rb_node;

    while (rb_node) {
        struct permission *perm = container_of(rb_node, struct permission, rb_node);
        if (tokenid < perm->tokenid) {
            rb_node = rb_node->rb_left;
        } else if (tokenid > perm->tokenid) {
            rb_node = rb_node->rb_right;
        } else {
            return perm;
        }
    }

    return NULL;
}

int insert_permission(struct trie_node *node, struct permission *new_perm)
{
    if (!node || !new_perm) {
        dec_loge("Invalid input to insert_permission (node=%p, new_perm=%p)",
            node, new_perm);
        return -EINVAL;
    }

    struct rb_node **new_rb_node = &(node->permissions.rb_node);
    struct rb_node *parent_rb_node = NULL;
    struct permission *exist_perm = NULL;

    while (*new_rb_node) {
        parent_rb_node = *new_rb_node;
        exist_perm = container_of(parent_rb_node, struct permission, rb_node);

        if (new_perm->tokenid < exist_perm->tokenid) {
            new_rb_node = &((*new_rb_node)->rb_left);
        } else if (new_perm->tokenid > exist_perm->tokenid) {
            new_rb_node = &((*new_rb_node)->rb_right);
        } else {
            dec_loge("Token ID 0x%llx already exists in node - insert failed",
                (unsigned long long)new_perm->tokenid);
            return -EEXIST;
        }
    }

    rb_link_node(&new_perm->rb_node, parent_rb_node, new_rb_node);
    rb_insert_color(&new_perm->rb_node, &node->permissions);

    dec_logi("Inserted permission for token ID 0x%llx into node",
        (unsigned long long)new_perm->tokenid);
    return 0;
}

static bool should_delete_permission(struct permission *perm, struct dec_destroy_ctx *ctx)
{
    if (!perm) {
        dec_loge(" NULL permission passed to should_delete_permission");
        return false;
    }
    bool id_match = false;
    bool timestamp_match = (ctx->timestamp == 0) || (ctx->timestamp >= perm->timestamp);
    switch (ctx->criteria) {
        case DELETE_BY_TOKENID:
            id_match = perm->tokenid == ctx->params.tokeninfo.tokenid;
            return id_match && timestamp_match;
        case DELETE_BY_USERID:
            id_match = perm->userid == ctx->params.userinfo.userid;
            return id_match && timestamp_match;
        default:
            dec_loge("Invalid delete criteria: %d", ctx->criteria);
            return false;
    }
}

static struct trie_node *get_node_by_path(const char *path)
{
    struct list_head comp_list;
    struct trie_node *node = path_tree;
    struct path_component *comp = NULL;

    if (is_path_valid(path) != 0) {
        dec_loge("Invalid path '%s' in get_node_by_path", path);
        return NULL;
    }

    INIT_LIST_HEAD(&comp_list);
    if (split_path_to_component_list(path, &comp_list) < 0)
        goto cleanup;

    list_for_each_entry(comp, &comp_list, list) {
        node = find_child(node, comp->name);
        if (node == NULL)
            break;
    }

cleanup:
    free_component_list(&comp_list);
    return node;
}

static enum query_state update_state(struct permission *perm, uint32_t mode, bool is_persist, enum query_state state)
{
    enum query_state current_status = state;
    /* If mode doesn't match, deny access (if in initial state) */
    if ((perm->mode & mode) != mode) {
        if (current_status == DEC_INIT) {
            return DEC_NOT_ALLOWED;
        }
        return current_status;
    }

    /* Temporary rule check (inherits parent directory permissions) */
    if (!is_persist) {
        if (current_status == DEC_INIT) {
            return DEC_ALLOWED;
        }
        return current_status;
    }

    /* Persistent rule check (explicit permission required) */
    if (perm->persist_flag) {
        return DEC_ALLOWED;
    }

    return current_status;
}

bool dec_path_tree_query(uint64_t tokenid, const char *path, uint32_t mode, bool is_persist)
{
    struct list_head comp_list;
    struct trie_node *node = path_tree;
    struct path_component *comp = NULL;

    INIT_LIST_HEAD(&comp_list);
    if (split_path_to_component_list(path, &comp_list) < 0) {
        dec_loge("Failed to split path '%s' into components for query", path);
        free_component_list(&comp_list);
        return false;
    }

    down_read(dec_path_tree_rwsem);
    enum query_state state = DEC_INIT;
    /* Check root node ("/") first */
    struct permission *root_prefix_perm = find_permission(node, PREFIX_TOKENID);
    if (root_prefix_perm != NULL) {
        if ((root_prefix_perm->mode & DEC_PREFIX) != 0) {
            state = DEC_INIT;
        }
    }
    struct permission *root_perm = find_permission(node, tokenid);
    if (root_perm != NULL) {
        state = update_state(root_perm, mode, is_persist, state);
    }

    /* Traverse path components to check child nodes */
    list_for_each_entry(comp, &comp_list, list) {
        node = find_child(node, comp->name);
        if (!node) {
            dec_logd("Path component '%s' not found in tree - stopping traversal", comp->name);
            break;
        }

        /* Check global prefix constraint for this node */
        struct permission *prefix_perm = find_permission(node, PREFIX_TOKENID);
        if (prefix_perm != NULL) {
            if ((prefix_perm->mode & DEC_PREFIX) != 0) {
                state = DEC_INIT;
            }
        }

        /* Check token-specific permission for this node */
        struct permission *perm = find_permission(node, tokenid);
        if (perm != NULL) {
            state = update_state(perm, mode, is_persist, state);
        }
    }

    up_read(dec_path_tree_rwsem);
    free_component_list(&comp_list);

    return (state == DEC_ALLOWED);
}

int dec_set_rule(struct path_tree_params *params)
{
    struct list_head comp_list;
    struct trie_node *node = path_tree;
    struct permission *perm = NULL;
    int ret = 0;
    ret = is_path_valid(params->path);
    if (ret != 0) {
        return ret;
    }
    dec_logi("Setting rule - token=0x%llx, path='%s', mode=0x%x, timestamp=%llu",
        params->tokenid, params->path, params->mode, params->timestamp);

    INIT_LIST_HEAD(&comp_list);
    ret = split_path_to_component_list(params->path, &comp_list);
    if (ret < 0) {
        free_component_list(&comp_list);
        return ret;
    }

    down_write(dec_path_tree_rwsem);
    struct path_component *comp;
    list_for_each_entry(comp, &comp_list, list) {
        struct trie_node *child = find_child(node, comp->name);
        if (!child) {
            child = insert_child(node, comp->name);
            if (!child) {
                dec_loge("Failed to create child node for '%s'", comp->name);
                ret = -ENOMEM;
                goto cleanup;
            }
        }

        node = child;
    }

    struct permission *existing_perm = find_permission(node, params->tokenid);
    if (existing_perm != NULL) {
        existing_perm->mode |= params->mode;
        existing_perm->userid = params->userid;
        existing_perm->persist_flag = params->persist_flag;
        existing_perm->timestamp = params->timestamp;
        dec_logi("Updated existing permission - token=0x%llx, mode=0x%x",
            existing_perm->tokenid, existing_perm->mode);
        goto cleanup;
    }

    perm = kmalloc(sizeof(struct permission), GFP_KERNEL);
    if (!perm) {
        dec_loge("Failed to allocate memory for new permission");
        ret = -ENOMEM;
        goto cleanup;
    }
    perm->tokenid = params->tokenid;
    perm->mode = params->mode;
    perm->userid = params->userid;
    perm->persist_flag = params->persist_flag;
    perm->timestamp = params->timestamp;
    ret = insert_permission(node, perm);
    if (ret) {
        dec_loge("Failed to insert permission for token 0x%llx (err=%d)",
            params->tokenid, ret);
        kfree(perm);
        goto cleanup;
    }
    node->has_permissions = true;
    dec_logi("Added new permission: tokenid=%llu, mode=%u", perm->tokenid, perm->mode);

cleanup:
    up_write(dec_path_tree_rwsem);
    free_component_list(&comp_list);
    return ret;
}

int dec_delete_rule(uint64_t tokenid, const char *path, uint64_t timestamp)
{
    dec_logi("Deleting rule - token=0x%llx, path='%s', timestamp=%llu",
        tokenid, path, timestamp);
    struct list_head comp_list;
    struct trie_node *node = path_tree;
    struct list_head *path_stack;
    int ret = 0;
    ret = is_path_valid(path);
    if (ret != 0) {
        return ret;
    }

    INIT_LIST_HEAD(&comp_list);

    ret = split_path_to_component_list(path, &comp_list);
    if (ret < 0) {
        free_component_list(&comp_list);
        return ret;
    }
    path_stack = create_path_stack();
    if (!path_stack) {
        dec_loge("Failed to create path stack for delete operation");
        free_component_list(&comp_list);
        return -ENOMEM;
    }

    down_write(dec_path_tree_rwsem);
    struct path_component *comp;
    list_for_each_entry(comp, &comp_list, list) {
        struct trie_node *child = find_child(node, comp->name);
        if (!child) {
            dec_loge("Path component '%s' not found in tree", comp->name);
            ret = -ENOENT;
            goto cleanup;
        }
        if (add_to_path_stack(path_stack, child, node, comp->name) < 0) {
            dec_loge("Failed to add '%s' to path stack", comp->name);
            ret = -ENOMEM;
            goto cleanup;
        }
        node = child;
    }

    struct permission *perm = find_permission(node, tokenid);
    if (perm == NULL) {
        dec_loge("Permission for token 0x%llx not found at path '%s'",
            tokenid, path);
        ret = -ENOENT;
        goto cleanup;
    }
    if (timestamp != 0 && timestamp < perm->timestamp) {
        dec_loge("DEC: Timestamp %llu not newer than permission timestamp %llu",
            timestamp, perm->timestamp);
        ret = -ENOENT;
        goto cleanup;
    }
    rb_erase(&perm->rb_node, &node->permissions);
    kfree(perm);

     /* Clean up empty nodes (traverse stack in reverse) */
    node->has_permissions = !RB_EMPTY_ROOT(&node->permissions);
    struct trie_stack_item *item, *tmp;
    list_for_each_entry_safe_reverse(item, tmp, path_stack, list) {
        if (!item->node->has_permissions && RB_EMPTY_ROOT(&item->node->children) && item->parent) {
            /* Remove empty node from parent */
            rb_erase(&item->node->rb_node, &item->parent->children);
            trie_node_destroy(item->node);
            item->node = NULL;
        } else {
            break;  /* Stop at first non-empty node */
        }
    }

cleanup:
    up_write(dec_path_tree_rwsem);
    free_component_list(&comp_list);
    destroy_path_stack(path_stack);
    return ret;
}

int dec_destroy_rule_by_id(struct dec_destroy_ctx *ctx)
{
    enum delete_criteria criteria = ctx->criteria;
    if (criteria != DELETE_BY_TOKENID && criteria != DELETE_BY_USERID) {
        dec_loge("Invalid deletion criteria %d (must be token or user ID)", criteria);
        return -EINVAL;
    }

    struct list_head stack_list;
    INIT_LIST_HEAD(&stack_list);
    struct trie_stack_item *first_item = kmalloc(sizeof(struct trie_stack_item), GFP_KERNEL);
    if (!first_item) {
        dec_loge("Failed to allocate initial stack item for bulk delete");
        return -ENOMEM;
    }

    down_write(dec_path_tree_rwsem);
    first_item->node = path_tree;
    first_item->parent = NULL;
    first_item->child_key = NULL;
    first_item->visited_children = false;

    if (criteria == DELETE_BY_USERID) {
        struct trie_node *target_node = get_node_by_path(ctx->params.userinfo.path);
        if (!target_node) {
            dec_loge("Path '%s' not found for user ID deletion", ctx->params.userinfo.path);
            up_write(dec_path_tree_rwsem);
            kfree(first_item);
            return -ENOENT;
        }
        first_item->node = target_node;
    }

    INIT_LIST_HEAD(&first_item->list);
    list_add(&first_item->list, &stack_list);

    /* Depth-first traversal of trie */
    while (!list_empty(&stack_list)) {
        struct trie_stack_item *item = list_first_entry(&stack_list, struct trie_stack_item, list);
        struct trie_node *curr_node = item->node;

        if (!item->visited_children) {
            /* First visit: process permissions and queue children */
            item->visited_children = true;

            /* Delete matching permissions in current node */
            struct rb_node *rb_iter = rb_first(&curr_node->permissions);
            while (rb_iter) {
                struct permission *perm = container_of(rb_iter, struct permission, rb_node);
                struct rb_node *next_rb = rb_next(rb_iter);

                if (should_delete_permission(perm, ctx)) {
                    rb_erase(&perm->rb_node, &curr_node->permissions);
                    dec_logi("Deleted permission - token=0x%llx, user=%d, node='%s'",
                             (unsigned long long)perm->tokenid, perm->userid,
                             curr_node->component ?: "root");
                    kfree(perm);
                }

                rb_iter = next_rb;
            }

            /* Update node permission status */
            curr_node->has_permissions = !RB_EMPTY_ROOT(&curr_node->permissions);

            /* Queue child nodes for traversal (post-order) */
            struct rb_node *child_rb = rb_first(&curr_node->children);
            while (child_rb) {
                struct trie_node *child_node = container_of(child_rb, struct trie_node, rb_node);
                struct trie_stack_item *child_item = kmalloc(sizeof(struct trie_stack_item), GFP_KERNEL);
                if (!child_item) {
                    dec_loge("Failed to allocate child stack item during bulk delete");
                    break;
                }

                child_item->node = child_node;
                child_item->parent = curr_node;
                child_item->child_key = child_node->component ? kstrdup(child_node->component, GFP_KERNEL) : NULL;
                child_item->visited_children = false;
                INIT_LIST_HEAD(&child_item->list);

                /* Insert after current item (post-order traversal) */
                list_add(&child_item->list, &stack_list);

                child_rb = rb_next(child_rb);
            }
        } else {
            /* Second visit: clean up empty nodes */
            if (!item->node->has_permissions &&
                RB_EMPTY_ROOT(&item->node->children) &&
                item->parent != NULL)
            {
                rb_erase(&item->node->rb_node, &item->parent->children);
                dec_logd("Removed empty node: %s", item->node->component ?: "root");
                if (item->node->component)
                    kfree(item->node->component);
                kfree(item->node);
                item->node = NULL;
            }

            list_del(&item->list);
            if (item->child_key)
                kfree(item->child_key);
            kfree(item);
        }
    }

    up_write(dec_path_tree_rwsem);

    struct trie_stack_item *item, *tmp;
    list_for_each_entry_safe(item, tmp, &stack_list, list) {
        list_del(&item->list);
        if (item->child_key)
            kfree(item->child_key);
        kfree(item);
    }

    return 0;
}

int dec_set_prefix(const char *prefix)
{
    int ret = 0;

    /* Initialize parameters for global prefix rule */
    struct path_tree_params param = {0};
    param.path = (char *)prefix;
    param.tokenid = PREFIX_TOKENID;
    param.userid = PREFIX_USERID;
    param.mode = DEC_PREFIX;
    ret = dec_set_rule(&param);

    return ret;
}

/* Register initialization function for filesystem init phase */
fs_initcall(dec_path_tree_init);