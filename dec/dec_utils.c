// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/limits.h>

#include "dec_utils.h"
#include "dec_log.h"

int is_path_valid(const char *path)
{
	const char *start;
	const char *end;
	size_t path_len;
    bool prev_is_slash = false;

	if (!path) {
		dec_loge("path is NULL");
		return -EINVAL;
	}

	path_len = strlen(path);
	if (path_len == 0 || path_len > PATH_MAX) {
		dec_loge("invalid path length: %zu (must be 1~%d)", path_len, PATH_MAX);
		return -EINVAL;
	}

	/* Must be an absolute path */
	if (*path != '/') {
		dec_loge("path '%s' is not absolute (must start with '/')", path);
		return -EINVAL;
	}

    /* Path with only '/' */
    if (path_len == 1) {
        return 0;
    }

	start = path;

	/* Validate each path component */
	while (*start) {
        if (*start == '/') {
            /* Reject consecutive '/' */
            if (prev_is_slash) {
                dec_loge("path '%s' contains consecutive '/'", path);
                return -EINVAL;
            }
            prev_is_slash = true;
            start++;
            continue;
        }
        prev_is_slash = false;

		size_t comp_len;
		end = strchr(start, '/');
		if (!end) {
			comp_len = strlen(start);
		} else {
			comp_len = end - start;
		}

		/* Check component length validity */
		if (comp_len == 0 || comp_len >= NAME_MAX) {
			dec_loge("invalid component length %zu in path '%s'", comp_len, path);
			return -EINVAL;
		}

		/* Reject single '.' component */
		if (comp_len == 1 && *start == '.') {
			dec_loge("path '%s' contains invalid component '.'", path);
			return -EINVAL;
		}

		/* Reject '..' component */
		if (comp_len == 2 && *start == '.' && *(start + 1) == '.') {
			dec_loge("path '%s' contains invalid component '..'", path);
			return -EINVAL;
		}

		if (!end)
			break;

		start = end;
	}

	return 0;
}


struct trie_node *trie_node_create(const char *component)
{
    if (!component) {
        return NULL;
    }

    struct trie_node *node = kzalloc(sizeof(struct trie_node), GFP_KERNEL);
    if (!node) {
        return NULL;
    }
    node->component = kstrdup(component, GFP_KERNEL);
    if (!node->component) {
        kfree(node);
        return NULL;
    }
    node->permissions = RB_ROOT;
    node->children = RB_ROOT;
    node->has_permissions = false;

    return node;
}

struct trie_node *find_child(struct trie_node *node, const char *component)
{
    if (node == NULL || component == NULL || strlen(component) == 0) {
        return NULL;
    }

    struct rb_node *rb_node = node->children.rb_node;
    struct trie_node *child = NULL;
    while (rb_node) {
        child = container_of(rb_node, struct trie_node, rb_node);
        if (child->component == NULL) {
            return NULL;
        }
        int cmp = strcmp(component, child->component);

        if (cmp < 0)
            rb_node = rb_node->rb_left;
        else if (cmp > 0)
            rb_node = rb_node->rb_right;
        else
            return child;
    }

    return NULL;
}

struct trie_node *insert_child(struct trie_node *parent, const char *component)
{
    if (parent == NULL || component == NULL) {
        return NULL;
    }

    struct rb_node **new_node = &(parent->children.rb_node);
    struct rb_node *parent_rb = NULL;
    struct trie_node *child = NULL;
    int cmp = 0;

    while (*new_node) {
        parent_rb = *new_node;
        child = container_of(parent_rb, struct trie_node, rb_node);
        if (child->component == NULL) {
            new_node = &((*new_node)->rb_right);
            continue;
        }

        cmp = strcmp(component, child->component);
        if (cmp < 0) {
            new_node = &((*new_node)->rb_left);
        } else if (cmp > 0) {
            new_node = &((*new_node)->rb_right);
        } else {
            return NULL; /* Node already exists, insertion failed */
        }
    }

    struct trie_node *new_child = trie_node_create(component);
    if (new_child == NULL) {
        dec_loge("failed to create trie node");
        return NULL;
    }

    rb_link_node(&new_child->rb_node, parent_rb, new_node);
    rb_insert_color(&new_child->rb_node, &parent->children);

    return new_child;
}

 void trie_node_destroy(struct trie_node *node)
{
    struct rb_node *rb_node;
    struct permission *perm;
    struct trie_node *child;

    if (node == NULL)
        return;

    while ((rb_node = rb_first(&node->permissions))) {
        perm = container_of(rb_node, struct permission, rb_node);
        rb_erase(rb_node, &node->permissions);
        kfree(perm);
    }

    while ((rb_node = rb_first(&node->children))) {
        child = container_of(rb_node, struct trie_node, rb_node);
        rb_erase(rb_node, &node->children);
        trie_node_destroy(child);
    }

    if (node->component)
        kfree(node->component);

    kfree(node);
}


int split_path_to_component_list(const char *path, struct list_head *comp_list)
{
    const char *start;
    const char *end;
    int ret = 0;

    if (comp_list == NULL) {
        dec_loge("split_path_to_component_list: comp_list is NULL");
        return -EINVAL;
    }

    start = path;
    while (*start == '/')
        start++;

    while (*start) {
        size_t len;
        end = strchr(start, '/');
        if (end == NULL) {
            len = strlen(start);
        } else if (end > start) {
            len = end - start;
        } else {
            start++;
            continue;
        }

        struct path_component *comp = kmalloc(sizeof(*comp) + len + 1, GFP_KERNEL);
        if (!comp) {
            dec_loge("failed to allocate path_component");
            free_component_list(comp_list);
            return -ENOMEM;
        }

        memcpy(comp->name, start, len);
        comp->name[len] = '\0';
        INIT_LIST_HEAD(&comp->list);
        list_add_tail(&comp->list, comp_list);

        if (end == NULL)
            break;

        start = end + 1;
        while (*start == '/')
            start++;
    }

    return 0;
}

void free_component_list(struct list_head *comp_list)
{
    struct path_component *comp, *tmp;
    list_for_each_entry_safe(comp, tmp, comp_list, list) {
        list_del(&comp->list);
        kfree(comp);
    }
}