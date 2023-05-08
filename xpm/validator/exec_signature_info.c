// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/rwlock_types.h>
#include <linux/rwlock.h>
#include <linux/init.h>
#include "exec_signature_info.h"

#define VERITY_NODE_CACHE_LIMITS       10000
#define VERITY_NODE_CACHE_RECYCLE_NUM  200

static DEFINE_RWLOCK(dm_verity_tree_lock);
static struct rb_root dm_verity_tree = RB_ROOT;
static int dm_verity_node_count;
static DEFINE_RWLOCK(fs_verity_tree_lock);
static struct rb_root fs_verity_tree = RB_ROOT;
static int fs_verity_node_count;

static int check_exec_file_is_verity(struct file *file)
{
	return FILE_SIGNATURE_DM_VERITY;
}

static struct exec_file_signature_info *rb_search_node(struct rb_root *root, uintptr_t file_inode)
{
	struct rb_node *node = root->rb_node;
	struct exec_file_signature_info *file_node;

	while (node != NULL) {
		file_node = rb_entry(node, struct exec_file_signature_info, rb_node);
		if (file_inode < file_node->inode) {
			node = file_node->rb_node.rb_left;
		} else if (file_inode > file_node->inode) {
			node = file_node->rb_node.rb_right;
		} else {
			atomic_inc(&file_node->reference);
			return file_node;
		}
	}
	return NULL;
}

static struct exec_file_signature_info *rb_add_node(struct rb_root *root, int *node_count,
	struct exec_file_signature_info *node)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct exec_file_signature_info *file;

	while (*p != NULL) {
		parent = *p;
		file = rb_entry(parent, struct exec_file_signature_info, rb_node);
		if (node->inode < file->inode) {
			p = &(*p)->rb_left;
		} else if (node->inode > file->inode) {
			p = &(*p)->rb_right;
		} else {
			atomic_inc(&file->reference);
			return file;
		}
	}

	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, root);
	atomic_inc(&node->reference);
	(*node_count)++;
	return NULL;
}

static void rb_erase_node(struct rb_root *root, int *node_count,
	struct exec_file_signature_info *node)
{
	rb_erase(&node->rb_node, root);
	(*node_count)--;
}

static int find_idle_nodes(struct rb_root *root, uintptr_t *ilde_nodes, size_t count)
{
	int i = 0;
	struct exec_file_signature_info *code_segment;
	struct rb_node *node;

	for (node = rb_first(root); node != NULL && i < count; node = rb_next(node)) {
		code_segment = rb_entry(node, struct exec_file_signature_info, rb_node);
		if (atomic_read(&code_segment->reference) > 0)
			continue;

		ilde_nodes[i++] = (uintptr_t)code_segment;
	}
	return i;
}

static void clear_code_segment_info_cache(struct rb_root *root, int *node_count)
{
	struct exec_file_signature_info *code_segment_info;
	uintptr_t *code_segments;
	int i = 0;
	int count = VERITY_NODE_CACHE_RECYCLE_NUM;

	code_segments = kcalloc(count, sizeof(uintptr_t), GFP_KERNEL);
	if (code_segments == NULL)
		return;

	count = find_idle_nodes(root, code_segments, count);
	while (i < count) {
		code_segment_info = (struct exec_file_signature_info *)code_segments[i];
		rb_erase_node(root, node_count, code_segment_info);
		kfree(code_segment_info);
		i++;
	}
	kfree(code_segments);
}

#ifdef CONFIG_SECURITY_XPM_DEBUG
static size_t test_elf_code_segment_info_size(struct rb_root *root)
{
	size_t size = 0;
	struct exec_file_signature_info *file_node;
	struct rb_node *node;

	for (node = rb_first(root); node != NULL; node = rb_next(node)) {
		file_node = rb_entry(node, struct exec_file_signature_info, rb_node);
		size += sizeof(struct exec_file_signature_info) +
				file_node->code_segment_count * sizeof(struct exec_segment_info);
	}
	return size;
}

static void test_printf_code_segment_cache_size(void)
{
	size_t cache_size = 0;
	int count = 0;

	read_lock(&dm_verity_tree_lock);
	cache_size += test_elf_code_segment_info_size(&dm_verity_tree);
	count += dm_verity_node_count;
	read_unlock(&dm_verity_tree_lock);

	read_lock(&fs_verity_tree_lock);
	cache_size += test_elf_code_segment_info_size(&fs_verity_tree);
	count += fs_verity_node_count;
	read_unlock(&fs_verity_tree_lock);

	pr_info("[exec signature cache] count=%d, cache size=%d KB\n", count, cache_size / 1024);
}

static void test_print_elf_code_segment_info(struct file *file, const struct exec_file_signature_info *file_info)
{
	char *ret_path;
	char path[PATH_MAX] = {0};
	static int code_segment_test_count = 100;
	int i;

	code_segment_test_count--;
	if (code_segment_test_count > 0)
		return;

	ret_path = file_path(file, path, PATH_MAX-1);
	if (IS_ERR(ret_path))
		return;

	for (i = 0; i < file_info->code_segment_count; i++) {
		pr_info("[exec signature segment] %s -> offset: 0x%llx size: 0x%lx\n",
			ret_path, file_info->code_segments->file_offset, file_info->code_segments->size);
	}

	code_segment_test_count = 100;
}
#endif

static void rm_code_segment_info(void)
{
	if (dm_verity_node_count + fs_verity_node_count < VERITY_NODE_CACHE_LIMITS)
		return;

#ifdef CONFIG_SECURITY_XPM_DEBUG
	test_printf_code_segment_cache_size();
#endif

	if (dm_verity_node_count > fs_verity_node_count) {
		write_lock(&dm_verity_tree_lock);
		clear_code_segment_info_cache(&dm_verity_tree, &dm_verity_node_count);
		write_unlock(&dm_verity_tree_lock);
		return;
	}

	write_lock(&fs_verity_tree_lock);
	clear_code_segment_info_cache(&fs_verity_tree, &fs_verity_node_count);
	write_unlock(&fs_verity_tree_lock);
}

static int get_elf_code_segment_info(struct file *file, bool is_exec, int type,
	struct exec_file_signature_info **code_segment_info)
{
	int ret;
	struct rb_root *root;
	rwlock_t *verity_lock;
	int *node_count;
	struct inode *file_node;
	struct exec_file_signature_info *new_info;
	struct exec_file_signature_info *tmp_info;

	if (type == FILE_SIGNATURE_DM_VERITY) {
		root = &dm_verity_tree;
		verity_lock = &dm_verity_tree_lock;
		node_count = &dm_verity_node_count;
	} else if (type == FILE_SIGNATURE_FS_VERITY) {
		verity_lock = &fs_verity_tree_lock;
		root = &fs_verity_tree;
		node_count = &fs_verity_node_count;
	} else {
		return -EINVAL;
	}

	file_node = file_inode(file);
	if (file_node == NULL)
		return -EINVAL;

	read_lock(verity_lock);
	tmp_info = rb_search_node(root, (uintptr_t)file_node);
	read_unlock(verity_lock);
	if (tmp_info != NULL) {
		if (is_exec && tmp_info->code_segments == NULL)
			goto need_parse;

		*code_segment_info = tmp_info;
		return 0;
	}

need_parse:
	rm_code_segment_info();

	if (!is_exec) {
		new_info = kzalloc(sizeof(struct exec_file_signature_info), GFP_KERNEL);
		if (new_info == NULL)
			return -ENOMEM;
	} else {
		ret = parse_elf_code_segment_info(file, &new_info);
		if (ret < 0)
			return ret;
#ifdef CONFIG_SECURITY_XPM_DEBUG
		test_print_elf_code_segment_info(file, new_info);
#endif
	}

	new_info->type = type;
	new_info->inode = (uintptr_t)file_node;
	RB_CLEAR_NODE(&new_info->rb_node);
	if (tmp_info != NULL) {
		write_lock(verity_lock);
		rb_erase_node(root, node_count, tmp_info);
		tmp_info->type |= FILE_SIGNATURE_DELETE;
		write_unlock(verity_lock);
		if (atomic_sub_return(1, &tmp_info->reference) <= 0)
			kfree(tmp_info);
	}

	write_lock(verity_lock);
	tmp_info = rb_add_node(root, node_count, new_info);
	write_unlock(verity_lock);
	if (tmp_info != NULL) {
		kfree(new_info);
		new_info = tmp_info;
	}
	*code_segment_info = new_info;
	return 0;
}

int get_exec_file_signature_info(struct file *file, bool is_exec,
	struct exec_file_signature_info **info_ptr)
{
	int type;

	if (file == NULL || info_ptr == NULL)
		return -EINVAL;

	type = check_exec_file_is_verity(file);
	return get_elf_code_segment_info(file, is_exec, type, info_ptr);
}

int put_exec_file_signature_info(struct exec_file_signature_info *exec_info)
{
	if ((exec_info == NULL) ||
		!exec_file_signature_is_verity(exec_info))
		return -EINVAL;

	if (atomic_sub_return(1, &exec_info->reference) <= 0 &&
		exec_file_signature_is_delete(exec_info))
		kfree(exec_info);
	return 0;
}

static struct exec_file_signature_info *elf_code_segment_info_delete(struct rb_root *root,
	int *node_count, struct inode *file_node)
{
	struct exec_file_signature_info *signature_info;

	signature_info = rb_search_node(root, (uintptr_t)file_node);
	if (signature_info != NULL) {
		rb_erase_node(root, node_count, signature_info);
		if (atomic_sub_return(1, &signature_info->reference) > 0)
			signature_info->type |= FILE_SIGNATURE_DELETE;
		else
			kfree(signature_info);
	}
	return signature_info;
}

void delete_exec_file_signature_info(struct inode *file_node)
{
	struct exec_file_signature_info *signature_info;

	if (file_node == NULL)
		return;

	write_lock(&fs_verity_tree_lock);
	signature_info = elf_code_segment_info_delete(&fs_verity_tree, &fs_verity_node_count, file_node);
	write_unlock(&fs_verity_tree_lock);
	if (signature_info != NULL)
		return;

	write_lock(&dm_verity_tree_lock);
	signature_info = elf_code_segment_info_delete(&dm_verity_tree, &dm_verity_node_count, file_node);
	write_unlock(&dm_verity_tree_lock);
}
