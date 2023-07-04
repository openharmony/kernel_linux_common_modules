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
#include <linux/moduleparam.h>
#include <linux/device-mapper.h>
#include <linux/kdev_t.h>
#include <linux/namei.h>
#include "mount.h"
#include "internal.h"
#include "exec_signature_info.h"
#include "xpm_report.h"
#include "xpm_log.h"

#define VERITY_NODE_CACHE_LIMITS       10000
#define VERITY_NODE_CACHE_RECYCLE_NUM  200

static DEFINE_RWLOCK(dm_verity_tree_lock);
static struct rb_root dm_verity_tree = RB_ROOT;
static int dm_verity_node_count;
static DEFINE_RWLOCK(fs_verity_tree_lock);
static struct rb_root fs_verity_tree = RB_ROOT;
static int fs_verity_node_count;

struct verity_info {
	struct rb_root *root;
	rwlock_t *lock;
	int *node_count;
};

static bool dm_verity_enable_check;

#define DM_PARTITION_PATH_MAX	20
#define DM_VERITY_INVALID_DEV	((dev_t)-1)
#define SYSTTEM_STARTUP_SECOND_STAGE	"/system/bin/init"

struct dm_partition {
	char path[DM_PARTITION_PATH_MAX];
	int len;
	dev_t s_dev;
};

static struct dm_partition	dm_partition_table[] = {
	{ .path = "/",           .len = 1,  .s_dev = DM_VERITY_INVALID_DEV },
	{ .path = "/system/",    .len = 8,  .s_dev = DM_VERITY_INVALID_DEV },
	{ .path = "/vendor/",    .len = 8,  .s_dev = DM_VERITY_INVALID_DEV },
	{ .path = "/misc/",      .len = 6,  .s_dev = DM_VERITY_INVALID_DEV },
	{ .path = "/sys_prod/",  .len = 10, .s_dev = DM_VERITY_INVALID_DEV },
	{ .path = "/chip_prod/", .len = 11, .s_dev = DM_VERITY_INVALID_DEV },
};

static struct path	root_path;

static dev_t get_file_dev(struct file *file)
{
	struct super_block *sb;
	struct mount *mnt;

	if (file->f_path.mnt == NULL)
		return DM_VERITY_INVALID_DEV;

	mnt = container_of(file->f_path.mnt, struct mount, mnt);
	sb = mnt->mnt.mnt_sb;
	if (sb == NULL)
		return DM_VERITY_INVALID_DEV;

	return sb->s_dev;
}

static dev_t get_dm_verity_partition_dev(const char *dir)
{
	int ret;
	struct path path;
	struct vfsmount *mnt;
	dev_t s_dev;

	if (root_path.dentry == NULL) {
		ret = kern_path("/", LOOKUP_DIRECTORY, &path);
		if (ret) {
			xpm_log_error("get / path failed.");
			return DM_VERITY_INVALID_DEV;
		}
	} else {
		ret = vfs_path_lookup(root_path.dentry, root_path.mnt, dir, LOOKUP_DIRECTORY, &path);
		if (ret) {
			xpm_log_error("get %s path failed.", dir);
			return DM_VERITY_INVALID_DEV;
		}
	}

	mnt = path.mnt;
	if (IS_ERR(mnt) || IS_ERR(mnt->mnt_sb)) {
		path_put(&path);
		xpm_log_error("get %s dev failed.", dir);
		return DM_VERITY_INVALID_DEV;
	}

	s_dev = mnt->mnt_sb->s_dev;
	path_put(&path);

	xpm_log_info("get %s dev=%u:%u success", dir, s_dev, MINOR(s_dev));
	return s_dev;
}

static bool find_partition_dev(struct file *file)
{
	char *full_path = NULL;
	char path[PATH_MAX] = {0};
	struct dm_partition *dm_path;
	int i;

	for (i = 1; i < sizeof(dm_partition_table) / sizeof(struct dm_partition); i++) {
		dm_path = &dm_partition_table[i];
		if (dm_path->s_dev != DM_VERITY_INVALID_DEV)
			continue;

		if (full_path == NULL) {
			full_path = file_path(file, path, PATH_MAX-1);
			if (IS_ERR(full_path))
				return false;
		}
		if (strncmp(dm_path->path, full_path, dm_path->len) != 0)
			continue;

		dm_path->s_dev = get_dm_verity_partition_dev(dm_path->path);
		if (dm_path->s_dev == DM_VERITY_INVALID_DEV)
			return false;
		if (dm_path->s_dev == get_file_dev(file))
			return true;
		return false;
	}

	return false;
}

static bool dm_verity_check_for_path(struct file *file)
{
	static int system_startup_stage;
	char *full_path;
	char path[PATH_MAX] = {0};
	struct dm_partition *dm_path;
	dev_t s_dev;
	int i, ret;

	s_dev = get_file_dev(file);
	if (!system_startup_stage) {
		full_path = file_path(file, path, PATH_MAX - 1);
		if (IS_ERR(full_path))
			return false;
		if (strcmp(SYSTTEM_STARTUP_SECOND_STAGE, full_path) != 0) {
			dm_path = &dm_partition_table[0];
			if (dm_path->s_dev == s_dev)
				return true;
			return false;
		}
		ret = kern_path("/", LOOKUP_DIRECTORY, &root_path);
		if (ret) {
			xpm_log_error("get / path failed.");
			return false;
		}
		system_startup_stage = 1;
	}

	for (i = 1; i < sizeof(dm_partition_table) / sizeof(struct dm_partition); i++) {
		dm_path = &dm_partition_table[i];
		if (dm_path->s_dev == s_dev)
			return true;
	}

	return find_partition_dev(file);
}

#ifdef CONFIG_DM_VERITY
#define HVB_CMDLINE_VB_STATE	"ohos.boot.hvb.enable"
static bool dm_verity_enable;

static int hvb_boot_param_cb(char *param, char *val,
	const char *unused, void *arg)
{
	if (param == NULL || val == NULL)
		return 0;

	if (strcmp(param, HVB_CMDLINE_VB_STATE) != 0)
		return 0;

	if (strcmp(val, "true") == 0 || strcmp(val, "TRUE") == 0)
		dm_verity_enable = true;

	return 0;
}

static bool dm_verity_is_enable(void)
{
	char *cmdline;

	if (dm_verity_enable || dm_verity_enable_check)
		return dm_verity_enable;

	cmdline = kstrdup(saved_command_line, GFP_KERNEL);
	if (cmdline == NULL)
		return false;

	parse_args("hvb.enable params", cmdline, NULL,
		0, 0, 0, NULL, &hvb_boot_param_cb);
	kfree(cmdline);
	dm_verity_enable_check = true;
	if (!dm_verity_enable) {
		dm_partition_table[0].s_dev = get_dm_verity_partition_dev(dm_partition_table[0].path);
		report_init_event(TYPE_DM_DISABLE);
	}
	return dm_verity_enable;
}

static bool dm_verity_check_for_mnt(struct file *file)
{
	struct mapped_device *device;

	device = dm_get_md(get_file_dev(file));
	if (device == NULL)
		return false;

	dm_put(device);
	return true;
}
#endif

static bool is_dm_verity(struct file *file)
{
#ifdef CONFIG_DM_VERITY
	if (dm_verity_is_enable())
		return dm_verity_check_for_mnt(file);
#endif

	if (!dm_verity_enable_check) {
		dm_partition_table[0].s_dev = get_dm_verity_partition_dev(dm_partition_table[0].path);
		dm_verity_enable_check = true;
		report_init_event(TYPE_DM_DISABLE);
	}
	return dm_verity_check_for_path(file);
}

#ifdef CONFIG_FS_VERITY
static bool is_fs_verity(struct file *file)
{
	struct inode *file_node;

	file_node = file_inode(file);
	if (file_node == NULL)
		return false;

	if (file_node->i_verity_info == NULL)
		return false;

	return true;
}
#endif

static int check_exec_file_is_verity(struct file *file)
{
#ifdef CONFIG_FS_VERITY
	if (is_fs_verity(file))
		return FILE_SIGNATURE_FS_VERITY;
#endif

	if (is_dm_verity(file))
		return FILE_SIGNATURE_DM_VERITY;

	return FILE_SIGNATURE_INVALID;
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
	int dm_count;
	int fs_count;

	read_lock(&dm_verity_tree_lock);
	cache_size += test_elf_code_segment_info_size(&dm_verity_tree);
	dm_count = dm_verity_node_count;
	read_unlock(&dm_verity_tree_lock);

	read_lock(&fs_verity_tree_lock);
	cache_size += test_elf_code_segment_info_size(&fs_verity_tree);
	fs_count = fs_verity_node_count;
	read_unlock(&fs_verity_tree_lock);

	xpm_log_info("cache dm count=%d, fs count=%d, cache size=%d KB\n", dm_count, fs_count, cache_size / 1024);
}

static void test_print_info(struct file *file, unsigned int type, const struct exec_file_signature_info *file_info)
{
	char *full_path;
	char path[PATH_MAX] = {0};
	static int code_segment_test_count = 100;
	int i;

	code_segment_test_count--;
	if (code_segment_test_count > 0)
		return;

	full_path = file_path(file, path, PATH_MAX - 1);
	if (IS_ERR(full_path))
		return;

	for (i = 0; i < file_info->code_segment_count; i++)
		xpm_log_info("%s -> type: %s, info: offset=0x%llx size=0x%lx\n",
			full_path, type == FILE_SIGNATURE_DM_VERITY ? "dm" : "fs",
			file_info->code_segments->file_offset, file_info->code_segments->size);

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

static int get_verity_info(int type, struct verity_info *verity)
{
	if (type == FILE_SIGNATURE_DM_VERITY) {
		verity->root = &dm_verity_tree;
		verity->lock = &dm_verity_tree_lock;
		verity->node_count = &dm_verity_node_count;
		return 0;
	}

	if (type == FILE_SIGNATURE_FS_VERITY) {
		verity->lock = &fs_verity_tree_lock;
		verity->root = &fs_verity_tree;
		verity->node_count = &fs_verity_node_count;
		return 0;
	}

	return -EINVAL;
}

static void insert_new_signature_info(struct inode *file_node, int type,
	struct verity_info *verity, struct exec_file_signature_info *new_info, struct exec_file_signature_info **old_info)
{
	new_info->type = type;
	new_info->inode = (uintptr_t)file_node;
	RB_CLEAR_NODE(&new_info->rb_node);
	if ((*old_info) != NULL) {
		write_lock(verity->lock);
		rb_erase_node(verity->root, verity->node_count, *old_info);
		(*old_info)->type |= FILE_SIGNATURE_DELETE;
		write_unlock(verity->lock);
		if (atomic_sub_return(1, &(*old_info)->reference) <= 0) {
			kfree(*old_info);
			*old_info = NULL;
		}
	}

	write_lock(verity->lock);
	*old_info = rb_add_node(verity->root, verity->node_count, new_info);
	write_unlock(verity->lock);
}

static int get_elf_code_segment_info(struct file *file, bool is_exec, int type,
	struct exec_file_signature_info **code_segment_info)
{
	int ret;
	struct verity_info verity;
	struct inode *file_node;
	struct exec_file_signature_info *new_info;
	struct exec_file_signature_info *old_info;

	if (get_verity_info(type, &verity) < 0)
		return -EINVAL;

	file_node = file_inode(file);
	if (file_node == NULL)
		return -EINVAL;

	read_lock(verity.lock);
	old_info = rb_search_node(verity.root, (uintptr_t)file_node);
	read_unlock(verity.lock);
	if (old_info != NULL) {
		if (is_exec && old_info->code_segments == NULL)
			goto need_parse;

		*code_segment_info = old_info;
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
		test_print_info(file, type, new_info);
#endif
	}

	insert_new_signature_info(file_node, type, &verity, new_info, &old_info);
	if (old_info != NULL) {
		kfree(new_info);
		new_info = old_info;
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
