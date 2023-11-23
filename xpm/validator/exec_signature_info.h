/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#ifndef _EXEC_SIGNATURE_INFO_H
#define _EXEC_SIGNATURE_INFO_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/list.h>

struct exec_segment_info {
	uintptr_t	file_offset;
	size_t	size;
};

#define FILE_SIGNATURE_INVALID	0
#define FILE_SIGNATURE_FS_VERITY	1
#define FILE_SIGNATURE_DM_VERITY	2
#define FILE_SIGNATURE_MASK	0x0000000F
#define FILE_SIGNATURE_DELETE	0x80000000

struct exec_file_signature_info {
	struct rb_node	rb_node;
	atomic_t	reference;
	unsigned int	type;
	uintptr_t	inode;
	unsigned int	code_segment_count;
	struct exec_segment_info	*code_segments;
};

static inline bool exec_file_signature_is_fs_verity(const struct exec_file_signature_info *signature_info)
{
	return (signature_info->type & FILE_SIGNATURE_MASK) == FILE_SIGNATURE_FS_VERITY;
}

static inline bool exec_file_signature_is_dm_verity(const struct exec_file_signature_info *signature_info)
{
	return (signature_info->type & FILE_SIGNATURE_MASK) == FILE_SIGNATURE_DM_VERITY;
}

static inline bool exec_file_signature_is_verity(const struct exec_file_signature_info *signature_info)
{
	return (signature_info->type & FILE_SIGNATURE_MASK) == FILE_SIGNATURE_DM_VERITY ||
		(signature_info->type & FILE_SIGNATURE_MASK) == FILE_SIGNATURE_FS_VERITY;
}

static inline bool exec_file_signature_is_delete(const struct exec_file_signature_info *signature_info)
{
	return !!(signature_info->type & FILE_SIGNATURE_DELETE);
}

int parse_elf_code_segment_info(struct file *file, struct exec_file_signature_info **code_segment_info);
int get_exec_file_signature_info(struct file *file, bool is_exec, struct exec_file_signature_info **info_ptr);
int put_exec_file_signature_info(struct exec_file_signature_info *exec_info);
void delete_exec_file_signature_info(struct inode *file_node);
#endif
