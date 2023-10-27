// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/code_sign.h>
#include <linux/fsverity.h>

#include "code_sign_ext.h"
#include "code_sign_log.h"

/**
 * Validate code sign descriptor
 *
 * Return: 1 on code sign version, 0 on basic version, and -errno on failure
 */
static inline int check_code_sign_descriptor(const struct inode *inode,
	const struct code_sign_descriptor *desc)
{
	u64 tree_offset = le64_to_cpu(desc->tree_offset);

	if (!desc->cs_version)
		return 0;

	if (desc->__reserved1 ||
		memchr_inv(desc->__reserved2, 0, sizeof(desc->__reserved2)))
		return -EINVAL;

	if (le64_to_cpu(desc->data_size) > inode->i_size) {
		code_sign_log_error("Wrong data_size: %llu (desc) > %lld (inode)",
				le64_to_cpu(desc->data_size), inode->i_size);
		return -EINVAL;
	}

	if (desc->salt_size > sizeof(desc->salt)) {
		code_sign_log_error("Invalid salt_size: %u", desc->salt_size);
		return -EINVAL;
	}

	if (IS_INSIDE_TREE(desc)) {
		if ((tree_offset > inode->i_size) || (tree_offset % PAGE_SIZE != 0)) {
			code_sign_log_error(
				"Wrong tree_offset: %llu (desc) > %lld (file size) or alignment is wrong",
					tree_offset, inode->i_size);
			return -EINVAL;
		}
	} else {
		if (tree_offset != 0) {
			code_sign_log_error(
					"Wrong tree_offset without tree: %llu (desc) != 0",
					tree_offset);
			return -EINVAL;
		}
	}
	return 1;
}

void code_sign_check_descriptor(const struct inode *inode, const void *desc, int *ret)
{
	*ret = check_code_sign_descriptor(inode, CONST_CAST_CODE_SIGN_DESC(desc));
}

void code_sign_before_measurement(void *_desc, int *ret)
{
	struct code_sign_descriptor *desc = CAST_CODE_SIGN_DESC(_desc);

	if (desc->cs_version) {
		// replace version with cs_version
		desc->version = desc->cs_version;
		desc->cs_version = 0;
		*ret = desc->version;
	}
}

void code_sign_after_measurement(void *_desc, int version)
{
	struct code_sign_descriptor *desc = CAST_CODE_SIGN_DESC(_desc);

	if (version) {
		// restore cs_version
		desc->cs_version = desc->version;
		desc->version = version;
	}
}
