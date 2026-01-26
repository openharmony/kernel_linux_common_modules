// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/limits.h>

#include "dec_security_hook.h"
#include "dec_common.h"
#include "dec_kernel_interface.h"
#include "dec_log.h"

#define SHAREFS_SUPER_MAGIC 0x20230212

static uint64_t get_tokenid(void)
{
    struct task_struct *curr = current;
    return curr->token;
}

static bool is_sharefs_magic(uint32_t fs_magic)
{
    return fs_magic == SHAREFS_SUPER_MAGIC;
}

static uint32_t dec_acc_permission_change(uint32_t may_mask)
{
    uint32_t dec_flags = 0;

    if (may_mask & MAY_READ) {
        dec_flags |= DEC_READ;
    }

    if ((may_mask & MAY_WRITE) || (may_mask & MAY_APPEND)) {
        dec_flags |= DEC_WRITE;
    }

    return dec_flags;
}

static uint32_t dec_acc_open_change(uint32_t file_flags)
{
    uint32_t dec_flags = 0;
    uint32_t acc_mode = file_flags & O_ACCMODE;

    if (acc_mode == O_RDONLY || acc_mode == O_RDWR) {
        dec_flags |= DEC_READ;
    }

    if (acc_mode == O_WRONLY || acc_mode == O_RDWR) {
        dec_flags |= DEC_WRITE;
    }

    if (file_flags & (O_TRUNC | O_APPEND)) {
        dec_flags |= DEC_WRITE;
    }

    return dec_flags;
}

static char *dec_get_path_buf(void)
{
    return kmalloc(PATH_MAX, GFP_KERNEL);
}

static void dec_free_path_buf(char *buf)
{
    if (buf) {
        kfree(buf);
    }
}

static int dec_generic_path_check(const struct path *dir, uint32_t dec_mode, const char *check_name)
{
    char *path_buf = NULL;
    const char *full_path = NULL;
    int ret = 0;
    uint64_t tokenid = 0;

    if (!dir || !dir->dentry || !dir->dentry->d_inode) {
        dec_loge("%s: invalid param", check_name);
        return -EINVAL;
    }
    uint32_t fs_magic = dir->dentry->d_inode->i_sb->s_magic;
    if (!is_sharefs_magic(fs_magic)) {
        return 0;
    }

    path_buf = dec_get_path_buf();
    if (!path_buf) {
        dec_loge("%s: path_buf malloc failed", check_name);
        return -ENOMEM;
    }

    full_path = d_path(dir, path_buf, PATH_MAX);
    if (IS_ERR(full_path)) {
        dec_loge("%s: get dir path failed, err=%ld", check_name, PTR_ERR(full_path));
        ret = PTR_ERR(full_path);
        goto out;
    }

    tokenid = get_tokenid();

    struct path_tree_params params = {0};
    params.path = full_path;
    params.tokenid = tokenid;
    params.mode = dec_mode;
    params.userid = 0;
    params.persist_flag = false;
    params.timestamp = 0;
    ret = dec_rule_query(&params);

out:
    dec_free_path_buf(path_buf);
    return ret;
}

static int dec_check_file_common(struct file *file, uint32_t dec_mode, const char *check_name)
{
    if (!file || !file->f_inode) {
        dec_loge("%s: invalid param", check_name);
        return -EINVAL;
    }

    return dec_generic_path_check(&file->f_path, dec_mode, check_name);
}

static int dec_check_permission(struct file *file, int may_mask)
{
    if (may_mask <= 0) {
        return 0;
    }
    uint32_t dec_mode = dec_acc_permission_change(may_mask);
    return dec_check_file_common(file, dec_mode, __func__);
}

static int dec_check_open(struct file *file)
{
    if (!file) {
        dec_loge("%s: invalid param", __func__);
        return -EINVAL;
    }
    uint32_t dec_mode = dec_acc_open_change(file->f_flags);
    return dec_check_file_common(file, dec_mode, __func__);
}

static int dec_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
    (void)dentry;
    (void)mode;
    return dec_generic_path_check(dir, DEC_WRITE, __func__);
}

static int dec_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    (void)dentry;
    return dec_generic_path_check(dir, DEC_WRITE, __func__);
}

static int dec_path_unlink(const struct path *dir, struct dentry *dentry)
{
    (void)dentry;
    return dec_generic_path_check(dir, DEC_WRITE, __func__);
}

static int dec_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
    (void)dev;
    /* Only check DEC permissions for standard file types */
    switch (mode & S_IFMT) {
        case S_IFREG:
        case S_IFDIR:
        case S_IFLNK:
            break;
        default:
            return 0;
    }
    return dec_generic_path_check(dir, DEC_WRITE, __func__);
}

static int dec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                           const struct path *new_dir, struct dentry *new_dentry,
                           unsigned int flags)
{
    (void)old_dentry;
    (void)new_dentry;
    (void)flags;
    int ret = 0;

    ret = dec_generic_path_check(old_dir, DEC_WRITE, __func__);
    if (ret != 0) {
        return ret;
    }

    ret = dec_generic_path_check(new_dir, DEC_WRITE, __func__);
    return ret;
}

static int dec_path_access(const struct path *path, int mode)
{

    uint32_t dec_mode = dec_acc_permission_change(mode);
    if (dec_mode == DEC_NONE) {
        return 0;
    }
    return dec_generic_path_check(path, dec_mode, __func__);
}

static struct security_hook_list dec_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(file_permission, dec_check_permission),
    LSM_HOOK_INIT(file_open, dec_check_open),
    LSM_HOOK_INIT(path_mknod, dec_path_mknod),
    LSM_HOOK_INIT(path_mkdir, dec_path_mkdir),
    LSM_HOOK_INIT(path_rmdir, dec_path_rmdir),
    LSM_HOOK_INIT(path_rename, dec_path_rename),
    LSM_HOOK_INIT(path_unlink, dec_path_unlink),
    LSM_HOOK_INIT(path_access, dec_path_access),
};

int dec_hook_init(void)
{
    dec_logi("dec security hooks init");
    security_add_hooks(dec_hooks, ARRAY_SIZE(dec_hooks), "dec_lsm");
    return 0;
}

void dec_hook_exit(void)
{
    dec_logi("dec security hooks exited");
}