// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/string.h>

#include "dec_misc.h"
#include "dec_security_hook.h"
#include "sysctl.h"
#include "dec_common.h"
#include "dec_log.h"
#include "dec_utils.h"
#include "dec_path_tree.h"
#include "dec_constraint_tree.h"

static const char *cmd_to_string(unsigned int cmd)
{
    switch (cmd) {
        case SET_DEC_RULE_CMD:
        case SET_DEC_RULE_CMD_32:
            return "SET_DEC_RULE";
        case DEL_DEC_RULE_CMD:
        case DEL_DEC_RULE_CMD_32:
            return "DEL_DEC_RULE";
        case QUERY_DEC_RULE_CMD:
        case QUERY_DEC_RULE_CMD_32:
            return "QUERY_DEC_RULE";
        case CHECK_DEC_RULE_CMD:
        case CHECK_DEC_RULE_CMD_32:
            return "CHECK_DEC_RULE";
        case DESTROY_DEC_RULE_CMD:
        case DESTROY_DEC_RULE_CMD_32:
            return "DESTROY_DEC_RULE";
        case CONSTRAINT_DEC_RULE_CMD:
        case CONSTRAINT_DEC_RULE_CMD_32:
            return "CONSTRAINT_DEC_RULE";
        case DEL_DEC_RULE_BY_USER_CMD:
        case DEL_DEC_RULE_BY_USER_CMD_32:
            return "DEL_DEC_RULE_BY_USER";
        case SET_DEC_PREFIX_CMD:
        case SET_DEC_PREFIX_CMD_32:
            return "SET_DEC_PREFIX";
        default:
            return "UNKNOWN_CMD";
    }
}

static char *copy_user_path(uintptr_t user_path_ptr, uint32_t path_len)
{
    if (path_len == 0 || path_len > PATH_MAX) {
        dec_logw("Invalid path length %u (max %d)", path_len, PATH_MAX);
        return NULL;
    }

    char *kernel_path = kmalloc(path_len + 1, GFP_KERNEL);
    if (kernel_path == NULL) {
        dec_loge("Failed to allocate memory for path (size %u)", path_len + 1);
        return NULL;
    }
    if (copy_from_user(kernel_path, (const char __user *)user_path_ptr, path_len) != 0) {
        dec_loge("Failed to copy path from user space (ptr=0x%lx, len=%u)",
                 (unsigned long)user_path_ptr, path_len);
        kfree(kernel_path);
        return NULL;
    }
    kernel_path[path_len] = '\0';
    return kernel_path;
}

static void ioctl_set_rule(struct dec_rule_s *info)
{
    int ret = 0;
    uint64_t tokenid = info->tokenid & DEC_TOKENID_MASK;

    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (!path) {
            dec_logw("Failed to get path for index %u", i);
            continue;
        }
        uint32_t mode = info->path[i].mode;

        struct path_tree_params params = {0};
        params.path = path;
        params.tokenid = tokenid;
        params.mode = mode;
        params.userid = info->user_id;
        params.persist_flag = info->persist_flag;
        params.timestamp = info->timestamp;

        ret = dec_set_rule(&params);
        if (ret) {
            dec_loge("Failed to set rule for path '%s' (tokenid=0x%llx, mode=0x%x): %d",
                     path, tokenid, mode, ret);
            info->path[i].ret_flag = FLAG_FALSE;
        } else {
            info->path[i].ret_flag = FLAG_TRUE;
        }

        kfree(path);
    }
}

static void ioctl_delete_rule(struct dec_rule_s *info)
{
    int ret = 0;
    uint64_t tokenid = info->tokenid & DEC_TOKENID_MASK;

    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (!path) {
            dec_logw("Failed to get path for index %u", i);
            continue;
        }
        uint64_t timestamp = info->timestamp;
        ret = dec_delete_rule(tokenid, path, timestamp);
        if (ret) {
            dec_loge("Failed to delete rule for path %s, ret=%d", path, ret);
            info->path[i].ret_flag = FLAG_FALSE;
        } else {
            info->path[i].ret_flag = FLAG_TRUE;
        }

        kfree(path);
    }
}

static void ioctl_query_rule(struct dec_rule_s *info, bool is_persist)
{
    uint64_t tokenid = info->tokenid & DEC_TOKENID_MASK;

    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (is_path_valid(path) != 0) {
            dec_logw("Invalid path for query: %s", path);
            info->path[i].ret_flag = FLAG_FALSE;
            if (path) kfree(path);
            continue;
        }

        /* Bypass check if path is not in constraint tree */
        if (!dec_constraint_query(path)) {
            info->path[i].ret_flag = FLAG_TRUE;
            dec_logd("Path '%s' not in constraint tree - access allowed", path);
            kfree(path);
            continue;
        }

        /* Check permission in path tree */
        uint32_t mode = info->path[i].mode;
        if (dec_path_tree_query(tokenid, path, mode, is_persist)) {
            info->path[i].ret_flag = FLAG_TRUE;
        } else {
            info->path[i].ret_flag = FLAG_FALSE;
        }
        dec_logd("Query rule for path '%s' (tokenid=0x%llx, mode=0x%x, is_persist=%d): %s",
                 path, tokenid, mode, is_persist,
                 info->path[i].ret_flag == FLAG_TRUE ? "ALLOWED" : "DENIED");

        kfree(path);
    }

    return;
}

static void ioctl_constraint_add(struct dec_rule_s *info)
{
    int ret = 0;

    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (!path) {
            dec_logw("Failed to get path for index %u", i);
            continue;
        }
        ret = dec_constraint_add(path);
        if (ret != 0) {
            dec_loge("Failed to add constraint path %s, ret=%d", path, ret);
            info->path[i].ret_flag = FLAG_FALSE;
        } else {
            info->path[i].ret_flag = FLAG_TRUE;
        }

        kfree(path);
    }
}

static void ioctl_set_prefix(struct dec_rule_s *info)
{
    int ret = 0;

    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (!path) {
            dec_logw("Failed to get path for index %u", i);
            continue;
        }
        ret = dec_set_prefix(path);
        if (ret) {
            dec_loge("Failed to set constraint prefix %s, ret=%d", path, ret);
            info->path[i].ret_flag = FLAG_FALSE;
        } else {
            info->path[i].ret_flag = FLAG_TRUE;
        }

        kfree(path);
    }
}

static void ioctl_delete_rule_by_tokenid(struct dec_rule_s *info)
{
    struct dec_destroy_ctx ctx = {0};
    ctx.criteria = DELETE_BY_TOKENID;
    ctx.params.tokeninfo.tokenid = info->tokenid & DEC_TOKENID_MASK;
    ctx.timestamp = info->timestamp;
    dec_destroy_rule_by_id(&ctx);
}

static void ioctl_delete_rule_by_userid(struct dec_rule_s *info)
{
    for (unsigned int i = 0; i < info->path_num; i++) {
        char *path = copy_user_path((uintptr_t)info->path[i].path, info->path[i].path_len);
        if (!path) {
            dec_logw("Failed to get path for index %u", i);
            continue;
        }
        struct dec_destroy_ctx ctx = {0};
        ctx.criteria = DELETE_BY_USERID;
        ctx.params.userinfo.userid = info->user_id;
        ctx.params.userinfo.path = path;
        ctx.timestamp = info->timestamp;
        if (dec_destroy_rule_by_id(&ctx) == 0) {
            info->path[i].ret_flag = FLAG_TRUE;
        } else {
            dec_loge("Failed to delete rule by userid %d and path %s", info->user_id, path);
            info->path[i].ret_flag = FLAG_FALSE;
        }

        kfree(path);
    }
}

static void dec_rule_32_to_64(struct dec_rule_s_32 *info_32, struct dec_rule_s *info)
{
    if (info_32 == NULL || info == NULL) {
        dec_loge("Invalid parameters for 32-to-64 rule conversion");
        return;
    }
    info->tokenid = info_32->tokenid;
    info->timestamp = info_32->timestamp;
    info->path_num = info_32->path_num;
    info->user_id = info_32->user_id;
    info->persist_flag = info_32->persist_flag;
    memcpy(info->reserved, info_32->reserved, sizeof(info->reserved));

    for (unsigned int i = 0; i < info->path_num; i++) {
        info->path[i].path = (uintptr_t)(uint32_t)info_32->path[i].path;
        info->path[i].path_len = info_32->path[i].path_len;
        info->path[i].mode = info_32->path[i].mode;
        info->path[i].ret_flag = FLAG_FALSE;
    }
}

static void dec_rule_64_to_32(struct dec_rule_s *info, struct dec_rule_s_32 *info_32)
{
    if (info_32 == NULL || info == NULL) {
        dec_loge("Invalid parameters for 64-to-32 rule conversion");
        return;
    }
    info_32->tokenid = info->tokenid;
    info_32->timestamp = info->timestamp;
    info_32->path_num = info->path_num;
    info_32->user_id = info->user_id;
    info_32->persist_flag = info->persist_flag;
    memcpy(info_32->reserved, info->reserved, sizeof(info_32->reserved));

    for (unsigned int i = 0; i < info->path_num; i++) {
        info_32->path[i].path = (uint32_t)(uintptr_t)info->path[i].path;
        info_32->path[i].path_len = info->path[i].path_len;
        info_32->path[i].mode = info->path[i].mode;
        info_32->path[i].ret_flag = info->path[i].ret_flag;
    }
}

static int vfs_deal_rule_cmd(unsigned int cmd, void __user *arg)
{
    struct dec_rule_s info = { 0 };
    bool needs_copy_back = true;

    if (copy_from_user(&info, arg, sizeof(info))) {
        dec_loge("Failed to copy 64-bit rule from user space");
        return -EFAULT;
    }

    if (info.path_num > MAX_POLICY_NUM) {
        dec_loge("Invalid path count %u (max %d)", info.path_num, MAX_POLICY_NUM);
        return -EINVAL;
    }

    switch (cmd) {
        case SET_DEC_RULE_CMD:
            ioctl_set_rule(&info);
            break;
        case DEL_DEC_RULE_CMD:
            ioctl_delete_rule(&info);
            break;
        case QUERY_DEC_RULE_CMD:
            ioctl_query_rule(&info, true);  /* Persistent rules */
            break;
        case CHECK_DEC_RULE_CMD:
            ioctl_query_rule(&info, false); /* Temporary rules */
            break;
        case DESTROY_DEC_RULE_CMD:
            ioctl_delete_rule_by_tokenid(&info);
            needs_copy_back = false;
            break;
        case CONSTRAINT_DEC_RULE_CMD:
            ioctl_constraint_add(&info);
            break;
        case DEL_DEC_RULE_BY_USER_CMD:
            ioctl_delete_rule_by_userid(&info);
            break;
        case SET_DEC_PREFIX_CMD:
            ioctl_set_prefix(&info);
            break;
        default:
            dec_loge("Unknown 64-bit DEC command: %u", cmd);
            return -EINVAL;
            break;
    }

    if (needs_copy_back && copy_to_user(arg, &info, sizeof(info))) {
        dec_loge("Failed to copy 64-bit rule to user space");
        return -EFAULT;
    }
    dec_logi("Completed 64-bit DEC command: %s (tokenid=0x%llx, path_num=%u)",
             cmd_to_string(cmd), info.tokenid, info.path_num);

    return 0;
}

static int vfs_deal_rule_cmd_32(unsigned int cmd, void __user *arg)
{
    int ret = 0;
    struct dec_rule_s_32 *info_32 = NULL;
    struct dec_rule_s *info = NULL;
    bool needs_copy_back = true;

    /* Allocate memory for rule structures (prevent stack overflow) */
    info_32 = kmalloc(sizeof(struct dec_rule_s_32), GFP_KERNEL);
    info = kmalloc(sizeof(struct dec_rule_s), GFP_KERNEL);
    if (!info_32 || !info) {
        dec_loge("Failed to allocate memory for 32-bit rule processing");
        ret = -ENOMEM;
        goto cleanup;
    }

    if (copy_from_user(info_32, arg, sizeof(struct dec_rule_s_32))) {
        dec_loge("Failed to copy 32-bit rule from user space");
        ret = -EFAULT;
        goto cleanup;
    }

    if (info_32->path_num > MAX_POLICY_NUM) {
        dec_loge("Invalid path count %u (max %d)", info_32->path_num, MAX_POLICY_NUM);
        ret = -EINVAL;
        goto cleanup;
    }
    dec_rule_32_to_64(info_32, info);
    switch (cmd) {
        case SET_DEC_RULE_CMD_32:
            ioctl_set_rule(info);
            break;
        case DEL_DEC_RULE_CMD_32:
            ioctl_delete_rule(info);
            break;
        case QUERY_DEC_RULE_CMD_32:
            ioctl_query_rule(info, true);  /* Persistent rules */
            break;
        case CHECK_DEC_RULE_CMD_32:
            ioctl_query_rule(info, false); /* Temporary rules */
            break;
        case DESTROY_DEC_RULE_CMD_32:
            ioctl_delete_rule_by_tokenid(info);
            needs_copy_back = false;
            break;
        case CONSTRAINT_DEC_RULE_CMD_32:
            ioctl_constraint_add(info);
            break;
        case DEL_DEC_RULE_BY_USER_CMD_32:
            ioctl_delete_rule_by_userid(info);
            break;
        case SET_DEC_PREFIX_CMD_32:
            ioctl_set_prefix(info);
            break;
        default:
            dec_loge("Unknown 32-bit DEC command: %u", cmd);
            ret = -EINVAL;
            goto cleanup;
    }

    if (needs_copy_back) {
        dec_rule_64_to_32(info, info_32);
        if (copy_to_user(arg, info_32, sizeof(struct dec_rule_s_32))) {
            dec_loge("Failed to copy 32-bit rule to user space");
            ret = -EFAULT;
            goto cleanup;
        }
    }
    dec_logi("Completed 32-bit DEC command: %s (tokenid=0x%llx, path_num=%u)",
             cmd_to_string(cmd), info_32->tokenid, info_32->path_num);

cleanup:
    if (info_32) kfree(info_32);
    if (info) kfree(info);
    return ret;
}

static int dec_open(struct inode *inode, struct file *filp)
{
    dec_logi("dec device opened");
    return 0;
}

static int dec_release(struct inode *inode, struct file *filp)
{
    dec_logi("dec device released");
    return 0;
}

static long dec_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    switch (cmd) {
        case SET_DEC_RULE_CMD:
        case DEL_DEC_RULE_CMD:
        case QUERY_DEC_RULE_CMD:
        case CHECK_DEC_RULE_CMD:
        case DESTROY_DEC_RULE_CMD:
        case CONSTRAINT_DEC_RULE_CMD:
        case DEL_DEC_RULE_BY_USER_CMD:
        case SET_DEC_PREFIX_CMD:
            dec_logi("Handling 64-bit ioctl cmd=%s", cmd_to_string(cmd));
            ret = vfs_deal_rule_cmd(cmd, (void __user *)arg);
            break;
        default:
            dec_loge("Unknown 64-bit ioctl cmd=%u", cmd);
            ret = -EINVAL;
            break;
    }

    return ret;
}

#ifdef CONFIG_COMPAT
static long dec_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    switch (cmd) {
        case SET_DEC_RULE_CMD_32:
        case DEL_DEC_RULE_CMD_32:
        case QUERY_DEC_RULE_CMD_32:
        case CHECK_DEC_RULE_CMD_32:
        case DESTROY_DEC_RULE_CMD_32:
        case CONSTRAINT_DEC_RULE_CMD_32:
        case DEL_DEC_RULE_BY_USER_CMD_32:
        case SET_DEC_PREFIX_CMD_32:
            dec_logi("Handling 32-bit ioctl cmd=%s", cmd_to_string(cmd));
            ret = vfs_deal_rule_cmd_32(cmd, compat_ptr(arg));
            break;
        default:
            dec_loge("Unknown 32-bit ioctl cmd=%u", cmd);
            ret = -EINVAL;
            break;
    }

    return ret;
}
#endif

static const struct file_operations dec_fops = {
    .owner = THIS_MODULE,
    .open = dec_open,
    .release = dec_release,
    .unlocked_ioctl = dec_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = dec_compat_ioctl,
#endif
};

static struct miscdevice dec_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "dec",
    .fops = &dec_fops,
};

static int __init dec_init(void)
{
    int err = 0;
    dec_logi("Initializing DEC module");

    dec_sysctl_init();

    err = misc_register(&dec_misc);
    if (err) {
        dec_loge("Failed to register DEC misc device: %d", err);
        return err;
    }

    dec_hook_init();
    dec_logi("DEC module initialized successfully");
    return 0;
}

static void __exit dec_exit(void)
{
    dec_logi("Cleaning up DEC module");
    dec_hook_exit();
    misc_deregister(&dec_misc);
    dec_logi("DEC misc device deregistered");
}

module_init(dec_init);
module_exit(dec_exit);

MODULE_LICENSE("GPL");