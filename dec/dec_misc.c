// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 */

#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "dec_misc.h"

static int vfs_deal_policy_cmd(unsigned int cmd, void __user *arg)
{
    pr_info("vfs dec deal policy cmd:%u\n", cmd);
    int ret = 0;
    struct dec_policy_info info = { 0 };

    ret = copy_from_user(&info, arg, sizeof(info));
    if (ret != 0) {
        pr_err("copy from user failed\n");
        return -EFAULT;
    }

    pr_info("tokenid:%lu path_num:%u persist_flag:%d\n", info.tokenid, info.path_num, info.persist_flag);

    return ret;
}

static int vfs_destroy_dec_policy(void __user *arg)
{
    int ret = 0;
    uint64_t tokenid;

    ret = copy_from_user(&tokenid, arg, sizeof(tokenid));
    if (ret != 0) {
        pr_err("destroy dec policy copy from caller failed\n");
        return -EFAULT;
    }

    pr_info("destroy dec policy tokenid:%ld\n", tokenid);
    return 0;
}

static long dec_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_info("dec ioctl cmd:%u\n", cmd);
    int ret = 0;

    switch (cmd) {
        case SET_DEC_POLICY_CMD:
        case DEL_DEC_POLICY_CMD:
        case QUERY_DEC_POLICY_CMD:
        case CHECK_DEC_POLICY_CMD:
        case CONSTRAINT_DEC_POLICY_CMD:
        case DENY_DEC_POLICY_CMD:
            ret = vfs_deal_policy_cmd(cmd, (void __user *)arg);
            break;
        case DESTROY_DEC_POLICY_CMD:
            ret = vfs_destroy_dec_policy((void __user *)arg);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    return 0;
}

static int dec_open(struct inode *inode, struct file *filp)
{
    pr_info("dec open\n");
    return 0;
}

static int dec_release(struct inode *inode, struct file *filp)
{
    pr_info("dec close\n");
    return 0;
}

static const struct file_operations dec_fops = {
    .owner = THIS_MODULE,
    .open = dec_open,
    .release = dec_release,
    .unlocked_ioctl = dec_ioctl,
    .compat_ioctl = dec_ioctl,
};

static struct miscdevice dec_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "dec",
    .fops = &dec_fops,
};

static int __init dec_init(void)
{
    int err = 0;

    err = misc_register(&dec_misc);
    if (err < 0) {
        pr_err("dec device init failed\n");
        return err;
    }

    pr_err("dec device init success\n");
    return 0;
}

static void __exit dec_exit(void)
{
    misc_deregister(&dec_misc);
    pr_info("dec exited");
}

/* module entry points */
module_init(dec_init);
module_exit(dec_exit);

MODULE_LICENSE("GPL");
