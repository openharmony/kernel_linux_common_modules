/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif // CONFIG_COMPAT

#include "ucollection_process_cpu.h"

static long (*unified_collection_ioctl_cb[])(unsigned int cmd, void __user *argp) = {
	unified_collection_collect_process_cpu       /* IOCTRL_COLLECT_CPU */
};

static long unified_collection_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = u64_to_user_ptr(arg);
	const char *comm = NULL;

	if ((_IOC_TYPE(cmd) >= ARRAY_SIZE(unified_collection_ioctl_cb)) ||
		(unified_collection_ioctl_cb[_IOC_TYPE(cmd)] == NULL)) {
			pr_err("invalid ioctrl cmd %u, _IOC_TYPE(cmd)=%d", cmd, _IOC_TYPE(cmd));
			return -EINVAL;
	}

	return unified_collection_ioctl_cb[_IOC_TYPE(cmd)](cmd, argp);
}

#ifdef CONFIG_COMPAT
static long unified_collection_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return unified_collection_ioctl(filp, cmd, (unsigned long) compat_ptr(arg));
}
#endif // CONFIG_COMPAT

static int unified_collection_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int unified_collection_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations unified_collection_device_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = unified_collection_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = unified_collection_compat_ioctl,
#endif // CONFIG_COMPAT
	.open = unified_collection_open,
	.release = unified_collection_release,
};

static struct miscdevice unified_collection_device = {
	.name = "ucollection",
	.fops = &unified_collection_device_fops,
	.minor = MISC_DYNAMIC_MINOR,
};

static int __init unified_collection_init(void)
{
	int ret = misc_register(&unified_collection_device);
	if (ret) {
		pr_err("failed to register unified collection device");
		return ret;
	}

	pr_info("register unified collection device successful");
	return 0;
}

static void __exit unified_collection_exit(void)
{
	pr_info("deregister unified collection device successful");
	misc_deregister(&unified_collection_device);
}

module_init(unified_collection_init);
module_exit(unified_collection_exit);

MODULE_AUTHOR("OHOS");
MODULE_DESCRIPTION("Unified Collection Driver");
MODULE_LICENSE("GPL");