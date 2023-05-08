// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "xpm_misc.h"

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/compat.h>
#include <linux/mm_types.h>
#include <linux/miscdevice.h>
#include <linux/xpm_types.h>
#include "xpm_log.h"
#include "xpm_report.h"

#define XPM_SET_REGION _IOW('x', 0x01, struct xpm_region_info)

static int xpm_set_region(unsigned long addr_base, unsigned long length)
{
	int ret = 0;
	unsigned long addr;
	struct mm_struct *mm = current->mm;

	if (!mm)
		return -EINVAL;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	if ((mm->xpm_region.addr_start != 0) ||
		(mm->xpm_region.addr_end != 0)) {
		xpm_log_info("xpm region has been set");
		goto exit;
	}

	addr = get_unmapped_area(NULL, addr_base, length, 0, 0);
	if (IS_ERR_VALUE(addr) || (ULONG_MAX - addr_base < length)) {
		xpm_log_error("xpm get unmmaped area failed");
		ret = -EINVAL;
		goto exit;
	}

	mm->xpm_region.addr_start = addr;
	mm->xpm_region.addr_end = addr + length;
exit:
	mmap_write_unlock(mm);
	return ret;
}

static long xpm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	struct xpm_region_info info = {0};

	if (unlikely(copy_from_user(&info, (void __user *)(uintptr_t)arg,
		sizeof(struct xpm_region_info))))
		return -EFAULT;

	switch (cmd) {
	case XPM_SET_REGION:
		ret = xpm_set_region(info.addr_base, info.length);
		break;
	default:
		xpm_log_error("xpm ioctl cmd error, cmd = %d", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long xpm_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	return xpm_ioctl(file, cmd, (uintptr_t)compat_ptr(arg));
}
#endif

static int xpm_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int xpm_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations xpm_fops = {
	.owner          = THIS_MODULE,
	.open           = xpm_open,
	.release        = xpm_release,
	.unlocked_ioctl = xpm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = xpm_compat_ioctl,
#endif
};

static struct miscdevice xpm_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "xpm",
	.fops  = &xpm_fops,
};

int xpm_register_misc_device(void)
{
	return misc_register(&xpm_misc);
}

void xpm_deregister_misc_device(void)
{
	misc_deregister(&xpm_misc);
}
