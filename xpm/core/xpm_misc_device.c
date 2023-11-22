// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/code_sign.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mm_types.h>

#include "code_sign_ext.h"
#include "xpm_log.h"
#include "xpm_misc_device.h"
#include "xpm_report.h"

#define XPM_SET_REGION _IOW('x', 0x01, struct xpm_config)
#define XPM_SET_OWNERID _IOW('x', 0x02, struct xpm_config)

static int xpm_set_region(struct xpm_config *config)
{
	uint64_t addr;
	struct mm_struct *mm = current->mm;

	if (!mm)
		return -EINVAL;

	if ((mm->xpm_region.addr_start != 0) ||
		(mm->xpm_region.addr_end != 0)) {
		xpm_log_info("xpm region has been set");
		return 0;
	}

	addr = get_unmapped_area(NULL, config->region_addr,
		config->region_length, 0, 0);
	if (IS_ERR_VALUE(addr) || (ULLONG_MAX - addr < config->region_length)) {
		xpm_log_error("xpm get unmmaped area failed");
		return -EINVAL;
	}

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	mm->xpm_region.addr_start = addr;
	mm->xpm_region.addr_end = addr + config->region_length;
	mmap_write_unlock(mm);

	return 0;
}

static int xpm_set_ownerid(struct xpm_config *config)
{
	struct mm_struct *mm = current->mm;

	if (!mm)
		return -EINVAL;

	if (config->id_type >= PROCESS_OWNERID_MAX) {
		xpm_log_error("input ownerid type is invalid");
		return -EINVAL;
	}

#ifndef CONFIG_SECURITY_XPM_DEBUG
	if ((mm->pcs_info.id_type == PROCESS_OWNERID_APP) ||
		mm->pcs_info.id_type == PROCESS_OWNERID_DEBUG) {
		xpm_log_info("process ownerid has been set");
		return 0;
	}
#endif

	if (config->ownerid[MAX_OWNERID_LEN - 1] != '\0') {
		xpm_log_error("input ownerid string is invalid");
		return -EINVAL;
	}

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	code_sign_set_ownerid(&mm->pcs_info, config->id_type,
		config->ownerid, strlen(config->ownerid));
	mmap_write_unlock(mm);

	return 0;
}

static long xpm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;
	struct xpm_config config = {0};

	if (unlikely(copy_from_user(&config, u64_to_user_ptr((uint64_t)arg),
		sizeof(struct xpm_config))))
		return -EFAULT;

	switch (cmd) {
	case XPM_SET_REGION:
		ret = xpm_set_region(&config);
		break;
	case XPM_SET_OWNERID:
		ret = xpm_set_ownerid(&config);
		break;
	default:
		xpm_log_error("xpm ioctl cmd error, cmd = %d", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}

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
	.compat_ioctl   = xpm_ioctl,
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
