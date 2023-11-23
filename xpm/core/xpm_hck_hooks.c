// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#include <asm/page.h>

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/hck/lite_hck_xpm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>

#include "exec_signature_info.h"
#include "xpm_common.h"
#include "xpm_debugfs.h"
#include "xpm_hck_hooks.h"
#include "xpm_log.h"
#include "xpm_report.h"

static void xpm_delete_cache_node(struct inode *file_node)
{
	delete_exec_file_signature_info(file_node);
}

static void xpm_region_outer(unsigned long addr_start, unsigned long addr_end,
	unsigned long flags, bool *ret)
{
	struct mm_struct *mm = current->mm;

	if (!mm)
		return;

	/*
	 * VM_UNMAPPED_AREA_XPM identifies the address to allocated in the
	 * xpm_region, just ignore.
	 */
	if (flags & VM_UNMAPPED_AREA_XPM)
		return;

	*ret = ((addr_start >= mm->xpm_region.addr_end) ||
		(addr_end <= mm->xpm_region.addr_start));
}

void xpm_get_unmapped_area(unsigned long addr, unsigned long len,
	unsigned long map_flags, unsigned long unmapped_flags,
	unsigned long *ret)
{
	struct vm_unmapped_area_info info;
	struct mm_struct *mm = current->mm;

	if (!mm)
		return;

	if ((mm->xpm_region.addr_start == 0) && (mm->xpm_region.addr_end == 0))
		return;

	if ((map_flags & MAP_FIXED) && !(addr >= mm->xpm_region.addr_end ||
		addr + len <= mm->xpm_region.addr_start)) {
		xpm_log_error("xpm region not allow mmap with MAP_FIXED");
		*ret = -EFAULT;
		return;
	}

	if (map_flags & MAP_XPM) {
		if (addr) {
			xpm_log_error("xpm region not allow specify addr");
			*ret = -EPERM;
			return;
		}

		info.flags = VM_UNMAPPED_AREA_XPM | unmapped_flags;
		info.length = len;
		info.low_limit = mm->xpm_region.addr_start;
		info.high_limit = mm->xpm_region.addr_end;
		info.align_mask = 0;
		info.align_offset = 0;

		*ret = vm_unmapped_area(&info);
	}
}

/*
 * A xpm readonly region is an area where any page mapped
 * will be marked with XPMReadonly.
 *
 * Return 1 if a region is readonly, otherwise, return 0.
 */
static bool is_xpm_readonly_region(struct vm_area_struct *vma)
{
	/* xpm region */
	if (vma->vm_flags & VM_XPM)
		return true;

	/* !anonymous && executable */
	if (!xpm_is_anonymous_vma(vma) && (vma->vm_flags & VM_EXEC))
		return true;

	return false;
}

void xpm_integrity_check(struct vm_area_struct *vma, unsigned int vflags,
	unsigned long addr, struct page *page, vm_fault_t *ret)
{
	if (!page)
		return;

	/* integrity violation: write a readonly page */
	if ((vflags & FAULT_FLAG_WRITE) && (vma->vm_flags & VM_WRITE) &&
			PageXPMReadonly(page)) {
		report_integrity_event(INTEGRITY_RO, vma, page);
		*ret = xpm_ret(VM_FAULT_SIGSEGV);
		return;
	}

	/* integrity violation: execute a writetained page */
	if (PageXPMWritetainted(page) && is_xpm_readonly_region(vma)) {
		report_integrity_event(INTEGRITY_WT, vma, page);
		*ret = xpm_ret(VM_FAULT_SIGSEGV);
		return;
	}
}

void xpm_integrity_update(struct vm_area_struct *vma, unsigned int vflags,
	struct page *page)
{
	/* set writetainted only if a real write occurred */
	if ((vflags & FAULT_FLAG_WRITE) && (vma->vm_flags & VM_WRITE) &&
			!PageXPMWritetainted(page)) {
		SetPageXPMWritetainted(page);
		return;
	}

	/* set xpm readonly flag */
	if (is_xpm_readonly_region(vma) && !PageXPMReadonly(page))
		SetPageXPMReadonly(page);
}

void xpm_integrity_validate(struct vm_area_struct *vma, unsigned int vflags,
	unsigned long addr, struct page *page, vm_fault_t *ret)
{
	if (!page)
		return;

	xpm_integrity_check(vma, vflags, addr, page, ret);
	if (!*ret)
		xpm_integrity_update(vma, vflags, page);
}

/*
 * check the integrity of these two pages.
 *
 * Return true if equal, otherwise false.
 */
void xpm_integrity_equal(struct page *page, struct page *kpage, bool *ret)
{
	if (!page || !kpage)
		return;

	*ret = ((PageXPMWritetainted(page) == PageXPMWritetainted(kpage)) &&
		(PageXPMReadonly(page) == PageXPMReadonly(kpage)));
}

void xpm_register_hck_hooks(void)
{
	REGISTER_HCK_LITE_HOOK(xpm_delete_cache_node_lhck,
		xpm_delete_cache_node);

	REGISTER_HCK_LITE_HOOK(xpm_region_outer_lhck, xpm_region_outer);
	REGISTER_HCK_LITE_HOOK(xpm_get_unmapped_area_lhck,
		xpm_get_unmapped_area);

	/* xpm integrity */
	REGISTER_HCK_LITE_HOOK(xpm_integrity_equal_lhck, xpm_integrity_equal);
	REGISTER_HCK_LITE_HOOK(xpm_integrity_check_lhck, xpm_integrity_check);
	REGISTER_HCK_LITE_HOOK(xpm_integrity_update_lhck, xpm_integrity_update);
	REGISTER_HCK_LITE_HOOK(xpm_integrity_validate_lhck,
		xpm_integrity_validate);
}
