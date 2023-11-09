// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#include <asm/page.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/sched/mm.h>
#include <linux/hck/lite_hck_xpm.h>
#include <linux/fsverity.h>
#include "avc.h"
#include "objsec.h"
#include "xpm_hck.h"
#include "xpm_log.h"
#include "xpm_report.h"
#include "xpm_debugfs.h"
#include "exec_signature_info.h"

static int xpm_value(int value)
{
	return xpm_is_permissve_mode() ? 0 : value;
}

static bool xpm_is_anonymous_vma(struct vm_area_struct *vma)
{
	return vma_is_anonymous(vma) || vma_is_shmem(vma);
}

static int xpm_avc_has_perm(u16 tclass, u32 requested)
{
	struct av_decision avd;
	u32 sid = current_sid();
	int rc, rc2;

	rc = avc_has_perm_noaudit(&selinux_state, sid, sid, tclass, requested,
		AVC_STRICT, &avd);
	rc2 = avc_audit(&selinux_state, sid, sid, tclass, requested, &avd, rc,
		NULL, AVC_STRICT);
	if (rc2)
		return rc2;

	return rc;
}

static int xpm_validate_signature(struct vm_area_struct *vma,
	struct exec_file_signature_info *info)
{
	unsigned long verified_data_end, vm_addr_end;
	const struct inode *inode = (const struct inode *)info->inode;

	if (IS_ERR_OR_NULL(info))
		return xpm_avc_has_perm(SECCLASS_XPM, XPM__EXEC_NO_SIGN);

	if(!exec_file_signature_is_fs_verity(info))
		return 0;

	vm_addr_end = (vma->vm_pgoff << PAGE_SHIFT)
					+ (vma->vm_end - vma->vm_start);
	verified_data_end = PAGE_ALIGN(fsverity_get_verified_data_size(inode));
	if (verified_data_end < vm_addr_end) {
		xpm_log_error("data is out of verified data size.");
		return -EPERM;
	}
	return 0;
}

static int xpm_check_code_segment(bool is_exec, struct vm_area_struct *vma,
	struct exec_file_signature_info *info)
{
	int i;
	unsigned long vm_addr_start, vm_addr_end;
	unsigned long seg_addr_start, seg_addr_end;
	struct exec_segment_info *segments = info->code_segments;

	if (!is_exec)
		return 0;

	if (!segments) {
		xpm_log_error("code segments is NULL");
		return -EINVAL;
	}

	vm_addr_start = vma->vm_pgoff << PAGE_SHIFT;
	vm_addr_end = vm_addr_start + (vma->vm_end - vma->vm_start);

	for (i = 0; i < info->code_segment_count; i++) {
		seg_addr_start = ALIGN_DOWN(segments[i].file_offset, PAGE_SIZE);
		seg_addr_end = PAGE_ALIGN(segments[i].file_offset +
			segments[i].size);
		if ((vm_addr_start >= seg_addr_start) &&
			(vm_addr_end <= seg_addr_end))
			return 0;
	}

	return xpm_avc_has_perm(SECCLASS_XPM, XPM__EXEC_NO_SIGN);
}

static void xpm_check_signature_error(struct file *file, int err_num)
{
	char *full_path;
	char *path;

	if (file == NULL)
		return;

	path = __getname();
	if (path == NULL) {
		xpm_log_error("malloc file name failed");
		return;
	}

	full_path = file_path(file, path, PATH_MAX - 1);
	if (IS_ERR(full_path)) {
		xpm_log_error("get file d_path failed");
		return;
	}

	xpm_log_error("xpm get %s signature info failed, errno = %d", full_path, -err_num);
	__putname(path);
	return;
}

static int xpm_check_signature(struct vm_area_struct *vma, unsigned long prot)
{
	int ret;
	bool is_exec;
	struct exec_file_signature_info *info = NULL;

	/* vma is non-executable or mmap in xpm region just return */
	is_exec = !xpm_is_anonymous_vma(vma) && (prot & PROT_EXEC);
	if (!((vma->vm_flags & VM_XPM) || is_exec))
		return 0;

	/* validate signature when vma is mmap in xpm region or executable */
	ret = get_exec_file_signature_info(vma->vm_file, is_exec, &info);
	if (ret) {
		xpm_check_signature_error(vma->vm_file, ret);
		report_file_event(TYPE_FORMAT_UNDEF, vma->vm_file);
		return ret;
	}

	ret = xpm_validate_signature(vma, info);
	if (ret) {
		xpm_log_error("xpm validate signature info failed");
		report_mmap_event(TYPE_SIGN_INVALID, vma, is_exec, prot);
		goto exit;
	}

	ret = xpm_check_code_segment(is_exec, vma, info);
	if (ret) {
		xpm_log_error("xpm check executable vma mmap code segment failed");
		report_mmap_event(TYPE_DATA_MMAP_CODE, vma, is_exec, prot);
		goto exit;
	}
exit:
	put_exec_file_signature_info(info);
	return ret;
}

static int xpm_check_prot(struct vm_area_struct *vma, unsigned long prot)
{
	int ret;
	bool is_anon;

	is_anon = xpm_is_anonymous_vma(vma);
	if ((vma->vm_flags & VM_XPM) && (is_anon || (prot & PROT_WRITE) ||
		(prot & PROT_EXEC))) {
		xpm_log_error("xpm region mmap not allow anonymous/exec/write permission");
		return -EPERM;
	}

	/* anonymous executable permission need controled by selinux */
	if (is_anon && (prot & PROT_EXEC)) {
		ret = xpm_avc_has_perm(SECCLASS_XPM, XPM__EXEC_ANON_MEM);
		if (ret) {
			xpm_log_error("anonymous mmap not allow exec permission");
			report_mmap_event(TYPE_ANON_EXEC, vma, TYPE_ANON, prot);
			return -EPERM;
		}
	}

	if (!is_anon && (prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		xpm_log_error("file mmap not allow write & exec permission");
		return -EPERM;
	}

	return 0;
}

static int xpm_common_check(struct vm_area_struct *vma, unsigned long prot)
{
	int ret;

	do {
		ret = xpm_check_prot(vma, prot);
		if (ret)
			break;

		ret = xpm_check_signature(vma, prot);
	} while (0);

	return xpm_value(ret);
}

static int xpm_mmap_check(struct vm_area_struct *vma)
{
	return xpm_common_check(vma, vma->vm_flags);
}

static int xpm_mprotect_check(struct vm_area_struct *vma,
	unsigned long reqprot, unsigned long prot)
{
	(void)reqprot;

	return xpm_common_check(vma, prot);
}

void xpm_delete_cache_node(struct inode *file_node)
{
	delete_exec_file_signature_info(file_node);
}

static void xpm_region_outer(unsigned long addr_start, unsigned long addr_end,
	unsigned long flags, bool *ret)
{
	struct mm_struct *mm = current->mm;

	if (!mm)
		return;

	/* Already in xpm region, just return without judge */
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
 * Return 1 if a region is readonly, otherwise, return 0.
 */
static bool is_xpm_readonly_region(struct vm_area_struct *vma)
{
	/* 1. xpm region */
	if (vma->vm_flags & VM_XPM)
		return true;

	/* 2. !anonymous && executable */
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
		report_integrity_event(TYPE_INTEGRITY_RO, vma, page);
		*ret = xpm_value(VM_FAULT_SIGSEGV);
		return;
	}

	/* integrity violation: execute a writetained page */
	if (PageXPMWritetainted(page) && is_xpm_readonly_region(vma)) {
		report_integrity_event(TYPE_INTEGRITY_WT, vma, page);
		*ret = xpm_value(VM_FAULT_SIGSEGV);
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

void  xpm_integrity_validate(struct vm_area_struct *vma, unsigned int vflags,
	unsigned long addr, struct page *page, vm_fault_t *ret)
{
	if (!page)
		return;

	xpm_integrity_check(vma, vflags, addr, page, ret);
	if (!*ret)
		xpm_integrity_update(vma, vflags, page);
}

/*
 * check the integrity of these two pages, return true if equal,
 * otherwise false
 */
void xpm_integrity_equal(struct page *page, struct page *kpage, bool *ret)
{
	if (!page || !kpage)
		return;

	*ret = ((PageXPMWritetainted(page) == PageXPMWritetainted(kpage)) &&
		(PageXPMReadonly(page) == PageXPMReadonly(kpage)));
}

static struct security_hook_list xpm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(mmap_region, xpm_mmap_check),
	LSM_HOOK_INIT(file_mprotect, xpm_mprotect_check),
};

void xpm_register_xpm_hooks(void)
{
	security_add_hooks(xpm_hooks, ARRAY_SIZE(xpm_hooks), "xpm");
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
