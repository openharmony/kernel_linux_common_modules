// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <internal.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/hck/lite_hck_hideaddr.h>
#include <linux/hck/lite_vendor_hooks.h>
#include <linux/init.h>
#include <linux/module.h>

#include "avc.h"
#include "objsec.h"
#include "hideaddr.h"

static bool is_anon_exec(struct vm_area_struct *vma)
{
	const char *name = NULL;
	vm_flags_t flags = vma->vm_flags;

	if (!(flags & VM_EXEC))
		return false;

	name = arch_vma_name(vma);
	if (!name) {
		struct anon_vma_name *anon_name;
		anon_name = anon_vma_name(vma);
		if (!anon_name)
			return false;
	}
	return true;
}

static int hideaddr_avc_has_perm(u16 tclass, u32 requested, struct seq_file *m)
{
	struct av_decision avd;
	struct inode *inode_task = file_inode(m->file);
	struct task_struct *task = get_proc_task(inode_task);
	u32 secid;

	security_cred_getsecid(task->cred, &secid);
	return avc_has_perm_noaudit(&selinux_state, secid, secid, tclass, requested,
		AVC_STRICT, &avd);
}

static void hideaddr_header_prefix(unsigned long *start, unsigned long *end,
			vm_flags_t *flags, struct seq_file *m, struct vm_area_struct *vma)
{
	if (!is_anon_exec(vma))
		return;

	if (hideaddr_avc_has_perm(SECCLASS_HIDEADDR, HIDEADDR__HIDE_EXEC_ANON_MEM, m))
		return;

	if (!hideaddr_avc_has_perm(SECCLASS_HIDEADDR, HIDEADDR__HIDE_EXEC_ANON_MEM_DEBUG, m))
		return;

	*start = 0;
	*end = 0;
	*flags = 0;
}

void hideaddr_header_prefix_lhck_register(void)
{
	REGISTER_HCK_LITE_HOOK(hideaddr_header_prefix_lhck, hideaddr_header_prefix);
}