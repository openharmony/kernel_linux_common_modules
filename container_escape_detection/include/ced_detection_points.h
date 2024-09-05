// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _LINUX_CED_DETECTION_POINTS_H
#define _LINUX_CED_DETECTION_POINTS_H

#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/nsproxy.h>

struct cred_info {
	uid_t euid;
	gid_t egid;
	uid_t fsuid;
	kernel_cap_t cap_effective;
};

static inline void cred_info_record(struct cred_info *info, const struct cred *cred)
{
	info->euid = cred->euid.val;
	info->egid = cred->egid.val;
	info->fsuid = cred->fsuid.val;

	memcpy(&info->cap_effective, &cred->cap_effective, sizeof(kernel_cap_t));
}

struct ns_info {
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns;
	struct net *net_ns;
};

static inline void ns_info_record(struct ns_info *info, const struct nsproxy *nsproxy)
{
	if (nsproxy) {
		info->mnt_ns = nsproxy->mnt_ns;
		info->pid_ns = nsproxy->pid_ns_for_children;
		info->net_ns = nsproxy->net_ns;
	}
}

struct process_info {
	struct cred_info cred;
	struct ns_info ns;
};

struct point_info {
	struct rb_node node;
	pid_t tgid;
	uint32_t count;
	struct process_info *info;
};

static inline struct process_info *process_info_record(struct task_struct *task)
{
	struct process_info *info = NULL;
	const struct cred *cred = get_task_cred(task);
	if (cred == NULL) {
		return NULL;
	}

	info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
	if (info == NULL) {
		return NULL;
	}
	memset(info, 0, sizeof(struct process_info));

	cred_info_record(&info->cred, cred);

	if (task->nsproxy != NULL) {
		ns_info_record(&info->ns, task->nsproxy);
	}

	return info;
}

#endif /* _LINUX_CED_DETECTION_POINTS_H */