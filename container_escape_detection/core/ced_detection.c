// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/fs_struct.h>
#include "ced_log.h"
#include "avc.h"
#include "objsec.h"
#include "ced_detection.h"

enum ced_event_type {
	EVENT_CRED_ROOT,
	EVENT_NSPROXY_ROOT,
	EVENT_HAS_ROOT,
	EVENT_NUM
};

extern struct task_struct init_task;

static const char *gEventContent[EVENT_NUM] = {
	"cred has been changed to root.",
	"nsproxy has been changed to init.",
	"process has been rooted."
};

static inline void print_container_escape_detection(enum ced_event_type type)
{
	if (type < EVENT_NUM) {
		ced_log_error("tgid is %d, %s container escape is detected!!!!", current->tgid, gEventContent[type]);
	}
}

static int ced_avc_has_perm(u16 tclass, u32 requested)
{
	struct av_decision avd;
	u32 sid = current_sid();
	int rc;

	rc = avc_has_perm_noaudit(&selinux_state, sid, sid, tclass, requested,
		AVC_STRICT, &avd);

	return rc;
}

static bool ced_has_check_perm(void)
{
	// use selinux label to tell the process is hap process
	int rc = ced_avc_has_perm(SECCLASS_CED, CED__CONTAINER_ESCAPE_CHECK);
	if (rc) {
		return false;
	}

	return true;
}

static uint64_t process_ns_pac_hash(const struct nsproxy *nsproxy)
{
	uint64_t pac_hash = 0;
	uintptr_t ns_ptr = (uintptr_t)nsproxy->mnt_ns;
	pac_hash ^= ns_ptr;
	ns_ptr = (uintptr_t)nsproxy->pid_ns_for_children;
	pac_hash ^= ns_ptr;
	ns_ptr = (uintptr_t)nsproxy->net_ns;
	pac_hash ^= ns_ptr;
	return pac_hash;
}

static bool is_container_process(const struct nsproxy *new)
{
	uint64_t current_pac_hash = process_ns_pac_hash(new);
	uint64_t init_task_ns_pac = process_ns_pac_hash(init_task.nsproxy);
	if (current_pac_hash == init_task_ns_pac) {
		return false;
	} else {
		return true;
	}
}

static bool detection_promotion_privilege(const struct cred *new)
{
	const struct cred *init_cred = get_task_cred(&init_task);
	bool flag = false;
	if (new->euid.val == 0 || new->egid.val == 0 || new->fsuid.val == 0
		|| !memcmp(&new->cap_effective, &init_cred->cap_effective, sizeof(kernel_cap_t))) {
		flag = true;
	}
	return flag;
}

void switch_task_namespaces_hook(const struct nsproxy *new)
{
	if (!ced_has_check_perm()) {
		return;
	}

	if (new == NULL) {
		return;
	}

	if (!is_container_process(new)) {
		print_container_escape_detection(EVENT_NSPROXY_ROOT);
	}
}

void commit_creds_hook(const struct cred *new)
{
	if (!ced_has_check_perm()) {
		return;
	}

	if (detection_promotion_privilege(new)) {
		print_container_escape_detection(EVENT_CRED_ROOT);
	}
}

void detection_hook(struct task_struct *task)
{
	if (!ced_has_check_perm()) {
		return;
	}

	const struct cred *cred = get_task_cred(task);

	if ((!is_container_process(task->nsproxy) || (detection_promotion_privilege(cred)))) {
		print_container_escape_detection(EVENT_HAS_ROOT);
	}
}