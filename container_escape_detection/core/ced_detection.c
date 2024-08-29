// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/fs_struct.h>
#include "ced_log.h"
#include "avc.h"
#include "objsec.h"
#include "ced_detection.h"
#include "ced_detection_points.h"
#include <linux/version.h>

enum ced_event_type {
	EVENT_OK,
	EVENT_CRED_CHANGED,
	EVENT_NSPROXY_CHANGED,
	EVENT_ATTRIBUTE_CHANGED,
	EVENT_TREE_CHANGED,
	EVENT_NUM
};

static struct rb_root root_tree = RB_ROOT;
static struct rw_semaphore point_lock;

static const char *gEventContent[EVENT_NUM - 1] = {
	"cred has been changed illegally.",
	"nsproxy has been changed illegally.",
	"attribute has been changed illegally.",
	"tree has been changed illegally",
};

static inline void print_container_escape_detection(enum ced_event_type type)
{
	if (type < EVENT_NUM)
		ced_log_error("tgid is %d, %s container escape is detected!!!!", current->tgid, gEventContent[type - 1]);
}

static int ced_avc_has_perm(u16 tclass, u32 requested)
{
	struct av_decision avd;
	int rc;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0))
	if (!selinux_initialized(&selinux_state))
		return 1;
#else
	if (!selinux_initialized())
		return 1;
#endif
	u32 sid = current_sid();
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0))
	rc = avc_has_perm_noaudit(&selinux_state, sid, sid, tclass, requested,
		AVC_STRICT, &avd);
#else
	rc = avc_has_perm_noaudit(sid, sid, tclass, requested,
		AVC_STRICT, &avd);
#endif
	return rc;
}

bool ced_has_check_perm(void)
{
	// use selinux label to tell the process is hap process
	int rc = ced_avc_has_perm(SECCLASS_CED, CED__CONTAINER_ESCAPE_CHECK);
	if (rc)
		return false;

	return true;
}

static struct point_info *point_search(pid_t tgid)
{
	struct rb_node *node = root_tree.rb_node;
	while (node != NULL) {
		struct point_info *point = container_of(node, struct point_info, node);
		pid_t result = point->tgid;
		if (result > tgid)
			node = node->rb_left;
		else if (result < tgid)
			node = node->rb_right;
		else
			return point;
	}

	return NULL;
}

static bool point_insert(pid_t tgid, struct process_info *info)
{
	struct rb_node **new = &root_tree.rb_node;
	struct rb_node *parent = NULL;
	struct point_info *point = NULL;
	pid_t result;
	/* Figure out where to put new node */
	while (*new != NULL) {
		point = container_of((*new), struct point_info, node);
		result = point->tgid;
		parent = *new;
		if (result > tgid)
			new = &(*new)->rb_left;
		else if (result < tgid)
			new = &(*new)->rb_right;
		else
			return false;
	}

	point = kmalloc(sizeof(struct point_info), GFP_KERNEL);
	if (point == NULL)
		return false;

	point->tgid = tgid;
	point->count = 1;
	point->info = info;

	/* Add new node and rebalance tree. */
	rb_link_node(&point->node, parent, new);
	rb_insert_color(&point->node, &root_tree);
	return true;
}

void point_erase(pid_t pid)
{
	struct point_info *point = point_search(pid);
	if (point != NULL) {
		rb_erase(&point->node, &root_tree);
		kfree(point->info);
		point->info = NULL;
		kfree(point);
		point=NULL;
	}
}

static bool has_same_attributes(struct process_info *a, struct process_info *b)
{
	if (memcmp(a, b, sizeof(struct process_info)))
		return false;

	return true;
}

static bool has_same_cred(const struct cred *a, struct process_info *b)
{
	if (a->euid.val == b->cred.euid && a->egid.val == b->cred.egid
		&& a->fsuid.val == b->cred.fsuid
		&& memcmp(&a->cap_effective, &b->cred.cap_effective, sizeof(kernel_cap_t)))
		return true;
	
	return false;
}

static bool has_same_nsproxy(const struct nsproxy *a, struct process_info *b)
{
	if (a->mnt_ns == b->ns.mnt_ns && a->pid_ns_for_children == b->ns.pid_ns
		&& a->net_ns == b->ns.net_ns)
		return true;
	
	return false;
}

void ced_initialize(void)
{
	init_rwsem(&point_lock);
}

void setattr_insert_hook(struct task_struct *task)
{
	if (!ced_has_check_perm())
		return;

	pid_t tgid = task->tgid;
	struct process_info *info = process_info_record(task);
	if (info == NULL)
		return;

	down_read(&point_lock);
	struct point_info *result = point_search(task->tgid);
	if (result != NULL) {
		up_read(&point_lock);
		kfree(info);
		print_container_escape_detection(EVENT_TREE_CHANGED);
		return;
	}
	up_read(&point_lock);

	down_write(&point_lock);
	bool ret = point_insert(tgid, info);
	if (!ret) {
		up_write(&point_lock);
		kfree(info);
		ced_log_error("insert point into tree failed");
		return;
	}
	up_write(&point_lock);
}

static int check_tree_and_attribute(pid_t tgid, struct process_info *current_info, struct point_info **point)
{
	struct point_info *result = point_search(tgid);
	if (result == NULL)
		return EVENT_TREE_CHANGED;

	if (!has_same_attributes(result->info, current_info)) {
		return EVENT_ATTRIBUTE_CHANGED;
	}
	*point = result;
	return EVENT_OK;
}

static int check_cred_atrribute(pid_t tgid, const struct cred *new)
{
	struct point_info *result = point_search(tgid);
	if (result == NULL)
		return EVENT_TREE_CHANGED;

	if (!has_same_cred(new, result->info))
		return EVENT_CRED_CHANGED;

	return EVENT_OK;
}

static int check_nsproxy_atrribute(pid_t tgid, const struct nsproxy *new)
{
	struct point_info *result = point_search(tgid);
	if (result == NULL)
		return EVENT_TREE_CHANGED;

	if (!has_same_nsproxy(new, result->info))
		return EVENT_NSPROXY_CHANGED;

	return EVENT_OK;
}

void kernel_clone_hook(struct task_struct *task)
{
	if (!ced_has_check_perm())
		return;

	struct process_info *info = process_info_record(task);
	if (info == NULL)
		return;

	struct point_info *parent = NULL;
	// if clone_flags & (CLONE_PARENT|CLONE_THREAD) 
	// p->real_parent = current->real_parent else task->real_parent = current
	pid_t parent_tgid = task->real_parent->tgid;
	if (task->real_parent == current->real_parent) {
		parent_tgid = task->tgid;
	}
	// check firstly, judge child task's attributes are different from parent task
	down_read(&point_lock);
	int ret = check_tree_and_attribute(parent_tgid, info, &parent);
	up_read(&point_lock);
	if (ret) {
		print_container_escape_detection(ret);
		kfree(info);
		info = NULL;
		return;
	}

	// if the tgid of thread exist in the tree, it doesn't have to insert
	// the node into the tree
	down_write(&point_lock);
	if (task->tgid == parent->tgid) {
		parent->count++;
		up_write(&point_lock);
		kfree(info);
		info = NULL;
		return;
	}

	if (!point_insert(task->tgid, info)) {
		up_write(&point_lock);
		kfree(info);
		ced_log_error("insert point into tree failed");
		return;
	}
	up_write(&point_lock);
}

void switch_task_namespaces_hook(const struct nsproxy *new)
{
	if (new == NULL || !ced_has_check_perm())
		return;

	down_read(&point_lock);
	int ret = check_nsproxy_atrribute(current->tgid, new);
	up_read(&point_lock);
	if (ret)
		print_container_escape_detection(ret);
}

void commit_creds_hook(const struct cred *new)
{
	if (!ced_has_check_perm())
		return;

	down_read(&point_lock);
	int ret = check_cred_atrribute(current->tgid, new);
	up_read(&point_lock);
	if (ret)
		print_container_escape_detection(ret);
}

void detection_hook(struct task_struct *task)
{
	if (!ced_has_check_perm())
		return;

	struct process_info *info = process_info_record(task);
	if (info == NULL)
		return;

	struct point_info *point = NULL;
	// check whether the value of node is same as task
	down_read(&point_lock);
	int ret = check_tree_and_attribute(task->tgid, info, &point);
	up_read(&point_lock);
	if (ret) {
		print_container_escape_detection(ret);
	}
	kfree(info);
}

void exit_hook(struct task_struct *task)
{
	if (!ced_has_check_perm()) {
		return;
	}

	down_read(&point_lock);
	struct point_info *result = point_search(task->tgid);
	if (result == NULL) {
		up_read(&point_lock);
		print_container_escape_detection(EVENT_TREE_CHANGED);
		return;
	}
	up_read(&point_lock);

	down_write(&point_lock);
	result->count--;

	// when thread number is zero, erase the node of tree
	if (result->count == 0) {
		point_erase(task->tgid);
	}
	up_write(&point_lock);
}
