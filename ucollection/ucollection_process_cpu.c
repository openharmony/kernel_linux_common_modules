/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#include "ucollection_process_cpu.h"

#include <asm/div64.h>
#ifdef CONFIG_CPU_FREQ_TIMES
#include <linux/cpufreq_times.h>
#endif // CONFIG_CPU_FREQ_TIMES
#include <linux/sched/stat.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/sched/signal.h>
#endif // LINUX_VERSION_CODE
#ifdef CONFIG_SMT_MODE_GOV
#include <platform_include/cee/linux/time_in_state.h>
#endif // CONFIG_SMT_MODE_GOV

#include "unified_collection_data.h"

#define NS_TO_MS 1000000
static char dmips_values[DMIPS_NUM];

unsigned long long __attribute__((weak)) get_proc_cpu_load(struct task_struct *task, char dmips[],
	unsigned int dmips_num)
{
	return 0;
}

static void get_process_flt(struct task_struct *task, struct ucollection_process_cpu_item* proc_cpu_entry)
{
	unsigned long tmp_min_flt = 0;
	unsigned long tmp_maj_flt = 0;

	struct task_struct *t = task;
	signed int thread_count = 0;
	do {
		tmp_min_flt += t->min_flt;
		tmp_maj_flt += t->maj_flt;
		++thread_count;
	} while_each_thread(task, t);

	struct signal_struct *sig = task->signal;
	if (sig != NULL) {
		tmp_min_flt += sig->min_flt;
		tmp_maj_flt += sig->maj_flt;
	}

	proc_cpu_entry->min_flt = tmp_min_flt;
	proc_cpu_entry->maj_flt = tmp_maj_flt;
	proc_cpu_entry->thread_total = thread_count;
}

static unsigned long long get_process_load_cputime(struct task_struct *task)
{
	unsigned long long proc_load_cputime = 0;
	proc_load_cputime = get_proc_cpu_load(task, dmips_values, DMIPS_NUM);
	return proc_load_cputime;
}

static void get_process_usage_cputime(struct task_struct *task, unsigned long long *ut, unsigned long long *st)
{
	unsigned long long utime, stime;

	thread_group_cputime_adjusted(task, &utime, &stime);
	do_div(utime, NS_TO_MS);
	do_div(stime, NS_TO_MS);
	*ut = utime;
	*st = stime;
}

static void get_process_load(struct task_struct *task, int cur_count,
	struct ucollection_process_cpu_entry __user *entry)
{
	struct ucollection_process_cpu_item proc_cpu_entry;
	memset(&proc_cpu_entry, 0, sizeof(struct ucollection_process_cpu_item));
	proc_cpu_entry.pid = task->pid;
	get_process_flt(task, &proc_cpu_entry);
	proc_cpu_entry.cpu_load_time = get_process_load_cputime(task);
	get_process_usage_cputime(task, &proc_cpu_entry.cpu_usage_utime, &proc_cpu_entry.cpu_usage_stime);
	(void)copy_to_user(&entry->datas[cur_count], &proc_cpu_entry, sizeof(struct ucollection_process_cpu_item));
}

static void get_thread_load(struct task_struct *task, int cur_count,
	struct ucollection_thread_cpu_entry __user *entry)
{
	struct ucollection_thread_cpu_item thread_cpu_item;
	memset(&thread_cpu_item, 0, sizeof(struct ucollection_thread_cpu_item));
	unsigned long long utime, stime;
	utime = task->utime;
	stime = task->stime;
	do_div(utime, NS_TO_MS);
	do_div(stime, NS_TO_MS);
	thread_cpu_item.tid = task->pid;
	strcpy(thread_cpu_item.name, task->comm);
	thread_cpu_item.cpu_usage_utime = utime;
	thread_cpu_item.cpu_usage_stime = stime;
	thread_cpu_item.cpu_load_time = 0;
	(void)copy_to_user(&entry->datas[cur_count], &thread_cpu_item, sizeof(struct ucollection_thread_cpu_item));
}

static long ioctrl_collect_process_cpu(void __user *argp)
{
	struct task_struct *task = NULL;
	struct ucollection_process_cpu_entry kentry;
	struct ucollection_process_cpu_entry __user *entry = argp;
	if (entry == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}

	memset(&kentry, 0, sizeof(struct ucollection_process_cpu_entry));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_process_cpu_entry));

	rcu_read_lock();
	task = &init_task;
	for_each_process(task) {
		if (task->pid != task->tgid)
			continue;

		if (kentry.cur_count >= kentry.total_count) {
			pr_err("process over total count");
			break;
		}

		get_process_load(task, kentry.cur_count, entry);
		kentry.cur_count++;
	}
	put_user(kentry.cur_count, &entry->cur_count);
	rcu_read_unlock();
	return 0;
}

static struct task_struct* get_alive_task_by_pid(unsigned int pid)
{
	struct task_struct *task = NULL;
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task == NULL || !pid_alive(task)) {
		return NULL;
	}
	return task;
}

static long ioctrl_collect_process_count(void __user *argp)
{
	struct task_struct *task = NULL;
	unsigned int process_count = 0;
	unsigned int __user *count = argp;
	rcu_read_lock();
	task = &init_task;
	for_each_process(task) {
		if (task->pid != task->tgid) {
			continue;
		}
		++process_count;
	}
	rcu_read_unlock();
	put_user(process_count, count);
	return 0;
}

static long read_thread_count_locked(struct ucollection_process_thread_count *kcount,
	struct ucollection_process_thread_count __user *count)
{
	rcu_read_lock();
	struct task_struct *task = get_alive_task_by_pid(kcount->pid);
	if (task == NULL) {
		pr_info("pid=%d is task NULL or not alive", kcount->pid);
		rcu_read_unlock();
		return -EINVAL;
	}
	unsigned int thread_count = 0;
	struct task_struct *t = task;
	do {
		thread_count++;
	} while_each_thread(task, t);
	put_user(thread_count, &count->thread_count);
	rcu_read_unlock();
	return 0;
}

static long ioctrl_collect_thread_count(void __user *argp)
{
	struct ucollection_process_thread_count kcount;
	struct ucollection_process_thread_count __user *count = argp;
	if (count == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}
	memset(&kcount, 0, sizeof(struct ucollection_process_thread_count));
	(void)copy_from_user(&kcount, count, sizeof(struct ucollection_process_thread_count));
	return read_thread_count_locked(&kcount, count);
}

static long ioctrl_collect_app_thread_count(void __user *argp)
{
	struct ucollection_process_thread_count kcount;
	struct ucollection_process_thread_count __user *count = argp;
	if (count == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}
	memset(&kcount, 0, sizeof(struct ucollection_process_thread_count));
	(void)copy_from_user(&kcount, count, sizeof(struct ucollection_process_thread_count));
	if (current->tgid != kcount.pid) {
		pr_err("pid=%d is not self current tgid:%d", kcount.pid, current->tgid);
		return -EINVAL;
	}
	return read_thread_count_locked(&kcount, count);
}

static long read_thread_info_locked(struct ucollection_thread_cpu_entry *kentry,
	struct ucollection_thread_cpu_entry __user *entry)
{
	rcu_read_lock();
	struct task_struct *task = get_alive_task_by_pid(kentry->filter.pid);
	if (task == NULL) {
		pr_info("pid=%d is task NULL not alive", kentry->filter.pid);
		rcu_read_unlock();
		return -EINVAL;
	}
	unsigned int thread_count = 0;
	struct task_struct *t = task;
	do {
		if (thread_count >= kentry->total_count) {
			pr_err("thread over total count");
			break;
		}
		get_thread_load(t, thread_count, entry);
		thread_count++;
	} while_each_thread(task, t);
	put_user(thread_count, &entry->cur_count);
	rcu_read_unlock();
	return 0;
}

static long ioctrl_collect_app_thread_cpu(void __user *argp)
{
	struct ucollection_thread_cpu_entry kentry;
	struct ucollection_thread_cpu_entry __user *entry = argp;
	if (entry == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}
	memset(&kentry, 0, sizeof(struct ucollection_thread_cpu_entry));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_thread_cpu_entry));
	if (current->tgid != kentry.filter.pid || kentry.cur_count >= kentry.total_count) {
		pr_err("pid=%d is not self current tgid:%d , or current count over total count"
			, kentry.filter.pid, current->tgid);
		return -EINVAL;
	}
	return read_thread_info_locked(&kentry, entry);
}

static long ioctrl_collect_the_thread_cpu(void __user *argp)
{
	struct ucollection_thread_cpu_entry kentry;
	struct ucollection_thread_cpu_entry __user *entry = argp;
	if (entry == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}
	memset(&kentry, 0, sizeof(struct ucollection_thread_cpu_entry));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_thread_cpu_entry));
	if (kentry.cur_count >= kentry.total_count) {
		pr_err("pid=%d is not self current:%d , or current count over total count"
			, kentry.filter.pid, current->pid);
		return -EINVAL;
	}
	return read_thread_info_locked(&kentry, entry);
}

static long ioctrl_collect_the_process_cpu(void __user *argp)
{
	struct ucollection_process_cpu_entry kentry;
	struct ucollection_process_cpu_entry __user *entry = argp;
	if (entry == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}

	memset(&kentry, 0, sizeof(struct ucollection_process_cpu_entry));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_process_cpu_entry));

	if (kentry.cur_count >= kentry.total_count) {
		pr_err("current count over total count");
		return -EINVAL;
	}

	rcu_read_lock();
	struct task_struct *task = get_alive_task_by_pid(kentry.filter.pid);
	if (task == NULL) {
		pr_info("pid=%d is task null or not alive", kentry.filter.pid);
		rcu_read_unlock();
		return -EINVAL;
	}

	get_process_load(task, kentry.cur_count, entry);
	kentry.cur_count++;
	put_user(kentry.cur_count, &entry->cur_count);
	rcu_read_unlock();
	return 0;
}

long unified_collection_collect_process_cpu(unsigned int cmd, void __user *argp)
{
	long ret = 0;
	switch(cmd) {
	case IOCTRL_COLLECT_ALL_PROC_CPU:
		ret = ioctrl_collect_process_cpu(argp);
		break;
	case IOCTRL_COLLECT_THE_PROC_CPU:
		ret = ioctrl_collect_the_process_cpu(argp);
		break;
	case IOCTRL_COLLECT_THREAD_COUNT:
		ret = ioctrl_collect_thread_count(argp);
		break;
	case IOCTRL_COLLECT_APP_THREAD_COUNT:
		ret = ioctrl_collect_app_thread_count(argp);
		break;
	case IOCTRL_COLLECT_APP_THREAD:
		ret = ioctrl_collect_app_thread_cpu(argp);
		break;
	case IOCTRL_COLLECT_THE_THREAD:
		ret = ioctrl_collect_the_thread_cpu(argp);
		break;
	case IOCTRL_COLLECT_PROC_COUNT:
		ret = ioctrl_collect_process_count(argp);
		break;
	default:
		pr_err("handle ioctrl cmd %u, _IOC_TYPE(cmd)=%d", cmd, _IOC_TYPE(cmd));
		ret = 0;
	}
	return ret;
}