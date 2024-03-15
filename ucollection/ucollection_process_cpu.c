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

static int get_cpu_num(void)
{
	int core_num = 0;
	int i = 0;
	for_each_possible_cpu(i)
		core_num++;
	return core_num;
}

static void get_process_flt(struct task_struct *task, unsigned long long *min_flt, unsigned long long *maj_flt)
{
	unsigned long tmp_min_flt = 0;
	unsigned long tmp_maj_flt = 0;

	struct task_struct *t = task;
	do {
		tmp_min_flt += t->min_flt;
		tmp_maj_flt += t->maj_flt;

	} while_each_thread(task, t);

	struct signal_struct *sig = task->signal;
	if (sig != NULL) {
		tmp_min_flt += sig->min_flt;
		tmp_maj_flt += sig->maj_flt;
	}

	*min_flt = tmp_min_flt;
	*maj_flt = tmp_maj_flt;
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

static void get_process_load(struct task_struct *task, int cpu_num, int cur_count,
	struct ucollection_process_cpu_entry __user *entry)
{
	struct ucollection_process_cpu_item proc_cpu_entry;
	memset(&proc_cpu_entry, 0, sizeof(struct ucollection_process_cpu_item));
	proc_cpu_entry.pid = task->pid;
	get_process_flt(task, &proc_cpu_entry.min_flt, &proc_cpu_entry.maj_flt);
	proc_cpu_entry.cpu_load_time = get_process_load_cputime(task);
	get_process_usage_cputime(task, &proc_cpu_entry.cpu_usage_utime, &proc_cpu_entry.cpu_usage_stime);
	(void)copy_to_user(&entry->datas[cur_count], &proc_cpu_entry, sizeof(struct ucollection_process_cpu_item));
}

static long ioctrl_collect_process_cpu(void __user *argp)
{
	int cpu_num = 0;
	struct task_struct *task = NULL;
	struct ucollection_process_cpu_entry kentry;
	struct ucollection_process_cpu_entry __user *entry = argp;
	if (entry == NULL) {
		pr_err("cpu entry is null");
		return -EINVAL;
	}

	memset(&kentry, 0, sizeof(struct ucollection_process_cpu_entry));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_process_cpu_entry));

	cpu_num = get_cpu_num();
	rcu_read_lock();
	task = &init_task;
	for_each_process(task) {
		if (task->pid != task->tgid)
			continue;

		if (kentry.cur_count >= kentry.total_count) {
			pr_err("process over total count");
			break;
		}

		get_process_load(task, cpu_num, kentry.cur_count, entry);
		kentry.cur_count++;
	}
	put_user(kentry.cur_count, &entry->cur_count);
	rcu_read_unlock();
	return 0;
}

static bool is_pid_alive(int pid)
{
	struct task_struct *task = NULL;
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task == NULL)
		return false;

	return pid_alive(task);
}

static long ioctrl_collect_the_process_cpu(void __user *argp)
{
	int cpu_num = 0;
	struct task_struct *task = NULL;
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
	if (!is_pid_alive(kentry.filter.pid)) {
		pr_err("pid=%d is not alive", kentry.filter.pid);
		rcu_read_unlock();
		return -EINVAL;
	}

	task = find_task_by_vpid(kentry.filter.pid);
	if (task == NULL) {
		pr_err("can not get pid=%d", task->pid);
		rcu_read_unlock();
		return -EINVAL;
	}

	cpu_num = get_cpu_num();
	get_process_load(task, cpu_num, kentry.cur_count, entry);
	kentry.cur_count++;
	put_user(kentry.cur_count, &entry->cur_count);
	rcu_read_unlock();
	return 0;
}

static long ioctrl_set_cpu_dmips(void __user *argp)
{
	int i;
	struct ucollection_cpu_dmips kentry;
	struct ucollection_cpu_dmips __user *entry = argp;
	memset(&kentry, 0, sizeof(struct ucollection_cpu_dmips));
	(void)copy_from_user(&kentry, entry, sizeof(struct ucollection_cpu_dmips));
	pr_info("set dimps %d cpus\n", kentry.total_count);
	for (i = 0; i < DMIPS_NUM; i++) {
		if (i >= kentry.total_count)
			break;
		get_user(dmips_values[i], &entry->dmips[i]);
		pr_info("set dimps cpu[%d]=%d\n", i, dmips_values[i]);
	}
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
	case IOCTRL_SET_CPU_DMIPS:
		ret = ioctrl_set_cpu_dmips(argp);
		break;
	default:
		pr_err("handle ioctrl cmd %u, _IOC_TYPE(cmd)=%d", cmd, _IOC_TYPE(cmd));
		ret = 0;
	}
	return ret;
}