/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#ifndef __UNIFIED_COLLECTION_DATA__
#define __UNIFIED_COLLECTION_DATA__

#include <linux/ioctl.h>

// kernel struct, modify at the same time
struct ucollection_process_cpu_item {
	int pid;
	unsigned long long cpu_usage_utime;
	unsigned long long cpu_usage_stime;
	unsigned long long cpu_load_time;
};

struct ucollection_process_filter {
	int uid;
	int pid;
	int tid;
};

struct ucollection_process_cpu_entry {
	int magic;
	int total_count;
	int cur_count;
	struct ucollection_process_filter filter;
	struct ucollection_process_cpu_item datas[];
};

struct ucollection_cpu_dmips {
	int magic;
	int total_count;
	char dmips[];
};

#define IOCTRL_COLLECT_ALL_PROC_CPU_MAGIC 1
#define IOCTRL_COLLECT_THE_PROC_CPU_MAGIC 1
#define IOCTRL_SET_CPU_DMIPS_MAGIC 1
#define DMIPS_NUM 128

#define IOCTRL_COLLECT_CPU_BASE 0
#define IOCTRL_COLLECT_ALL_PROC_CPU _IOR(IOCTRL_COLLECT_CPU_BASE, 1, struct ucollection_process_cpu_entry)
#define IOCTRL_COLLECT_THE_PROC_CPU _IOR(IOCTRL_COLLECT_CPU_BASE, 2, struct ucollection_process_cpu_entry)
#define IOCTRL_SET_CPU_DMIPS _IOW(IOCTRL_COLLECT_CPU_BASE, 3, struct ucollection_cpu_dmips)
#endif // __UNIFIED_COLLECTION_DATA__