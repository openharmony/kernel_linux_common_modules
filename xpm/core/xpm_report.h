/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_REPORT_H
#define _XPM_REPORT_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/xpm_types.h>

#define NULL_STR "NULL"

#define MAX_FILENAME_LEN 128

/* EVENT_INIT */
#define DEVICEFS_UNINIT      "devicefs uninitialized"
#define DEBUGFS_UNINIT       "debugfs uninitialized"
#define DM_DISABLE           "dm-verity disable"

/* EVENT_FILE */
#define FORMAT_UNDEF         "unkown file format"

/* EVENT_MMAP */
#define ANON_EXEC            "anon executed"
#define GET_SIGN_FAIL        "get signature info failed"
#define SIGN_INVALID         "invalid signature"
#define DATA_MMAP_CODE       "data mmap code"
#define OWNERID_INCONSISTENT "ownerid inconsistent"

/* EVENT_INTEGRITY */
#define INTEGRITY_RO         "code tampered"
#define INTEGRITY_WT         "data executed"

enum xpm_code_type {
	TYPE_ABC = 0,
	TYPE_ELF,
	TYPE_ANON,
};

enum xpm_event_id {
	EVENT_INIT      = 1011009110,
	EVENT_FILE      = 1011009111,
	EVENT_MMAP      = 1011009112,
	EVENT_INTEGRITY = 1011009113,
};

/* set of report info */
struct xpm_report_info {
	char *event_type;
	char *code_type;

	pid_t pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN + 1];
	struct cs_info pcs_info;
	struct cs_info fcs_info;

	unsigned long vm_prot;
	unsigned long vm_pgprot;
	unsigned long vm_pgoff;
	unsigned long vm_size;

	char *page_type;
	pgoff_t page_index;

	ktime_t timestamp;
};

/* set of caller parameters */
struct xpm_report_param {
	char *event_type;
	enum xpm_event_id event_id;
	enum xpm_code_type code_type;
	struct vm_area_struct *vma;
	unsigned long vm_prot;
	struct page *page;
	struct file *file;

	int (*set_content)(struct xpm_report_info *info, uint8_t *content,
		uint32_t content_len);
};

#define MAX_CONTENT_LEN 900
#define XPM_EVENT_VERSION 0

#ifndef CONFIG_SECURITY_XPM_DEBUG
#define xpm_report_ratelimited(func, fmt, ...) \
	do { \
		static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL, \
			DEFAULT_RATELIMIT_BURST); \
		if (__ratelimit(&_rs)) \
			func(fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define xpm_report_ratelimited(func, fmt, ...) \
	func(fmt, ##__VA_ARGS__);

#endif

#define JSTR(val) "\""#val"\""
#define JVAL_PAIR(val, format) JSTR(val) ": " #format
#define JSTR_PAIR(val, format) JSTR(val) ": " JSTR(format)

void report_init_event(char *event_type);
void report_file_event(char *event_type, struct file *file);
void report_mmap_event(char *event_type, enum xpm_code_type code_type,
	struct vm_area_struct *vma, unsigned long prot);
void report_integrity_event(char *event_type, struct vm_area_struct *vma,
	struct page *page);

#endif /* _XPM_REPORT_H */
