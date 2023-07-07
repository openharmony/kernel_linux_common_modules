/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_REPORT_H
#define _XPM_REPORT_H

#include <linux/sched.h>
#include <linux/mm.h>

enum xpm_event_id {
	EVENT_INIT      = 1011009110,
	EVENT_FILE      = 1011009111,
	EVENT_MMAP      = 1011009112,
	EVENT_INTEGRITY = 1011009113,
};

enum xpm_event_type {
	TYPE_DEVICEFS_UNINIT = 0,
	TYPE_DEBUGFS_UNINIT,
	TYPE_DM_DISABLE,
	TYPE_FORMAT_UNDEF,
	TYPE_ANON_EXEC,
	TYPE_SIGN_INVALID,
	TYPE_DATA_MMAP_CODE,
	TYPE_INTEGRITY_RO,
	TYPE_INTEGRITY_WT,
};

enum {
	TYPE_ABC,
	TYPE_ELF,
	TYPE_ANON,
};

struct xpm_event_param {
	char *event_type;
	char *filename;
	ktime_t timestamp;
	pid_t pid;

	struct vm_area_struct *vma;
	struct page *page;
	struct file *file;
	int code;
	unsigned long prot;
};

struct xpm_event_info {
	char *event_type;
	enum xpm_event_id event_id;
	int (*set_content)(struct xpm_event_param *param, uint8_t *content,
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

void report_init_event(enum xpm_event_type type);
void report_file_event(enum xpm_event_type type, struct file *file);
void report_mmap_event(enum xpm_event_type type, struct vm_area_struct *vma,
	int code, int prot);
void report_integrity_event(enum xpm_event_type type,
	struct vm_area_struct *vma, struct page *page);

#endif /* _XPM_REPORT_H */
